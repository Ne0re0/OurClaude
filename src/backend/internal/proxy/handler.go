package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"codex-proxy/internal/database"
	"codex-proxy/internal/metrics"
	"codex-proxy/internal/pool"
	"codex-proxy/internal/quota"
	"codex-proxy/internal/ratelimit"
	"codex-proxy/internal/sse"

	"gorm.io/gorm"
)

// WebhookDispatcher abstracts webhook.Dispatcher to avoid tight coupling.
type WebhookDispatcher interface {
	Dispatch(event string, payload interface{})
}

var errUnauthorized = errors.New("unauthorized")

// quotaAlertState tracks the last time a quota alert was sent per user to debounce.
type quotaAlertState struct {
	mu       sync.Mutex
	lastSent map[uint]time.Time
}

func (q *quotaAlertState) shouldAlert(userID uint) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if t, ok := q.lastSent[userID]; ok && time.Since(t) < time.Hour {
		return false
	}
	q.lastSent[userID] = time.Now()
	return true
}

// aliasCache caches model aliases from the DB to avoid per-request queries.
type aliasCache struct {
	mu        sync.RWMutex
	data      map[string]string
	updatedAt time.Time
}

func (c *aliasCache) get(db *gorm.DB, model string) string {
	c.mu.RLock()
	stale := time.Since(c.updatedAt) > 5*time.Second
	if !stale {
		if target, ok := c.data[model]; ok {
			c.mu.RUnlock()
			return target
		}
		c.mu.RUnlock()
		return model
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	// Double-check after acquiring write lock.
	if time.Since(c.updatedAt) <= 5*time.Second {
		if target, ok := c.data[model]; ok {
			return target
		}
		return model
	}
	var aliases []database.ModelAlias
	if err := db.Find(&aliases).Error; err != nil {
		log.Printf("proxy: failed to refresh alias cache: %v", err)
	}
	c.data = make(map[string]string, len(aliases))
	for _, a := range aliases {
		c.data[a.Alias] = a.Target
	}
	c.updatedAt = time.Now()
	if target, ok := c.data[model]; ok {
		return target
	}
	return model
}

type quotaCacheEntry struct {
	dailyUsed, monthlyUsed int64
	budgetSpent            float64
	poolDailyUsed          map[uint]int64
	poolMonthlyUsed        map[uint]int64
	expiresAt              time.Time
}

type quotaCache struct {
	mu    sync.RWMutex
	cache map[uint]*quotaCacheEntry // keyed by user ID
}

func (c *quotaCache) get(userID uint) *quotaCacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if e, ok := c.cache[userID]; ok && time.Now().Before(e.expiresAt) {
		return e
	}
	return nil
}

func (c *quotaCache) set(userID uint, entry *quotaCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry.expiresAt = time.Now().Add(10 * time.Second)
	c.cache[userID] = entry
}

type Handler struct {
	db              *gorm.DB
	pool            *pool.Manager
	apiUpstream     string
	chatGPTUpstream string
	client          *http.Client
	limiter         ratelimit.Limiter
	settings        SettingsProvider
	webhooks        WebhookDispatcher
	logStream       *sse.Broadcaster
	statsStream     *sse.Broadcaster
	quotaAlerts     quotaAlertState
	aliases         aliasCache
	quotas          quotaCache
	respCache       *responseCache
	inflight        sync.Map // map[string]struct{} for in-flight idempotency keys
}

// SettingsProvider reads runtime settings (backed by DB).
type SettingsProvider interface {
	Get(key string) string
	GetBool(key string) bool
	GetInt(key string) int
}

func New(db *gorm.DB, poolMgr *pool.Manager, apiUpstream, chatGPTUpstream, redisURL string, settings SettingsProvider, wh WebhookDispatcher, logStream *sse.Broadcaster, statsStream *sse.Broadcaster) *Handler {
	rpm := 0
	if settings != nil {
		rpm = settings.GetInt("user_max_rpm")
	}
	return &Handler{
		db:              db,
		pool:            poolMgr,
		apiUpstream:     strings.TrimRight(apiUpstream, "/"),
		chatGPTUpstream: strings.TrimRight(chatGPTUpstream, "/"),
		limiter:         ratelimit.New(rpm, redisURL),
		settings:        settings,
		webhooks:        wh,
		logStream:       logStream,
		statsStream:     statsStream,
		quotaAlerts:     quotaAlertState{lastSent: make(map[uint]time.Time)},
		aliases:         aliasCache{data: make(map[string]string)},
		quotas:          quotaCache{cache: make(map[uint]*quotaCacheEntry)},
		respCache:       newResponseCache(0), // TTL read from settings per-request
		client: &http.Client{
			Timeout: 5 * time.Minute,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CORS preflight — no auth needed
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	start := time.Now()

	user, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized — check your API token with 'ourcodex status' or re-login with 'ourcodex login'")
		return
	}

	if !user.Active {
		writeError(w, http.StatusForbidden, "account disabled")
		return
	}

	// Token expiry
	if user.TokenExpiresAt != nil && time.Now().After(*user.TokenExpiresAt) {
		writeError(w, http.StatusUnauthorized, "token expired")
		return
	}

	// IP whitelist
	if user.IPWhitelist != "" {
		if !ipAllowed(r, user.IPWhitelist) {
			writeError(w, http.StatusForbidden, "IP not allowed")
			return
		}
	}

	// Idempotency-Key deduplication: reject duplicate in-flight requests
	if key := r.Header.Get("Idempotency-Key"); key != "" {
		if _, loaded := h.inflight.LoadOrStore(key, struct{}{}); loaded {
			writeError(w, http.StatusConflict, "duplicate request in progress")
			return
		}
		defer h.inflight.Delete(key)
	}

	if !h.limiter.Allow(user.ID) {
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	// Load all pool IDs for this user from user_pools join table
	var poolIDs []uint
	if err := h.db.Table("user_pools").Where("user_id = ?", user.ID).Pluck("pool_id", &poolIDs).Error; err != nil {
		log.Printf("proxy: failed to load user pool IDs (user=%d): %v", user.ID, err)
	}

	if len(poolIDs) == 0 {
		writeError(w, http.StatusServiceUnavailable, "no pool linked to your account; ask an administrator to assign one")
		return
	}

	// Quota checks with cache
	cached := h.quotas.get(user.ID)
	if cached == nil {
		now := time.Now().UTC()
		today := now.Truncate(24 * time.Hour)
		monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

		var dailyUsed int64
		h.db.Model(&database.UsageLog{}).
			Where("user_id = ? AND created_at >= ?", user.ID, today).
			Select("COALESCE(SUM(input_tokens + output_tokens), 0)").
			Row().Scan(&dailyUsed)

		var monthlyUsed int64
		h.db.Model(&database.UsageLog{}).
			Where("user_id = ? AND created_at >= ?", user.ID, monthStart).
			Select("COALESCE(SUM(input_tokens + output_tokens), 0)").
			Row().Scan(&monthlyUsed)

		budgetSpent := estimateMonthlyCost(h.db, user.ID, monthStart)

		poolDailyUsed := make(map[uint]int64)
		poolMonthlyUsed := make(map[uint]int64)
		firstPoolID := poolIDs[0]
		var poolRec database.Pool
		if h.db.First(&poolRec, firstPoolID).Error == nil {
			if poolRec.DailyTokenQuota > 0 {
				var used int64
				h.db.Model(&database.UsageLog{}).
					Joins("JOIN codex_accounts ON usage_logs.account_id = codex_accounts.id").
					Joins("JOIN account_pools ON account_pools.account_id = codex_accounts.id").
					Where("account_pools.pool_id = ? AND usage_logs.created_at >= ?", firstPoolID, today).
					Select("COALESCE(SUM(usage_logs.input_tokens + usage_logs.output_tokens), 0)").
					Row().Scan(&used)
				poolDailyUsed[firstPoolID] = used
			}
			if poolRec.MonthlyTokenQuota > 0 {
				var used int64
				h.db.Model(&database.UsageLog{}).
					Joins("JOIN codex_accounts ON usage_logs.account_id = codex_accounts.id").
					Joins("JOIN account_pools ON account_pools.account_id = codex_accounts.id").
					Where("account_pools.pool_id = ? AND usage_logs.created_at >= ?", firstPoolID, monthStart).
					Select("COALESCE(SUM(usage_logs.input_tokens + usage_logs.output_tokens), 0)").
					Row().Scan(&used)
				poolMonthlyUsed[firstPoolID] = used
			}
		}

		cached = &quotaCacheEntry{
			dailyUsed:       dailyUsed,
			monthlyUsed:     monthlyUsed,
			budgetSpent:     budgetSpent,
			poolDailyUsed:   poolDailyUsed,
			poolMonthlyUsed: poolMonthlyUsed,
		}
		h.quotas.set(user.ID, cached)
	}

	// Daily token quota
	if user.DailyTokenQuota > 0 {
		if int(cached.dailyUsed) >= user.DailyTokenQuota {
			writeError(w, http.StatusTooManyRequests, "daily token quota exceeded")
			return
		}
		h.maybeAlertQuota(user, "daily", int(cached.dailyUsed), user.DailyTokenQuota)
	}

	// Monthly token quota
	if user.MonthlyTokenQuota > 0 {
		if int(cached.monthlyUsed) >= user.MonthlyTokenQuota {
			writeError(w, http.StatusTooManyRequests, "monthly token quota exceeded")
			return
		}
		h.maybeAlertQuota(user, "monthly", int(cached.monthlyUsed), user.MonthlyTokenQuota)
	}

	// Monthly budget (USD)
	if user.MonthlyBudgetUSD > 0 {
		if cached.budgetSpent >= user.MonthlyBudgetUSD {
			writeError(w, http.StatusTooManyRequests, fmt.Sprintf("monthly budget of $%.2f exceeded", user.MonthlyBudgetUSD))
			return
		}
	}

	// Per-pool quotas (check first assigned pool for now)
	firstPoolID := poolIDs[0]
	var poolRecord database.Pool
	if h.db.First(&poolRecord, firstPoolID).Error == nil {
		if poolRecord.DailyTokenQuota > 0 {
			if int(cached.poolDailyUsed[firstPoolID]) >= poolRecord.DailyTokenQuota {
				writeError(w, http.StatusTooManyRequests, "pool daily token quota exceeded")
				return
			}
		}
		if poolRecord.MonthlyTokenQuota > 0 {
			if int(cached.poolMonthlyUsed[firstPoolID]) >= poolRecord.MonthlyTokenQuota {
				writeError(w, http.StatusTooManyRequests, "pool monthly token quota exceeded")
				return
			}
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, 50*1024*1024) // 50MB limit
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if err.Error() == "http: request body too large" {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large (max 50MB)")
		} else {
			writeError(w, http.StatusBadRequest, "failed to read request body")
		}
		return
	}
	r.Body.Close()

	// Extract Responses API input for conversation logging (before rewriting).
	var reqParsed struct {
		Input json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &reqParsed); err != nil {
		log.Printf("proxy: failed to parse request body for conversation logging: %v", err)
	}
	messagesJSON := string(reqParsed.Input)

	// System prompt injection (runtime-editable via settings)
	if sp := h.settings.Get("system_prompt_inject"); sp != "" {
		body = injectSystemPrompt(body, sp)
	}

	// Model alias rewriting
	body = rewriteModel(body, func(model string) string {
		return h.aliases.get(h.db, model)
	})

	// Model allowlist check (after alias resolution)
	if user.AllowedModels != "" {
		if !modelAllowed(body, user.AllowedModels) {
			writeError(w, http.StatusForbidden, "model not allowed for your account")
			return
		}
	}

	// Pool-level model restriction
	if poolRecord.AllowedModels != "" {
		if !modelAllowed(body, poolRecord.AllowedModels) {
			writeError(w, http.StatusForbidden, "model not allowed in this pool")
			return
		}
	}

	// Response cache check
	var cacheKey string
	if h.settings.GetInt("response_cache_ttl") > 0 {
		cacheKey = h.respCache.key(user.ID, body)
		if cached := h.respCache.get(cacheKey); cached != nil {
			for k, vs := range cached.headers {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.Header().Set("X-Cache", "HIT")
			w.WriteHeader(cached.statusCode)
			w.Write(cached.body)
			return
		}
	}

	const maxRetries = 3
	var lastErr error
	// limitedOnly stays true while every failed attempt was a usage limit, so
	// the client can be told to back off rather than seeing a gateway error.
	limitedOnly := true
	attemptedAccountIDs := make(map[uint]struct{}, maxRetries)

	for attempt := 0; attempt < maxRetries; attempt++ {
		account, err := h.pool.GetAccountForUserExcluding(poolIDs, attemptedAccountIDs)
		if err != nil {
			if lastErr != nil {
				break
			}
			writeError(w, http.StatusServiceUnavailable, "no available Codex accounts: "+err.Error())
			return
		}
		attemptedAccountIDs[account.ID] = struct{}{}

		resp, err := h.forward(r, body, account, user)
		if err != nil {
			if r.Context().Err() != nil {
				return // Client disconnected — not the account's fault
			}
			lastErr = err
			limitedOnly = false
			log.Printf("proxy: account %d network error: %v", account.ID, err)
			continue
		}

		// On 429 or 401: don't change account status — just try next account.
		// Account status is managed by the quota poller (based on real usage data)
		// and the health checker, NOT by the proxy request handler.
		if resp.StatusCode == http.StatusTooManyRequests {
			quota.UpdateFromHeaders(h.db, account.ID, resp.Header)
			resp.Body.Close()
			h.pool.MarkExhausted(account.ID)
			log.Printf("proxy: account %d got 429, trying next account", account.ID)
			lastErr = fmt.Errorf("account %d: rate limited", account.ID)
			continue
		}

		if resp.StatusCode == http.StatusUnauthorized {
			resp.Body.Close()
			log.Printf("proxy: account %d got 401 (token expired/invalid), trying next account", account.ID)
			lastErr = fmt.Errorf("account %d: unauthorized", account.ID)
			limitedOnly = false
			continue
		}

		// A ChatGPT plan account that is out of usage still answers 200 and
		// then fails the stream. When that happens before any output, nothing
		// has reached the client yet, so move on to another account.
		if resp.StatusCode == http.StatusOK {
			prefix, failure := peekLeadingFailure(resp.Body)
			if failure != "" {
				resp.Body.Close()
				if failure == codeUsageLimitExceeded {
					h.pool.MarkExhausted(account.ID)
				}
				log.Printf("proxy: account %d stream failed with %s, trying next account", account.ID, failure)
				lastErr = fmt.Errorf("account %d: %s", account.ID, failure)
				continue
			}
			resp.Body = newReplayBody(prefix, resp.Body)
		}

		h.streamResponse(w, resp, user.ID, account.ID, r.URL.Path, start, messagesJSON, cacheKey, h.logStream, h.statsStream)
		h.pool.UpdateLastUsed(account.ID)
		return
	}

	if lastErr != nil && limitedOnly {
		writeError(w, http.StatusTooManyRequests, "usage limit reached on every available account, try again later ("+lastErr.Error()+")")
	} else if lastErr != nil {
		writeError(w, http.StatusBadGateway, "upstream error: "+lastErr.Error())
	} else {
		writeError(w, http.StatusServiceUnavailable, "all accounts exhausted, try again later")
	}
}

func (h *Handler) authenticate(r *http.Request) (*database.User, error) {
	var token string

	// Accept the standard bearer token and x-api-key for compatible clients.
	if key := r.Header.Get("x-api-key"); key != "" {
		token = key
	} else if key := r.Header.Get("X-Api-Key"); key != "" {
		token = key
	} else if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		// Try "Bearer TOKEN" format
		if t := strings.TrimPrefix(authHeader, "Bearer "); t != authHeader {
			token = t
		} else if t := strings.TrimPrefix(authHeader, "bearer "); t != authHeader {
			token = t
		}
	}

	// Also check openai-auth-token header (some clients send it this way)
	if token == "" {
		if key := r.Header.Get("OpenAI-Auth-Token"); key != "" {
			token = key
		}
	}

	if token == "" {
		log.Printf("proxy auth: no token found in request headers (x-api-key=%q, Authorization=%q)",
			r.Header.Get("x-api-key"), r.Header.Get("Authorization"))
		return nil, errUnauthorized
	}

	var user database.User
	if err := h.db.Where("api_token = ?", token).First(&user).Error; err != nil {
		log.Printf("proxy auth: token not found in DB (prefix=%s...)", token[:min(len(token), 15)])
		return nil, errUnauthorized
	}

	return &user, nil
}

func (h *Handler) forward(r *http.Request, body []byte, account *database.CodexAccount, user *database.User) (*http.Response, error) {
	// Safety: strip /proxy prefix if chi Mount didn't strip it
	path := r.URL.Path
	if strings.HasPrefix(path, "/proxy") {
		path = strings.TrimPrefix(path, "/proxy")
	}
	path = strings.TrimPrefix(path, "/v1")
	if path == "" {
		path = "/"
	}
	upstream := h.apiUpstream
	if account.AccountType != "apikey" && account.OAuthProvider != "siwc" {
		upstream = h.chatGPTUpstream
	}
	upstreamURL := upstream + path
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	for key, values := range r.Header {
		k := strings.ToLower(key)
		if k == "authorization" || k == "host" || k == "x-api-key" || k == "chatgpt-account-id" || k == "content-length" || k == "accept-encoding" {
			continue
		}
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	// The proxy reads every response to account for usage and detect limits,
	// so it must not relay an encoding the client negotiated (for example,
	// zstd from the Codex CLI). identity keeps streams flowing without
	// decompression buffering.
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Authorization", "Bearer "+account.AccessToken)
	if account.AccountType != "apikey" && account.OAuthProvider != "siwc" && account.ChatGPTAccountID != "" {
		req.Header.Set("ChatGPT-Account-ID", account.ChatGPTAccountID)
	}

	// Extra headers from user config (JSON map)
	if user != nil && user.ExtraHeaders != "" {
		var extra map[string]string
		if err := json.Unmarshal([]byte(user.ExtraHeaders), &extra); err == nil {
			for k, v := range extra {
				req.Header.Set(k, v)
			}
		}
	}

	return h.client.Do(req)
}

func (h *Handler) streamResponse(w http.ResponseWriter, resp *http.Response, userID, accountID uint, endpoint string, start time.Time, messagesJSON string, cacheKey string, logStream *sse.Broadcaster, statsStream *sse.Broadcaster) {
	defer resp.Body.Close()
	quota.UpdateFromHeaders(h.db, accountID, resp.Header)

	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	flusher, canFlush := w.(http.Flusher)
	isStreaming := strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream")

	const maxCapture = 10 * 1024 * 1024 // 10MB
	var buf bytes.Buffer
	limitedBuf := &limitedWriter{w: &buf, limit: maxCapture}
	tee := io.TeeReader(resp.Body, limitedBuf)

	var ttftMs int
	firstByte := true
	chunk := make([]byte, 4096)
	for {
		n, err := tee.Read(chunk)
		if n > 0 {
			if firstByte {
				// The ChatGPT plan route streams events as text/plain.
				isStreaming = isStreaming || looksLikeSSE(chunk[:n])
				if isStreaming {
					ttftMs = int(time.Since(start).Milliseconds())
				}
				firstByte = false
			}
			w.Write(chunk[:n])
			if canFlush {
				flusher.Flush()
			}
		}
		if err != nil {
			break
		}
	}

	latencyMs := int(time.Since(start).Milliseconds())
	captured := buf.Bytes()
	// The first read can end mid-marker; decide from the whole capture.
	isStreaming = isStreaming || looksLikeSSE(captured)

	// Debug: log captured body size and streaming status
	log.Printf("proxy: response captured %d bytes, streaming=%v, status=%d, user=%d, account=%d",
		len(captured), isStreaming, resp.StatusCode, userID, accountID)

	// Cache non-streaming successful responses
	if !isStreaming && resp.StatusCode == http.StatusOK && cacheKey != "" && h.settings.GetInt("response_cache_ttl") > 0 {
		headers := make(map[string][]string)
		for k, v := range resp.Header {
			headers[k] = v
		}
		cachedBody := make([]byte, len(captured))
		copy(cachedBody, captured)
		cacheTTL := time.Duration(h.settings.GetInt("response_cache_ttl")) * time.Second
		h.respCache.setWithTTL(cacheKey, &cachedResponse{
			statusCode: resp.StatusCode,
			headers:    headers,
			body:       cachedBody,
		}, cacheTTL)
	}

	go func() {
		outcome := parseAndLogUsage(captured, isStreaming, userID, accountID, endpoint, resp.StatusCode, latencyMs, ttftMs, messagesJSON, h.db, logStream, statsStream)
		if h.pool == nil {
			return
		}
		switch {
		case outcome.failure == codeUsageLimitExceeded:
			// The limit was hit after output had started streaming, too late
			// to switch accounts for this request; route the next ones away.
			log.Printf("proxy: account %d reached its usage limit mid-stream", accountID)
			h.pool.MarkExhausted(accountID)
		case outcome.completed:
			// ChatGPT plan accounts send no reset headers, so a completed
			// response is the signal that an exhausted account has capacity.
			h.pool.MarkRecovered(accountID)
		}
	}()
}

func (h *Handler) maybeAlertQuota(user *database.User, period string, used, quota int) {
	pct := float64(used) / float64(quota)
	if pct < 0.8 {
		return
	}
	if !h.quotaAlerts.shouldAlert(user.ID) {
		return
	}
	if h.webhooks == nil {
		return
	}
	h.webhooks.Dispatch("quota.warning", map[string]interface{}{
		"user_id": user.ID,
		"period":  period,
		"used":    used,
		"quota":   quota,
		"percent": int(pct * 100),
	})
}

// usageOutcome reports how an upstream response ended, so the caller can
// update the serving account's availability.
type usageOutcome struct {
	completed bool   // a response.completed event (or a completed JSON response) was seen
	failure   string // error code of a terminal response.failed / error event
}

func parseAndLogUsage(body []byte, isStreaming bool, userID, accountID uint, endpoint string, statusCode, latencyMs, ttftMs int, messagesJSON string, db *gorm.DB, logStream *sse.Broadcaster, statsStream *sse.Broadcaster) usageOutcome {
	var inputTokens, outputTokens, cacheRead, cacheWrite int
	var model string
	var responseText strings.Builder
	var outcome usageOutcome

	if len(body) == 0 {
		log.Printf("proxy: empty response body for user=%d account=%d status=%d", userID, accountID, statusCode)
	}

	if isStreaming {
		for _, data := range sseData(body, true) {
			var event streamEvent
			if json.Unmarshal(data, &event) != nil {
				continue // includes the [DONE] sentinel
			}
			switch event.Type {
			case "response.completed", "response.incomplete", "response.failed":
				model = event.Response.Model
				inputTokens = event.Response.Usage.InputTokens
				outputTokens = event.Response.Usage.OutputTokens
				cacheRead = event.Response.Usage.InputDetails.CachedTokens
				cacheWrite = event.Response.Usage.InputDetails.CacheWriteTokens
				outcome.completed = event.Type == "response.completed"
				outcome.failure = event.failureCode()
			case "error":
				outcome.failure = event.failureCode()
			case "response.output_text.delta":
				responseText.WriteString(event.Delta)
			}
		}
	} else {
		var resp struct {
			Model  string `json:"model"`
			Status string `json:"status"`
			Usage  struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
				InputDetails struct {
					CachedTokens     int `json:"cached_tokens"`
					CacheWriteTokens int `json:"cache_write_tokens"`
				} `json:"input_tokens_details"`
			} `json:"usage"`
			Output []struct {
				Type    string `json:"type"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"output"`
		}
		if err := json.Unmarshal(body, &resp); err == nil {
			outcome.completed = statusCode == http.StatusOK && resp.Status == "completed"
			model = resp.Model
			inputTokens = resp.Usage.InputTokens
			outputTokens = resp.Usage.OutputTokens
			cacheWrite = resp.Usage.InputDetails.CacheWriteTokens
			cacheRead = resp.Usage.InputDetails.CachedTokens
			for _, item := range resp.Output {
				for _, block := range item.Content {
					if block.Type == "output_text" {
						responseText.WriteString(block.Text)
					}
				}
			}
		}
	}

	log.Printf("proxy: parsed usage — model=%q input=%d output=%d cache_r=%d cache_w=%d streaming=%v status=%d",
		model, inputTokens, outputTokens, cacheRead, cacheWrite, isStreaming, statusCode)

	// Prometheus metrics
	statusStr := strconv.Itoa(statusCode)
	metrics.RequestsTotal.WithLabelValues(model, statusStr).Inc()
	if latencyMs > 0 {
		metrics.RequestDuration.WithLabelValues(model).Observe(float64(latencyMs))
	}
	if ttftMs > 0 {
		metrics.TTFT.WithLabelValues(model).Observe(float64(ttftMs))
	}
	if inputTokens > 0 {
		metrics.TokensTotal.WithLabelValues("input").Add(float64(inputTokens))
	}
	if outputTokens > 0 {
		metrics.TokensTotal.WithLabelValues("output").Add(float64(outputTokens))
	}
	if cacheRead > 0 {
		metrics.TokensTotal.WithLabelValues("cache_read").Add(float64(cacheRead))
	}
	if cacheWrite > 0 {
		metrics.TokensTotal.WithLabelValues("cache_write").Add(float64(cacheWrite))
	}

	entry := database.UsageLog{
		UserID:       userID,
		AccountID:    accountID,
		Model:        model,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		CacheRead:    cacheRead,
		CacheWrite:   cacheWrite,
		Endpoint:     endpoint,
		StatusCode:   statusCode,
		LatencyMs:    latencyMs,
		TTFTMs:       ttftMs,
	}

	if err := db.Create(&entry).Error; err != nil {
		log.Printf("failed to log usage (user=%d, account=%d): %v", userID, accountID, err)
		return outcome
	}

	if logStream != nil {
		if raw, err := json.Marshal(entry); err == nil {
			logStream.Publish(raw)
		}
	}

	if statsStream != nil {
		evt, _ := json.Marshal(map[string]interface{}{
			"type":          "usage",
			"input_tokens":  inputTokens,
			"output_tokens": outputTokens,
			"model":         model,
		})
		statsStream.Publish(evt)
	}

	// Save conversation log only for successful requests with actual content
	if len(messagesJSON) > 0 && messagesJSON != "null" && statusCode == 200 && (inputTokens > 0 || outputTokens > 0) && responseText.Len() > 0 {
		logID := entry.ID
		db.Create(&database.ConversationLog{
			UserID:       userID,
			UsageLogID:   &logID,
			Model:        model,
			MessagesJSON: messagesJSON,
			ResponseText: responseText.String(),
			InputTokens:  inputTokens,
			OutputTokens: outputTokens,
		})
	}
	return outcome
}

type limitedWriter struct {
	w       io.Writer
	limit   int
	written int
}

func (lw *limitedWriter) Write(p []byte) (n int, err error) {
	if lw.written >= lw.limit {
		return len(p), nil // Silently discard after limit
	}
	remaining := lw.limit - lw.written
	toWrite := p
	if len(toWrite) > remaining {
		toWrite = toWrite[:remaining]
	}
	n, err = lw.w.Write(toWrite)
	lw.written += n
	if err != nil {
		return len(p), nil // Always report full write to not break TeeReader
	}
	return len(p), nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func ipAllowed(r *http.Request, whitelist string) bool {
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	// Take first IP from X-Forwarded-For chain.
	if idx := strings.Index(clientIP, ","); idx != -1 {
		clientIP = strings.TrimSpace(clientIP[:idx])
	}
	// Strip port.
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, cidr := range strings.Split(whitelist, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if strings.Contains(cidr, "/") {
			_, network, err := net.ParseCIDR(cidr)
			if err == nil && network.Contains(ip) {
				return true
			}
		} else if net.ParseIP(cidr) != nil && net.ParseIP(cidr).Equal(ip) {
			return true
		}
	}
	return false
}

func modelAllowed(body []byte, allowedModels string) bool {
	var req struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Model == "" {
		return true // non-messages endpoints
	}
	for _, allowed := range strings.Split(allowedModels, ",") {
		allowed = strings.TrimSpace(allowed)
		if strings.EqualFold(allowed, req.Model) {
			return true
		}
	}
	return false
}

func rewriteModel(body []byte, resolve func(string) string) []byte {
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return body
	}
	modelRaw, ok := req["model"]
	if !ok {
		return body
	}
	var model string
	if err := json.Unmarshal(modelRaw, &model); err != nil || model == "" {
		return body
	}
	resolved := resolve(model)
	if resolved == model {
		return body
	}
	raw, err := json.Marshal(resolved)
	if err != nil {
		return body
	}
	req["model"] = raw
	result, err := json.Marshal(req)
	if err != nil {
		return body
	}
	return result
}

// estimateMonthlyCost queries the DB for cost since monthStart.
func estimateMonthlyCost(db *gorm.DB, userID uint, monthStart time.Time) float64 {
	type row struct {
		Model        string
		InputTokens  int64
		OutputTokens int64
	}
	var rows []row
	db.Model(&database.UsageLog{}).
		Where("user_id = ? AND created_at >= ?", userID, monthStart).
		Select("model, COALESCE(SUM(input_tokens),0) as input_tokens, COALESCE(SUM(output_tokens),0) as output_tokens").
		Group("model").Scan(&rows)
	var total float64
	for _, r := range rows {
		total += estimateCostRow(r.Model, r.InputTokens, r.OutputTokens)
	}
	return total
}

// estimateCostRow is a lightweight copy of the pricing logic from handlers/stats.go.
var modelPricingProxy = []struct {
	name          string
	input, output float64
}{
	// Standard short-context rates, developers.openai.com/api/docs/pricing (November 2026).
	{"gpt-6-astra", 10.0, 50.0},
	{"gpt-6.1-sol", 2.0, 10.0},
	{"gpt-6.1-terra", 1.0, 5.0},
	{"gpt-6-sol", 2.0, 10.0},
	{"gpt-6-luna", 0.10, 0.50},
	{"gpt-5.6-sol", 4.0, 20.0},
	{"gpt-5.6-terra", 2.0, 12.0},
	{"gpt-5.6-luna", 0.20, 1.20},
	{"gpt-5.3-codex", 1.75, 14.0},
	{"gpt-5.4-pro", 30.0, 180.0},
	{"gpt-5.2-pro", 21.0, 168.0},
	{"gpt-5.4", 2.50, 15.0},
	{"gpt-5.2", 1.75, 14.0},
	{"gpt-5.1", 1.25, 10.0},
	{"gpt-5-mini", 0.25, 2.0},
	{"gpt-5-nano", 0.05, 0.40},
	{"gpt-5", 1.25, 10.0},
	{"gpt-4.1", 2.0, 8.0},
}

func estimateCostRow(model string, input, output int64) float64 {
	for _, price := range modelPricingProxy {
		if strings.Contains(model, price.name) {
			return float64(input)/1_000_000*price.input + float64(output)/1_000_000*price.output
		}
	}
	return 0
}

func injectSystemPrompt(body []byte, prefix string) []byte {
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body
	}
	existing, _ := parsed["instructions"].(string)
	if existing != "" {
		parsed["instructions"] = prefix + "\n\n" + existing
	} else {
		parsed["instructions"] = prefix
	}
	result, err := json.Marshal(parsed)
	if err != nil {
		return body
	}
	return result
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"message": msg,
			"type":    "ourcodex_error",
			"code":    code,
		},
	})
}
