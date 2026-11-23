package proxy

import (
	"bytes"
	"compress/gzip"
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

	"claude-proxy/internal/database"
	"claude-proxy/internal/metrics"
	"claude-proxy/internal/middleware"
	"claude-proxy/internal/pool"
	"claude-proxy/internal/ratelimit"
	"claude-proxy/internal/sse"

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
	db          *gorm.DB
	pool        *pool.Manager
	upstream    string
	client      *http.Client
	limiter     ratelimit.Limiter
	settings    SettingsProvider
	webhooks    WebhookDispatcher
	logStream   *sse.Broadcaster
	statsStream *sse.Broadcaster
	quotaAlerts quotaAlertState
	aliases     aliasCache
	quotas      quotaCache
	respCache   *responseCache
	inflight    sync.Map // map[string]struct{} for in-flight idempotency keys
}

// SettingsProvider reads runtime settings (backed by DB).
type SettingsProvider interface {
	Get(key string) string
	GetBool(key string) bool
	GetInt(key string) int
}

func New(db *gorm.DB, poolMgr *pool.Manager, upstream string, redisURL string, settings SettingsProvider, wh WebhookDispatcher, logStream *sse.Broadcaster, statsStream *sse.Broadcaster) *Handler {
	rpm := 0
	if settings != nil {
		rpm = settings.GetInt("user_max_rpm")
	}
	return &Handler{
		db:          db,
		pool:        poolMgr,
		upstream:    strings.TrimRight(upstream, "/"),
		limiter:     ratelimit.New(rpm, redisURL),
		settings:    settings,
		webhooks:    wh,
		logStream:   logStream,
		statsStream: statsStream,
		quotaAlerts: quotaAlertState{lastSent: make(map[uint]time.Time)},
		aliases:     aliasCache{data: make(map[string]string)},
		quotas:      quotaCache{cache: make(map[uint]*quotaCacheEntry)},
		respCache:   newResponseCache(0), // TTL read from settings per-request
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

	if !allowedUpstreamRoute(r.Method, strings.TrimPrefix(r.URL.Path, "/proxy")) {
		writeError(w, http.StatusNotFound, "endpoint not available through the proxy")
		return
	}

	start := time.Now()

	user, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized — check your API token with 'ourclaude status' or re-login with 'ourclaude login'")
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type": "error",
			"error": map[string]string{
				"type":    "api_error",
				"message": "No pool linked to your account. Ask an administrator to assign you to a pool.",
			},
		})
		return
	}

	var quotaPools []database.Pool
	h.db.Where("id IN ? AND (daily_token_quota > 0 OR monthly_token_quota > 0)", poolIDs).Find(&quotaPools)

	// Quota checks with cache
	cached := h.quotas.get(user.ID)
	if cached == nil {
		now := time.Now().UTC()
		today := now.Truncate(24 * time.Hour)
		monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

		var dailyUsed int64
		h.db.Model(&database.UsageLog{}).
			Where("user_id = ? AND created_at >= ?", user.ID, today).
			Select(quotaTokensSQL).
			Row().Scan(&dailyUsed)

		var monthlyUsed int64
		h.db.Model(&database.UsageLog{}).
			Where("user_id = ? AND created_at >= ?", user.ID, monthStart).
			Select(quotaTokensSQL).
			Row().Scan(&monthlyUsed)

		budgetSpent := estimateMonthlyCost(h.db, user.ID, monthStart)

		poolDailyUsed := make(map[uint]int64)
		poolMonthlyUsed := make(map[uint]int64)
		for _, p := range quotaPools {
			if p.DailyTokenQuota > 0 {
				poolDailyUsed[p.ID] = poolTokensSince(h.db, p.ID, today)
			}
			if p.MonthlyTokenQuota > 0 {
				poolMonthlyUsed[p.ID] = poolTokensSince(h.db, p.ID, monthStart)
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

	// Per-pool quotas: only the user's pools still within quota may serve this request.
	usablePoolIDs := poolsWithinQuota(poolIDs, quotaPools, cached.poolDailyUsed, cached.poolMonthlyUsed)
	if len(usablePoolIDs) == 0 {
		writeError(w, http.StatusTooManyRequests, "pool token quota exceeded")
		return
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

	// Extract messages for conversation logging (before alias rewriting)
	var reqParsed struct {
		Messages json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &reqParsed); err != nil {
		log.Printf("proxy: failed to parse request body for conversation logging: %v", err)
	}
	messagesJSON := string(reqParsed.Messages)

	// System prompt injection (runtime-editable via settings)
	if sp := h.settings.Get("system_prompt_inject"); sp != "" {
		body = injectSystemPrompt(body, sp)
	}

	// Model alias rewriting
	body = rewriteModel(body, func(model string) string {
		return h.aliases.get(h.db, model)
	})
	var modelRequest struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &modelRequest)

	// Model allowlist check (after alias resolution)
	if user.AllowedModels != "" {
		if !modelAllowed(body, user.AllowedModels) {
			writeError(w, http.StatusForbidden, "model not allowed for your account")
			return
		}
	}

	// Pool-level model restriction: keep only the pools that allow the requested model.
	var usablePools []database.Pool
	h.db.Where("id IN ?", usablePoolIDs).Find(&usablePools)
	modelPoolIDs := make([]uint, 0, len(usablePools))
	for _, p := range usablePools {
		if p.AllowedModels == "" || modelAllowed(body, p.AllowedModels) {
			modelPoolIDs = append(modelPoolIDs, p.ID)
		}
	}
	if len(modelPoolIDs) == 0 {
		writeError(w, http.StatusForbidden, "model not allowed in this pool")
		return
	}
	usablePoolIDs = modelPoolIDs
	modelListRequest := r.Method == http.MethodGet && strings.TrimPrefix(r.URL.Path, "/proxy") == "/v1/models"
	if modelListRequest {
		// Let Go negotiate and transparently decompress upstream gzip before filtering.
		r.Header.Del("Accept-Encoding")
	}

	// Prompt cache injection
	if h.settings.GetBool("prompt_cache_inject") {
		body = injectPromptCache(body)
	}

	// Response cache check
	var cacheKey string
	if !modelListRequest && h.settings.GetInt("response_cache_ttl") > 0 {
		cacheKey = h.respCache.key(user.ID, body)
		if cached := h.respCache.get(cacheKey); cached != nil &&
			(http.Header(cached.headers).Get("Content-Encoding") == "" || acceptsGzip(r.Header.Get("Accept-Encoding"))) {
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
	attemptedAccountIDs := make(map[uint]struct{}, maxRetries)

	for attempt := 0; attempt < maxRetries; attempt++ {
		account, err := h.pool.GetAccountForUserExcludingModel(usablePoolIDs, attemptedAccountIDs, modelRequest.Model)
		if err != nil {
			if lastErr != nil {
				break
			}
			if strings.HasPrefix(strings.ToLower(modelRequest.Model), "claude-mythos-") {
				writeError(w, http.StatusServiceUnavailable, "no account assigned to "+modelRequest.Model+" in your pools")
				return
			}
			writeError(w, http.StatusServiceUnavailable, "no available Claude accounts: "+err.Error())
			return
		}
		attemptedAccountIDs[account.ID] = struct{}{}

		resp, err := h.forward(r, body, account.AccessToken, user)
		if err != nil {
			if r.Context().Err() != nil {
				return // Client disconnected — not the account's fault
			}
			lastErr = err
			log.Printf("proxy: account %d network error: %v", account.ID, err)
			continue
		}

		// On 429 or 401: don't change account status — just try next account.
		// Account status is managed by the quota poller (based on real usage data)
		// and the health checker, NOT by the proxy request handler.
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			log.Printf("proxy: account %d got 429, trying next account", account.ID)
			lastErr = fmt.Errorf("account %d: rate limited", account.ID)
			continue
		}

		if resp.StatusCode == http.StatusUnauthorized {
			resp.Body.Close()
			log.Printf("proxy: account %d got 401 (token expired/invalid), trying next account", account.ID)
			lastErr = fmt.Errorf("account %d: unauthorized", account.ID)
			continue
		}
		if strings.HasPrefix(strings.ToLower(modelRequest.Model), "claude-mythos-") && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound) {
			resp.Body.Close()
			lastErr = fmt.Errorf("account %d: model unavailable (%d)", account.ID, resp.StatusCode)
			continue
		}
		if modelListRequest && resp.StatusCode == http.StatusOK {
			filtered, err := h.filterModelList(resp.Body, poolIDs)
			resp.Body.Close()
			if err != nil {
				log.Printf("proxy: failed to filter model list: %v", err)
				writeError(w, http.StatusBadGateway, "failed to filter model list")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(filtered)
			return
		}

		h.streamResponse(w, resp, user.ID, account.ID, r.URL.Path, start, messagesJSON, cacheKey, h.logStream, h.statsStream)
		h.pool.UpdateLastUsed(account.ID)
		return
	}

	if lastErr != nil {
		writeError(w, http.StatusBadGateway, "upstream error: "+lastErr.Error())
	} else {
		writeError(w, http.StatusServiceUnavailable, "all accounts exhausted, try again later")
	}
}

func (h *Handler) filterModelList(body io.Reader, poolIDs []uint) ([]byte, error) {
	var assignments []string
	if err := h.db.Table("claude_accounts").
		Joins("JOIN account_pools ON account_pools.account_id = claude_accounts.id").
		Where("account_pools.pool_id IN ? AND claude_accounts.status IN ?", poolIDs, []string{"active", "exhausted"}).
		Pluck("COALESCE(claude_accounts.mythos_models, '')", &assignments).Error; err != nil {
		return nil, err
	}
	allowed := make(map[string]bool)
	for _, assigned := range assignments {
		for _, model := range strings.Split(assigned, ",") {
			allowed[strings.ToLower(strings.TrimSpace(model))] = true
		}
	}
	var list map[string]json.RawMessage
	data, err := io.ReadAll(io.LimitReader(body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(list["data"], &entries); err != nil {
		return nil, err
	}
	filtered := make([]json.RawMessage, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		var model struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(entry, &model) != nil {
			continue
		}
		id := strings.ToLower(model.ID)
		if (id == "claude-mythos-5-1" || id == "claude-mythos-5-2") && !allowed[id] {
			continue
		}
		seen[id] = true
		filtered = append(filtered, entry)
	}
	// Some upstream catalogs omit models that an account is explicitly assigned.
	// Advertise those assignments so Claude Code can offer them in /model.
	for _, model := range []struct{ id, name string }{
		{"claude-mythos-5-2", "Claude Mythos 5.2"},
		{"claude-mythos-5-1", "Claude Mythos 5.1"},
	} {
		if !allowed[model.id] || seen[model.id] {
			continue
		}
		entry, _ := json.Marshal(map[string]string{
			"id": model.id, "type": "model", "display_name": model.name,
			"description": "Assigned to an account in your OurClaude pool",
		})
		filtered = append(filtered, entry)
	}
	list["data"], _ = json.Marshal(filtered)
	if len(filtered) == 0 {
		if _, ok := list["first_id"]; ok {
			list["first_id"] = []byte("null")
		}
		if _, ok := list["last_id"]; ok {
			list["last_id"] = []byte("null")
		}
	} else {
		var first, last struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(filtered[0], &first)
		_ = json.Unmarshal(filtered[len(filtered)-1], &last)
		if _, ok := list["first_id"]; ok {
			list["first_id"], _ = json.Marshal(first.ID)
		}
		if _, ok := list["last_id"]; ok {
			list["last_id"], _ = json.Marshal(last.ID)
		}
	}
	return json.Marshal(list)
}

func (h *Handler) authenticate(r *http.Request) (*database.User, error) {
	var token string

	// Try all auth header patterns (Claude Code may use any of these)
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

	// Also check anthropic-auth-token header (some clients send it this way)
	if token == "" {
		if key := r.Header.Get("Anthropic-Auth-Token"); key != "" {
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

func (h *Handler) forward(r *http.Request, body []byte, accessToken string, user *database.User) (*http.Response, error) {
	// Safety: strip /proxy prefix if chi Mount didn't strip it
	path := r.URL.Path
	if strings.HasPrefix(path, "/proxy") {
		path = strings.TrimPrefix(path, "/proxy")
	}
	if path == "" {
		path = "/"
	}
	upstreamURL := h.upstream + path
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	for key, values := range r.Header {
		k := strings.ToLower(key)
		if k == "authorization" || k == "host" || k == "x-api-key" || k == "accept-encoding" {
			continue
		}
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	// Only ever ask upstream for gzip, the one encoding usage parsing can decode
	// with the stdlib. When the client accepts gzip we request it explicitly, so
	// the transport passes the compressed bytes straight through to the client
	// (no recompression) and parseAndLogUsage decompresses its captured copy off
	// the request path. Otherwise the header stays unset: the transport then
	// negotiates gzip itself and transparently decompresses for us.
	if acceptsGzip(r.Header.Get("Accept-Encoding")) {
		req.Header.Set("Accept-Encoding", "gzip")
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	// OAuth tokens (sk-ant-oat*) require specific headers for Anthropic to accept them.
	if strings.HasPrefix(accessToken, "sk-ant-oat") {
		req.Header.Set("Anthropic-Dangerous-Direct-Browser-Access", "true")
		existing := req.Header.Get("Anthropic-Beta")
		if !strings.Contains(existing, "oauth-2025-04-20") {
			if existing != "" {
				req.Header.Set("Anthropic-Beta", "oauth-2025-04-20,"+existing)
			} else {
				req.Header.Set("Anthropic-Beta", "oauth-2025-04-20")
			}
		}
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

	// Ensure prompt-caching beta is declared when cache injection is active.
	if h.settings.GetBool("prompt_cache_inject") {
		existing := req.Header.Get("anthropic-beta")
		if !strings.Contains(existing, "prompt-caching") {
			if existing != "" {
				req.Header.Set("anthropic-beta", existing+",prompt-caching-2024-07-31")
			} else {
				req.Header.Set("anthropic-beta", "prompt-caching-2024-07-31")
			}
		}
	}

	return h.client.Do(req)
}

func (h *Handler) streamResponse(w http.ResponseWriter, resp *http.Response, userID, accountID uint, endpoint string, start time.Time, messagesJSON string, cacheKey string, logStream *sse.Broadcaster, statsStream *sse.Broadcaster) {
	defer resp.Body.Close()

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
			if firstByte && isStreaming {
				ttftMs = int(time.Since(start).Milliseconds())
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

	go parseAndLogUsage(captured, resp.Header.Get("Content-Encoding"), isStreaming, userID, accountID, endpoint, resp.StatusCode, latencyMs, ttftMs, messagesJSON, h.db, logStream, statsStream)
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

func parseAndLogUsage(body []byte, contentEncoding string, isStreaming bool, userID, accountID uint, endpoint string, statusCode, latencyMs, ttftMs int, messagesJSON string, db *gorm.DB, logStream *sse.Broadcaster, statsStream *sse.Broadcaster) {
	var inputTokens, outputTokens, cacheRead, cacheWrite int
	var model string
	var responseText strings.Builder

	body = decodeBody(body, contentEncoding)

	if len(body) == 0 {
		log.Printf("proxy: empty response body for user=%d account=%d status=%d", userID, accountID, statusCode)
	}

	if isStreaming {
		// Anthropic SSE uses \r\n line endings — normalize before splitting
		body = bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))
		body = bytes.ReplaceAll(body, []byte("\r"), []byte("\n"))
		lines := bytes.Split(body, []byte("\n"))
		for _, line := range lines {
			if !bytes.HasPrefix(line, []byte("data: ")) {
				continue
			}
			data := line[6:]
			if string(data) == "[DONE]" {
				continue
			}

			var event struct {
				Type    string `json:"type"`
				Message struct {
					Model string `json:"model"`
					Usage struct {
						InputTokens              int `json:"input_tokens"`
						CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
						CacheReadInputTokens     int `json:"cache_read_input_tokens"`
					} `json:"usage"`
				} `json:"message"`
				Usage struct {
					OutputTokens int `json:"output_tokens"`
				} `json:"usage"`
				Delta struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"delta"`
			}
			if err := json.Unmarshal(data, &event); err != nil {
				continue
			}
			switch event.Type {
			case "message_start":
				model = event.Message.Model
				inputTokens = event.Message.Usage.InputTokens
				cacheWrite = event.Message.Usage.CacheCreationInputTokens
				cacheRead = event.Message.Usage.CacheReadInputTokens
			case "message_delta":
				outputTokens = event.Usage.OutputTokens
			case "content_block_delta":
				if event.Delta.Type == "text_delta" {
					responseText.WriteString(event.Delta.Text)
				}
			}
		}
	} else {
		var resp struct {
			Model string `json:"model"`
			Usage struct {
				InputTokens              int `json:"input_tokens"`
				OutputTokens             int `json:"output_tokens"`
				CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
				CacheReadInputTokens     int `json:"cache_read_input_tokens"`
			} `json:"usage"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(body, &resp); err == nil {
			model = resp.Model
			inputTokens = resp.Usage.InputTokens
			outputTokens = resp.Usage.OutputTokens
			cacheWrite = resp.Usage.CacheCreationInputTokens
			cacheRead = resp.Usage.CacheReadInputTokens
			for _, block := range resp.Content {
				if block.Type == "text" {
					responseText.WriteString(block.Text)
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
		return
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

	// Save conversation log for all successful requests with messages (including tool-use-only responses)
	if len(messagesJSON) > 0 && messagesJSON != "null" && statusCode == 200 && (inputTokens > 0 || outputTokens > 0) {
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

// allowedUpstreamRoute lists the only Anthropic endpoints users may reach with a
// pooled account's credentials; anything else (account profile, files, batches…)
// would let any user act as the account owner outside quota accounting.
func allowedUpstreamRoute(method, path string) bool {
	switch path {
	case "/v1/messages", "/v1/messages/count_tokens":
		return method == http.MethodPost
	case "/v1/models":
		return method == http.MethodGet
	}
	return false
}

func ipAllowed(r *http.Request, whitelist string) bool {
	ip := net.ParseIP(middleware.ClientIP(r))
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
	// Strip display suffix like "[1m]" appended by Claude Code UI
	if idx := strings.IndexByte(model, '['); idx != -1 {
		model = model[:idx]
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

// quotaTokensSQL is what token quotas count: input, output and cache writes.
// Cache reads are excluded (they cost 2.5-10% of input, and Anthropic's own input
// rate limits ignore them); budgets in USD price every token type instead.
const quotaTokensSQL = "COALESCE(SUM(input_tokens + output_tokens + cache_write), 0)"

func poolTokensSince(db *gorm.DB, poolID uint, since time.Time) int64 {
	var used int64
	db.Model(&database.UsageLog{}).
		Joins("JOIN claude_accounts ON usage_logs.account_id = claude_accounts.id").
		Joins("JOIN account_pools ON account_pools.account_id = claude_accounts.id").
		Where("account_pools.pool_id = ? AND usage_logs.created_at >= ?", poolID, since).
		Select("COALESCE(SUM(usage_logs.input_tokens + usage_logs.output_tokens + usage_logs.cache_write), 0)").
		Row().Scan(&used)
	return used
}

// poolsWithinQuota returns the pools in poolIDs that have not used up their daily or monthly quota.
func poolsWithinQuota(poolIDs []uint, quotaPools []database.Pool, dailyUsed, monthlyUsed map[uint]int64) []uint {
	exhausted := make(map[uint]bool, len(quotaPools))
	for _, p := range quotaPools {
		if (p.DailyTokenQuota > 0 && dailyUsed[p.ID] >= int64(p.DailyTokenQuota)) ||
			(p.MonthlyTokenQuota > 0 && monthlyUsed[p.ID] >= int64(p.MonthlyTokenQuota)) {
			exhausted[p.ID] = true
		}
	}
	usable := make([]uint, 0, len(poolIDs))
	for _, id := range poolIDs {
		if !exhausted[id] {
			usable = append(usable, id)
		}
	}
	return usable
}

// estimateMonthlyCost queries the DB for cost since monthStart.
func estimateMonthlyCost(db *gorm.DB, userID uint, monthStart time.Time) float64 {
	type row struct {
		Model        string
		InputTokens  int64
		OutputTokens int64
		CacheRead    int64
		CacheWrite   int64
	}
	var rows []row
	db.Model(&database.UsageLog{}).
		Where("user_id = ? AND created_at >= ?", userID, monthStart).
		Select("model, COALESCE(SUM(input_tokens),0) as input_tokens, COALESCE(SUM(output_tokens),0) as output_tokens, " +
			"COALESCE(SUM(cache_read),0) as cache_read, COALESCE(SUM(cache_write),0) as cache_write").
		Group("model").Scan(&rows)
	var total float64
	for _, r := range rows {
		total += estimateCostRow(r.Model, r.InputTokens, r.OutputTokens, r.CacheRead, r.CacheWrite)
	}
	return total
}

// modelPrice is in USD per million tokens. Cache writes are billed at 1.25x input
// (5-minute TTL); cache-read multipliers differ by model, so they are listed.
type modelPrice struct {
	match                    string
	input, output, cacheRead float64
}

// Ordered most specific first, since matching is by substring ("claude-opus-5" must not price "claude-opus-5-5").
var modelPricingProxy = []modelPrice{
	{"claude-fable-5-2", 8, 40, 0.20},
	{"claude-mythos-5-2", 8, 40, 0.20},
	{"claude-fable-5-1", 10, 50, 0.25},
	{"claude-mythos-5-1", 10, 50, 0.25},
	{"claude-fable-5", 10, 50, 1.00},
	{"claude-mythos-5", 10, 50, 1.00},
	{"claude-opus-5-5", 4, 20, 0.20},
	{"claude-opus-5", 5, 25, 0.50},
	{"claude-opus-4-8", 5, 25, 0.50},
	{"claude-opus-4-7", 5, 25, 0.50},
	{"claude-opus-4-6", 5, 25, 0.50},
	{"claude-opus-4", 15, 75, 1.50},
	{"claude-sonnet-5-5", 2, 10, 0.10},
	{"claude-sonnet-5", 2, 10, 0.20},
	{"claude-sonnet-4", 3, 15, 0.30},
	{"claude-haiku-5-5", 0.10, 0.50, 0.01},
	{"claude-haiku-4-5", 1, 5, 0.10},
	{"claude-3-7-sonnet", 3, 15, 0.30},
	{"claude-3-5-sonnet", 3, 15, 0.30},
	{"claude-3-5-haiku", 0.80, 4, 0.08},
	{"claude-3-opus", 15, 75, 1.50},
	{"claude-3-sonnet", 3, 15, 0.30},
	{"claude-3-haiku", 0.25, 1.25, 0.03},
}

// unknownModelPrice charges models missing from the table at the top rate, so a
// new or unlisted model cannot be used to spend a budget for free.
var unknownModelPrice = modelPrice{"", 10, 50, 1.00}

func estimateCostRow(model string, input, output, cacheRead, cacheWrite int64) float64 {
	price := unknownModelPrice
	for _, p := range modelPricingProxy {
		if strings.Contains(model, p.match) {
			price = p
			break
		}
	}
	return (float64(input)*price.input +
		float64(output)*price.output +
		float64(cacheRead)*price.cacheRead +
		float64(cacheWrite)*price.input*1.25) / 1_000_000
}

// claudeCodeLeadPrefixes mark the system blocks Claude Code sends first: an
// optional billing header block, then the identity block. Anthropic only
// accepts OAuth (subscription) credentials when the system prompt still starts
// with these, so the injected prompt goes right after them instead of
// replacing or preceding them.
var claudeCodeLeadPrefixes = []string{
	"x-anthropic-billing-header:",
	"You are Claude Code, Anthropic's official CLI for Claude",
}

func isClaudeCodeLeadBlock(text string) bool {
	for _, p := range claudeCodeLeadPrefixes {
		if strings.HasPrefix(text, p) {
			return true
		}
	}
	return false
}

// injectSystemPrompt adds prefix to the request's system prompt as its own
// text block. It accepts both forms the Messages API allows: a plain string
// and an array of content blocks (the form Claude Code always sends). Existing
// blocks, including their cache_control markers, are kept untouched.
func injectSystemPrompt(body []byte, prefix string) []byte {
	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		return body
	}

	var blocks []map[string]json.RawMessage
	raw, present := req["system"]
	var str string
	switch {
	case !present || string(raw) == "null":
		// No system prompt yet: the injected text becomes the whole prompt.
	case json.Unmarshal(raw, &str) == nil:
		if str != "" {
			textRaw, _ := json.Marshal(str)
			blocks = []map[string]json.RawMessage{{"type": json.RawMessage(`"text"`), "text": textRaw}}
		}
	case json.Unmarshal(raw, &blocks) == nil:
	default:
		return body
	}

	insertAt := 0
	for insertAt < len(blocks) {
		var text string
		if json.Unmarshal(blocks[insertAt]["text"], &text) != nil || !isClaudeCodeLeadBlock(text) {
			break
		}
		insertAt++
	}

	prefixRaw, err := json.Marshal(prefix)
	if err != nil {
		return body
	}
	injected := map[string]json.RawMessage{"type": json.RawMessage(`"text"`), "text": prefixRaw}

	out := make([]map[string]json.RawMessage, 0, len(blocks)+1)
	out = append(out, blocks[:insertAt]...)
	out = append(out, injected)
	out = append(out, blocks[insertAt:]...)

	sysRaw, err := json.Marshal(out)
	if err != nil {
		return body
	}
	req["system"] = sysRaw

	result, err := json.Marshal(req)
	if err != nil {
		return body
	}
	return result
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// acceptsGzip reports whether an Accept-Encoding header value allows gzip.
func acceptsGzip(header string) bool {
	for _, part := range strings.Split(header, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "gzip" && name != "x-gzip" && name != "*" {
			continue
		}
		q := strings.ToLower(strings.ReplaceAll(params, " ", ""))
		if strings.HasPrefix(q, "q=") {
			if v, err := strconv.ParseFloat(q[2:], 64); err == nil && v == 0 {
				continue
			}
		}
		return true
	}
	return false
}

// maxDecodedCapture bounds the decompressed size of a captured body.
const maxDecodedCapture = 32 << 20

// decodeBody returns the decoded form of a captured response body for usage
// parsing. A gzip stream cut short by the capture limit is decoded as far as
// it goes; anything undecodable is returned unchanged.
func decodeBody(body []byte, contentEncoding string) []byte {
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	if enc == "" || enc == "identity" || len(body) == 0 {
		return body
	}
	if enc != "gzip" && enc != "x-gzip" {
		log.Printf("proxy: cannot decode content-encoding %q for usage parsing", contentEncoding)
		return body
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		log.Printf("proxy: gzip header invalid for usage parsing: %v", err)
		return body
	}
	defer zr.Close()
	var out bytes.Buffer
	if _, err := io.Copy(&out, io.LimitReader(zr, maxDecodedCapture)); err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		log.Printf("proxy: gzip decode incomplete for usage parsing: %v", err)
	}
	return out.Bytes()
}
