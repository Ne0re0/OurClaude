package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"codex-proxy/internal/database"
	"codex-proxy/internal/middleware"
	"codex-proxy/internal/oauth"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const oauthConnectLifetime = 15 * time.Minute

type oauthConnectStartResponse struct {
	ID        uint      `json:"id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// StartOAuthConnect creates a one-time pairing token. The token is handed to
// the local OurCodex CLI, which owns the required loopback OAuth callback.
func (h *AccountsHandler) StartOAuthConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		PoolIDs []uint `json:"pool_ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid request body"))
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, errResp("name is required"))
		return
	}
	poolIDs, err := validatePoolIDs(h.db, req.PoolIDs)
	if err != nil {
		if errors.Is(err, errUnknownPool) {
			writeJSON(w, http.StatusBadRequest, errResp(err.Error()))
		} else {
			writeJSON(w, http.StatusInternalServerError, errResp("failed to validate pools"))
		}
		return
	}

	hostID, err := getOrCreateSIWCHostID(h.db)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to prepare ChatGPT sign-in"))
		return
	}
	token, err := randomConnectToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to create pairing token"))
		return
	}
	poolJSON, _ := json.Marshal(poolIDs)
	claims := middleware.GetAdmin(r.Context())
	session := database.OAuthConnectSession{
		TokenHash: hashConnectToken(token),
		Name:      req.Name,
		PoolIDs:   string(poolJSON),
		HostID:    hostID,
		ExpiresAt: time.Now().Add(oauthConnectLifetime),
	}
	if claims != nil {
		session.AdminID = claims.AdminID
		session.AdminUsername = claims.Username
	}
	if err := h.db.Create(&session).Error; err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to create pairing session"))
		return
	}
	logAudit(h.db, r, "start_oauth_connect", "account:"+req.Name, fmt.Sprintf("session=%d", session.ID))
	writeJSON(w, http.StatusCreated, oauthConnectStartResponse{ID: session.ID, Token: token, ExpiresAt: session.ExpiresAt})
}

// OAuthConnectStatus lets the dashboard poll without ever receiving tokens.
func (h *AccountsHandler) OAuthConnectStatus(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid id"))
		return
	}
	var session database.OAuthConnectSession
	if err := h.db.First(&session, id).Error; err != nil {
		writeJSON(w, http.StatusNotFound, errResp("pairing session not found"))
		return
	}
	status := "pending"
	if session.UsedAt != nil {
		status = "completed"
	} else if time.Now().After(session.ExpiresAt) {
		status = "expired"
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":         session.ID,
		"status":     status,
		"expires_at": session.ExpiresAt,
		"account_id": session.AccountID,
	})
}

// OAuthConnectInfo returns only non-secret parameters needed to begin local
// authorization. The one-time bearer token is never accepted in a URL.
func (h *AccountsHandler) OAuthConnectInfo(w http.ResponseWriter, r *http.Request) {
	session, err := h.findOAuthConnect(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errResp(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"host_id":    session.HostID,
		"agent_name": "OurCodex",
		"expires_at": session.ExpiresAt,
	})
}

// CompleteOAuthConnect verifies the OpenAI-signed credentials again on the
// server, encrypts them, consumes the pairing session atomically, and applies
// the administrator's original pool selection.
func (h *AccountsHandler) CompleteOAuthConnect(w http.ResponseWriter, r *http.Request) {
	session, err := h.findOAuthConnect(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errResp(err.Error()))
		return
	}
	var req struct {
		ClientID string                  `json:"client_id"`
		Tokens   oauth.SIWCTokenResponse `json:"tokens"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("invalid request body"))
		return
	}

	verifyClient := &http.Client{Timeout: 15 * time.Second}
	identity, err := oauth.VerifySIWCCredentials(r.Context(), verifyClient, req.Tokens, req.ClientID, "")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errResp("ChatGPT credentials were rejected: "+err.Error()))
		return
	}

	encAccess, err := h.enc.Encrypt(req.Tokens.AccessToken)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to encrypt access token"))
		return
	}
	encRefresh, err := h.enc.Encrypt(req.Tokens.RefreshToken)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to encrypt refresh token"))
		return
	}
	encID, err := h.enc.Encrypt(req.Tokens.IDToken)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("failed to encrypt ID token"))
		return
	}

	var poolIDs []uint
	if err := json.Unmarshal([]byte(session.PoolIDs), &poolIDs); err != nil {
		writeJSON(w, http.StatusInternalServerError, errResp("pairing session is invalid"))
		return
	}

	var accountID uint
	now := time.Now()
	err = h.db.Transaction(func(tx *gorm.DB) error {
		consume := tx.Model(&database.OAuthConnectSession{}).
			Where("id = ? AND used_at IS NULL AND expires_at > ?", session.ID, now).
			Updates(map[string]interface{}{"used_at": now})
		if consume.Error != nil {
			return consume.Error
		}
		if consume.RowsAffected != 1 {
			return fmt.Errorf("pairing session was already used or expired")
		}
		if len(poolIDs) > 0 {
			var poolCount int64
			if err := tx.Model(&database.Pool{}).Where("id IN ?", poolIDs).Count(&poolCount).Error; err != nil {
				return err
			}
			if poolCount != int64(len(poolIDs)) {
				return fmt.Errorf("one or more selected pools no longer exist")
			}
		}

		var account database.CodexAccount
		lookup := tx.Where("o_auth_provider = ? AND o_auth_client_id = ?", "siwc", req.ClientID).First(&account)
		if lookup.Error != nil && lookup.Error != gorm.ErrRecordNotFound {
			return lookup.Error
		}
		updates := map[string]interface{}{
			"name":               session.Name,
			"access_token":       encAccess,
			"refresh_token":      encRefresh,
			"refresh_token_hash": oauth.RefreshTokenHash(req.Tokens.RefreshToken),
			"id_token":           encID,
			"o_auth_issuer":      oauth.SIWCIssuer,
			"o_auth_client_id":   req.ClientID,
			"o_auth_provider":    "siwc",
			"o_auth_subject":     identity.Subject,
			"o_auth_host_id":     session.HostID,
			"expires_at":         identity.ExpiresAt,
			"account_type":       "oauth",
			"status":             "active",
			"last_error":         "",
		}
		if lookup.Error == gorm.ErrRecordNotFound {
			account = database.CodexAccount{
				Name:             session.Name,
				AccessToken:      encAccess,
				RefreshToken:     encRefresh,
				RefreshTokenHash: oauth.RefreshTokenHash(req.Tokens.RefreshToken),
				IDToken:          encID,
				OAuthIssuer:      oauth.SIWCIssuer,
				OAuthClientID:    req.ClientID,
				OAuthProvider:    "siwc",
				OAuthSubject:     identity.Subject,
				OAuthHostID:      session.HostID,
				ExpiresAt:        identity.ExpiresAt,
				AccountType:      "oauth",
				Status:           "active",
			}
			if err := tx.Create(&account).Error; err != nil {
				return err
			}
		} else if err := tx.Model(&account).Updates(updates).Error; err != nil {
			return err
		}
		if err := tx.Where("account_id = ?", account.ID).Delete(&database.AccountPool{}).Error; err != nil {
			return err
		}
		for _, poolID := range poolIDs {
			if err := tx.Create(&database.AccountPool{AccountID: account.ID, PoolID: poolID}).Error; err != nil {
				return err
			}
		}
		accountID = account.ID
		return tx.Model(&database.OAuthConnectSession{}).Where("id = ?", session.ID).Update("account_id", account.ID).Error
	})
	if err != nil {
		writeJSON(w, http.StatusConflict, errResp(err.Error()))
		return
	}

	h.db.Create(&database.AuditLog{
		AdminID:       session.AdminID,
		AdminUsername: session.AdminUsername,
		Action:        "complete_oauth_connect",
		Target:        fmt.Sprintf("account:%d", accountID),
		Details:       "verified Sign in with ChatGPT",
	})
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message":    "ChatGPT account connected",
		"account_id": accountID,
		"email":      identity.Email,
	})
}

func (h *AccountsHandler) findOAuthConnect(r *http.Request) (*database.OAuthConnectSession, error) {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == auth || !strings.HasPrefix(token, "oc-connect-") {
		return nil, fmt.Errorf("invalid or missing pairing token")
	}
	var session database.OAuthConnectSession
	if err := h.db.Where("token_hash = ?", hashConnectToken(token)).First(&session).Error; err != nil {
		return nil, fmt.Errorf("invalid or expired pairing token")
	}
	if session.UsedAt != nil || time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("pairing token was already used or expired")
	}
	return &session, nil
}

func getOrCreateSIWCHostID(db *gorm.DB) (string, error) {
	const key = "siwc_host_id"
	var setting database.Setting
	if err := db.First(&setting, "key = ?", key).Error; err == nil {
		return setting.Value, nil
	} else if err != gorm.ErrRecordNotFound {
		return "", err
	}
	value := "urn:uuid:" + uuid.NewString()
	setting = database.Setting{Key: key, Value: value}
	if err := db.Create(&setting).Error; err != nil {
		if err := db.First(&setting, "key = ?", key).Error; err != nil {
			return "", err
		}
	}
	return setting.Value, nil
}

func randomConnectToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "oc-connect-" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashConnectToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
