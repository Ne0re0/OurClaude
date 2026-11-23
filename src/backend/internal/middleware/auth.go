package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"claude-proxy/internal/auth"
	"claude-proxy/internal/config"
	"claude-proxy/internal/database"

	"gorm.io/gorm"
)

type contextKey string

const (
	adminKey contextKey = "admin"
	roleKey  contextKey = "admin_role"
)

// Authenticate accepts a session cookie only while its admin_sessions row exists,
// so logout, revocation, password changes and admin deletion take effect immediately.
func Authenticate(cfg *config.Config, db *gorm.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(auth.CookieName)
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			claims, err := auth.ValidateToken(cookie.Value, cfg.JWTSecret)
			if err != nil {
				http.Error(w, `{"error":"invalid session"}`, http.StatusUnauthorized)
				return
			}

			var session database.AdminSession
			if err := db.Where("token_hash = ? AND admin_id = ? AND expires_at > ?", auth.HashToken(cookie.Value), claims.AdminID, time.Now()).
				First(&session).Error; err != nil {
				http.Error(w, `{"error":"invalid session"}`, http.StatusUnauthorized)
				return
			}
			var admin database.Admin
			if err := db.Select("id", "role").First(&admin, claims.AdminID).Error; err != nil {
				http.Error(w, `{"error":"invalid session"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), adminKey, claims)
			ctx = context.WithValue(ctx, roleKey, admin.Role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// IsViewer reports whether the authenticated admin has the read-only "viewer" role.
func IsViewer(ctx context.Context) bool {
	role, _ := ctx.Value(roleKey).(string)
	return role == "viewer"
}

// viewerBlockedReads are GET endpoints that hand out secrets (decrypted OAuth
// credentials, invite links, pre-auth download links).
var viewerBlockedReads = []string{"/api/admin/invites", "/api/admin/download-links"}

// ReadOnlyForViewers keeps "viewer" admins to reading: no changes and no secrets.
// They can still manage their own login (password, 2FA) under /api/auth/.
func ReadOnlyForViewers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsViewer(r.Context()) && !viewerMayAccess(r.Method, r.URL.Path) {
			http.Error(w, `{"error":"viewers have read-only access"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func viewerMayAccess(method, path string) bool {
	if strings.HasPrefix(path, "/api/auth/") {
		return true
	}
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	if strings.HasPrefix(path, "/api/admin/accounts/") && strings.HasSuffix(path, "/credentials") {
		return false
	}
	for _, p := range viewerBlockedReads {
		if path == p || strings.HasPrefix(path, p+"/") {
			return false
		}
	}
	return true
}

func GetAdmin(ctx context.Context) *auth.Claims {
	v := ctx.Value(adminKey)
	if v == nil {
		return nil
	}
	claims, _ := v.(*auth.Claims)
	return claims
}
