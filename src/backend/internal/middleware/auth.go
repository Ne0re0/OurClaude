package middleware

import (
	"context"
	"net/http"
	"time"

	"claude-proxy/internal/auth"
	"claude-proxy/internal/config"
	"claude-proxy/internal/database"

	"gorm.io/gorm"
)

type contextKey string

const adminKey contextKey = "admin"

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
			if err := db.Select("id").First(&admin, claims.AdminID).Error; err != nil {
				http.Error(w, `{"error":"invalid session"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), adminKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetAdmin(ctx context.Context) *auth.Claims {
	v := ctx.Value(adminKey)
	if v == nil {
		return nil
	}
	claims, _ := v.(*auth.Claims)
	return claims
}
