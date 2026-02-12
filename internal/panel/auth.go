package panel

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "dnsttui_session"
	sessionDuration   = 24 * time.Hour
)

func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (p *Panel) createSession(w http.ResponseWriter) error {
	token, err := generateSessionToken()
	if err != nil {
		return err
	}
	expiresAt := time.Now().UTC().Add(sessionDuration).Format("2006-01-02 15:04:05")
	if err := p.db.CreateSession(token, expiresAt); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     p.basePath + "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})
	return nil
}

func (p *Panel) isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	valid, err := p.db.ValidateSession(cookie.Value)
	if err != nil || !valid {
		return false
	}
	return true
}

func (p *Panel) clearSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		p.db.DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     p.basePath + "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

func (p *Panel) requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.isAuthenticated(r) {
			// Check for basic auth as fallback (bcrypt comparison)
			user, pass, ok := r.BasicAuth()
			if ok {
				cfg, err := p.db.GetConfig()
				if err == nil && user == cfg.AdminUser {
					if bcrypt.CompareHashAndPassword([]byte(cfg.AdminPass), []byte(pass)) == nil {
						handler(w, r)
						return
					}
				}
				log.Printf("auth: basic-auth failed user=%q from %s", user, r.RemoteAddr)
			}
			if isHTMX(r) {
				w.Header().Set("HX-Redirect", p.basePath+"/login")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, p.basePath+"/login", http.StatusSeeOther)
			return
		}
		handler(w, r)
	}
}

func isHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}
