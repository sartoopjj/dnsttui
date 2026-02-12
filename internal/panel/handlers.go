package panel

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	dnsttserver "github.com/sartoopjj/dnsttui/dnstt-server"
	"github.com/sartoopjj/dnsttui/internal/panel/components"
	"github.com/sartoopjj/dnsttui/internal/shadowsocks"
	"github.com/sartoopjj/dnsttui/internal/xray"
	"golang.org/x/crypto/bcrypt"
)

func (p *Panel) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if p.isAuthenticated(r) {
		http.Redirect(w, r, p.basePath+"/", http.StatusSeeOther)
		return
	}
	components.LoginPage("").Render(r.Context(), w)
}

func (p *Panel) handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	cfg, err := p.db.GetConfig()
	if err != nil {
		components.LoginPage("Internal error").Render(r.Context(), w)
		return
	}

	if username != cfg.AdminUser || bcrypt.CompareHashAndPassword([]byte(cfg.AdminPass), []byte(password)) != nil {
		log.Printf("auth: login failed user=%q from %s", username, r.RemoteAddr)
		components.LoginPage("Invalid credentials").Render(r.Context(), w)
		return
	}

	if err := p.createSession(w); err != nil {
		components.LoginPage("Session error").Render(r.Context(), w)
		return
	}

	log.Printf("auth: login success user=%q from %s", username, r.RemoteAddr)
	http.Redirect(w, r, p.basePath+"/", http.StatusSeeOther)
}

func (p *Panel) handleLogout(w http.ResponseWriter, r *http.Request) {
	log.Printf("auth: logout from %s", r.RemoteAddr)
	p.clearSession(w, r)
	http.Redirect(w, r, p.basePath+"/login", http.StatusSeeOther)
}

func (p *Panel) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	totalUsers, _ := p.db.GetUserCount()
	activeUsers, _ := p.db.GetActiveUserCount()
	trafficUp, trafficDown, _ := p.db.GetTotalTraffic()

	dnsttStatus := "Stopped"
	if dnsttserver.Running.Load() {
		dnsttStatus = "Running"
	}

	data := components.DashboardData{
		TotalUsers:    totalUsers,
		ActiveUsers:   activeUsers,
		TrafficUp:     trafficUp,
		TrafficDown:   trafficDown,
		DNSTTStatus:   dnsttStatus,
		SSStatus:      "Running",
		DNSTTSessions: dnsttserver.ActiveSessions.Load(),
		DNSTTStreams:  dnsttserver.ActiveStreams.Load(),
		SSConnections: p.ss.ActiveConnections(),
	}

	components.DashboardPage(data).Render(r.Context(), w)
}

func (p *Panel) handleUsersPage(w http.ResponseWriter, r *http.Request) {
	users, err := p.db.ListUsers()
	if err != nil {
		http.Error(w, "Failed to list users", http.StatusInternalServerError)
		return
	}
	components.UsersPage(users).Render(r.Context(), w)
}

func (p *Panel) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if username == "" {
		w.WriteHeader(http.StatusBadRequest)
		components.Alert("Username is required", "error").Render(r.Context(), w)
		return
	}

	exists, _ := p.db.UserExists(username, 0)
	if exists {
		w.WriteHeader(http.StatusBadRequest)
		components.Alert("Username already exists", "error").Render(r.Context(), w)
		return
	}

	cfg, err := p.db.GetConfig()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		components.Alert("Failed to load config", "error").Render(r.Context(), w)
		return
	}

	// Generate user key
	userKey, err := shadowsocks.GenerateKey(cfg.SSMethod)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		components.Alert("Failed to generate key", "error").Render(r.Context(), w)
		return
	}

	trafficLimit, _ := strconv.ParseInt(r.FormValue("traffic_limit"), 10, 64)
	// Convert GB to bytes
	trafficLimit = trafficLimit * 1024 * 1024 * 1024

	var expireAt *time.Time
	if exp := r.FormValue("expire_at"); exp != "" {
		t, err := time.Parse("2006-01-02", exp)
		if err == nil {
			expireAt = &t
		}
	}

	user, err := p.db.CreateUser(username, userKey, trafficLimit, expireAt)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		components.Alert("Failed to create user: "+err.Error(), "error").Render(r.Context(), w)
		return
	}

	// Reload SS users
	if err := p.ss.ReloadUsers(); err != nil {
		log.Printf("reload SS users: %v", err)
	}

	// Return the new user row for htmx swap
	components.UserRow(*user).Render(r.Context(), w)
}

func (p *Panel) handleGetUserRow(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	user, err := p.db.GetUser(id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	components.UserRow(*user).Render(r.Context(), w)
}

func (p *Panel) handleEditUserForm(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	user, err := p.db.GetUser(id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	components.EditUserForm(*user).Render(r.Context(), w)
}

func (p *Panel) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	user, err := p.db.GetUser(id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	username := r.FormValue("username")
	if username == "" {
		username = user.Username
	}

	password := r.FormValue("password")
	if password == "" {
		password = user.Password
	}

	enabled := r.FormValue("enabled") == "on" || r.FormValue("enabled") == "true"

	trafficLimit, _ := strconv.ParseInt(r.FormValue("traffic_limit"), 10, 64)
	trafficLimit = trafficLimit * 1024 * 1024 * 1024

	var expireAt *time.Time
	if exp := r.FormValue("expire_at"); exp != "" {
		t, err := time.Parse("2006-01-02", exp)
		if err == nil {
			expireAt = &t
		}
	}

	if err := p.db.UpdateUser(id, username, password, enabled, trafficLimit, expireAt); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		components.Alert("Failed to update user: "+err.Error(), "error").Render(r.Context(), w)
		return
	}

	// Reload SS users
	if err := p.ss.ReloadUsers(); err != nil {
		log.Printf("reload SS users: %v", err)
	}

	updated, _ := p.db.GetUser(id)
	components.UserRow(*updated).Render(r.Context(), w)
}

func (p *Panel) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	if err := p.db.DeleteUser(id); err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	if err := p.ss.ReloadUsers(); err != nil {
		log.Printf("reload SS users: %v", err)
	}

	w.WriteHeader(http.StatusOK)
}

func (p *Panel) handleUserConfig(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	user, err := p.db.GetUser(id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	cfg, err := p.db.GetConfig()
	if err != nil {
		http.Error(w, "Config error", http.StatusInternalServerError)
		return
	}

	configJSON, err := xray.GenerateMahsaNGConfig(xray.GenerateParams{
		DNSResolverAddr: cfg.DNSResolverAddr,
		DNSResolverPort: cfg.DNSResolverPort,
		SSMethod:        cfg.SSMethod,
		ServerKey:       cfg.SSServerKey,
		UserKey:         user.Password,
		DNSTTDomain:     cfg.DNSTTDomain,
		DNSTTPubkey:     cfg.DNSTTPubkey,
	})
	if err != nil {
		http.Error(w, "Config generation error", http.StatusInternalServerError)
		return
	}

	components.UserConfigModal(user.Username, string(configJSON)).Render(r.Context(), w)
}

func (p *Panel) handleToggleUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	user, err := p.db.ToggleUser(id)
	if err != nil {
		http.Error(w, "Failed to toggle user", http.StatusInternalServerError)
		return
	}

	if err := p.ss.ReloadUsers(); err != nil {
		log.Printf("reload SS users: %v", err)
	}

	components.UserRow(*user).Render(r.Context(), w)
}

func (p *Panel) handleResetTraffic(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	user, err := p.db.ResetTraffic(id)
	if err != nil {
		http.Error(w, "Failed to reset traffic", http.StatusInternalServerError)
		return
	}

	if err := p.ss.ReloadUsers(); err != nil {
		log.Printf("reload SS users: %v", err)
	}

	components.UserRow(*user).Render(r.Context(), w)
}

func (p *Panel) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	cfg, err := p.db.GetConfig()
	if err != nil {
		http.Error(w, "Failed to load config", http.StatusInternalServerError)
		return
	}
	components.SettingsPage(*cfg).Render(r.Context(), w)
}

func (p *Panel) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := p.db.GetConfig()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		components.Alert("Failed to load config", "error").Render(r.Context(), w)
		return
	}

	if v := r.FormValue("dnstt_domain"); v != "" {
		cfg.DNSTTDomain = v
	}
	if v := r.FormValue("dnstt_udp_addr"); v != "" {
		cfg.DNSTTUDPAddr = v
	}
	if v := r.FormValue("dnstt_mtu"); v != "" {
		if mtu, err := strconv.Atoi(v); err == nil && mtu > 0 {
			cfg.DNSTTMTU = mtu
		}
	}
	if v := r.FormValue("ss_port"); v != "" {
		if port, err := strconv.Atoi(v); err == nil && port > 0 {
			cfg.SSPort = port
		}
	}
	if v := r.FormValue("ss_listen_addr"); v != "" {
		cfg.SSListenAddr = v
	}
	if v := r.FormValue("dns_resolver_addr"); v != "" {
		cfg.DNSResolverAddr = v
	}
	if v := r.FormValue("dns_resolver_port"); v != "" {
		if port, err := strconv.Atoi(v); err == nil && port > 0 {
			cfg.DNSResolverPort = port
		}
	}
	if v := r.FormValue("panel_domain"); v != "" {
		cfg.PanelDomain = v
	}
	if v := r.FormValue("acme_email"); v != "" {
		cfg.ACMEEmail = v
	}
	if v := r.FormValue("admin_user"); v != "" {
		cfg.AdminUser = v
	}
	// panel_base_path can be set to empty (to serve at root)
	if r.Form.Has("panel_base_path") {
		cfg.PanelBasePath = r.FormValue("panel_base_path")
	}

	if err := p.db.UpdateConfig(cfg); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		components.Alert("Failed to save settings: "+err.Error(), "error").Render(r.Context(), w)
		return
	}

	components.Alert("Settings saved. Some changes require a restart.", "success").Render(r.Context(), w)
}

func (p *Panel) handleRestart(w http.ResponseWriter, r *http.Request) {
	log.Printf("panel: restart requested from %s", r.RemoteAddr)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<div class="rounded-md bg-yellow-50 p-4 mb-4" role="alert"><p class="text-sm font-medium text-yellow-800">Restarting all services... Page will reload automatically.</p></div><script>
setTimeout(function() {
	var check = setInterval(function() {
		fetch(window.location.href, {method:'HEAD'}).then(function(r) {
			if (r.ok) { clearInterval(check); window.location.reload(); }
		}).catch(function(){});
	}, 1000);
}, 3000);
</script>`)

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	go func() {
		time.Sleep(500 * time.Millisecond)
		select {
		case p.restartCh <- struct{}{}:
		default:
		}
	}()
}

func (p *Panel) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	current := r.FormValue("current_password")
	newPass := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if newPass != confirm {
		w.WriteHeader(http.StatusBadRequest)
		components.Alert("Passwords do not match", "error").Render(r.Context(), w)
		return
	}

	if len(newPass) < 6 {
		w.WriteHeader(http.StatusBadRequest)
		components.Alert("Password must be at least 6 characters", "error").Render(r.Context(), w)
		return
	}

	cfg, err := p.db.GetConfig()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		components.Alert("Internal error", "error").Render(r.Context(), w)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(cfg.AdminPass), []byte(current)) != nil {
		w.WriteHeader(http.StatusBadRequest)
		components.Alert("Current password is incorrect", "error").Render(r.Context(), w)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		components.Alert("Failed to hash password", "error").Render(r.Context(), w)
		return
	}

	if err := p.db.UpdateAdminPassword(string(hash)); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		components.Alert("Failed to update password", "error").Render(r.Context(), w)
		return
	}

	components.Alert("Password updated successfully", "success").Render(r.Context(), w)
}

func (p *Panel) handleHelpPage(w http.ResponseWriter, r *http.Request) {
	cfg, err := p.db.GetConfig()
	if err != nil {
		http.Error(w, "Failed to load config", http.StatusInternalServerError)
		return
	}
	domain := cfg.DNSTTDomain
	if domain == "" {
		domain = "t.example.com"
	}
	components.HelpPage(domain, cfg.DNSTTPubkey).Render(r.Context(), w)
}

func (p *Panel) handleDiagnosticsPage(w http.ResponseWriter, r *http.Request) {
	cfg, _ := p.db.GetConfig()

	data := components.DiagnosticsData{
		DNSTTRunning:  dnsttserver.Running.Load(),
		DNSTTSessions: dnsttserver.ActiveSessions.Load(),
		DNSTTStreams:  dnsttserver.ActiveStreams.Load(),
		SSConnections: p.ss.ActiveConnections(),
	}

	if cfg != nil {
		data.DNSTTDomain = cfg.DNSTTDomain
		data.DNSTTUDPAddr = cfg.DNSTTUDPAddr
		data.DNSResolverAddr = cfg.DNSResolverAddr
		data.DNSResolverPort = cfg.DNSResolverPort
	}

	components.DiagnosticsPage(data).Render(r.Context(), w)
}
