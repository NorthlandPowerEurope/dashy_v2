package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net"
	"strings"
	"net/url"
	"sync"
	"time"

	"github.com/NorthlandPowerEurope/dashy/agent/auth"
	"github.com/NorthlandPowerEurope/dashy/certutil"

	"github.com/NorthlandPowerEurope/dashy/server"
	"github.com/gin-gonic/gin"
	"github.com/malivvan/servicekit"
	"github.com/malivvan/servicekit/log"
)

type Config struct {
	Webserver  WebserverConfig    `json:"webserver"`
	Dashboards []server.Dashboard `json:"dashboards"`
	Logging    log.Config         `json:"logging"`
}

type WebserverConfig struct {
	Address             string      `json:"address"`
	TLS                 []TLSConfig `json:"tls"`
	Authentication      string      `json:"authentication"`
	ReadTimeoutSeconds  int         `json:"read_timeout_seconds"`
	WriteTimeoutSeconds int         `json:"write_timeout_seconds"`
	IdleTimeoutSeconds  int         `json:"idle_timeout_seconds"`
	SessionTimeout      int         `json:"session_timeout_seconds"`
}

type TLSConfig struct {
	Domain      string `json:"domain,omitempty"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

type session struct {
 username string
 expires time.Time
 lastHeartbeat time.Time
 lastIP string
 userAgent string
 auditID string
 inactive bool
}

const sessionCookieName = "dashy_session"
const inactivityThreshold = 90 * time.Second

func peerIP(c *gin.Context) string {
 host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
 if err == nil { return host }
 return c.Request.RemoteAddr
}

// Redirects must remain within this application, never to an external origin.
func localRedirect(target string) string {
 if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") || strings.ContainsAny(target, "\\\r\n") { return "/" }
 return target
}

func audit(event, username, ip, auditID, reason, agent string) {
 entry := log.Info()
 if event == "LOGIN_FAILED" || event == "INVALID_SESSION" { entry = log.Warn() }
 entry.Str("event", event).Str("user", username).Str("ip", ip).
  Str("audit_id", auditID).Str("reason", reason).Str("user_agent", agent).
  Time("event_time_utc", time.Now().UTC()).Msg("authentication audit")
}

func newSessionID() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

type Service struct {
	dashboards     []*server.Dashboard
    monitorStop chan struct{}
	webserver      *http.Server
	authProvider   *auth.Provider
	sessions       map[string]*session
	sessionMutex   sync.Mutex
	sessionTimeout time.Duration
}

func (s *Service) Start(workdir servicekit.Workdir) error {

	config := &Config{}
	err := servicekit.Configure(workdir.Path("config.json"), config, &Config{
		Webserver: WebserverConfig{
			Address:             "127.0.0.1:8080",
			ReadTimeoutSeconds:  5,
			WriteTimeoutSeconds: 5,
			IdleTimeoutSeconds:  120,
		},
		Dashboards: []server.Dashboard{},
		Logging: log.Config{
			Level:    "info",
			Compress: true,
		},
	})
	if err != nil {
		return err
	}

	err = log.Start(workdir.Path("log", "dashy.log"), &config.Logging)
	if err != nil {
		return err
	}
	log.Info().Str("name", "dashy").Msg("starting service")

	// copy over dashboards
	s.dashboards = []*server.Dashboard{}
	for i := range config.Dashboards {
		// take the address of the slice element directly instead of
		// copying it into a local variable first - server.Dashboard
		// contains a sync.Mutex, and copying it (even transiently)
		// trips go vet's copylocks check.
		s.dashboards = append(s.dashboards, &config.Dashboards[i])
	}

	// initialize auth state
	if config.Webserver.SessionTimeout <= 0 {
		config.Webserver.SessionTimeout = 3600
	}

	// create routers
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// attach authentication
	switch config.Webserver.Authentication {
	case "none":
		log.Info().Msg("gui authentication is disabled")
	case "basic":
		log.Info().Str("file", workdir.Path("users.json")).Msg("login form auth enabled")
		authProvider, err := auth.New(workdir.Path("users.json"), ";f>3pVk`cp:@Z-Gw")
		if err != nil {
			return err
		}
		s.authProvider = authProvider
		s.sessions = make(map[string]*session)
		s.sessionTimeout = time.Duration(config.Webserver.SessionTimeout) * time.Second

	default:
		return errors.New("authentication type not specified")
	}

	router.GET("/bulma.css", func(c *gin.Context) {
		c.Data(200, "text/css", []byte(server.BulmaCSS))
	})
	router.GET("/fontawesome.css", func(c *gin.Context) {
		c.Data(200, "text/css", []byte(server.FontAwesomeCSS))
	})
	router.GET("/main.css", func(c *gin.Context) {
		c.Data(200, "text/css", []byte(server.MainCSS))
	})
	router.GET("/logo.png", func(c *gin.Context) {
		c.File(workdir.Path("logo.png"))
	})

	if s.authProvider != nil {
		router.GET("/login", s.loginGet)
		router.POST("/login", s.loginPost)
	}
	router.GET("/logout", s.logoutHandler)
 if s.authProvider != nil {
  router.POST("/heartbeat", s.authMiddleware(), s.heartbeatHandler)
  s.monitorStop = make(chan struct{})
  go s.sessionMonitor()
 }

	authorized := router.Group("/")
	if s.authProvider != nil {
		authorized.Use(s.authMiddleware())
	}

	dashboardLinks := []server.DashboardLink{}
	for dashboardIdx := range s.dashboards {

		dashboard := s.dashboards[dashboardIdx]
		log.Info().Str("ident", dashboard.Ident).Msg("initializing dashboard")

		authorized.GET("/"+dashboard.Ident, func(c *gin.Context) {
			err := dashboard.Render(c.Writer)
			if err != nil {
				c.AbortWithError(400, err)
			}
		})
		dashboardLinks = append(dashboardLinks, server.DashboardLink{
			Name: dashboard.Title,
			Url:  "/" + dashboard.Ident,
		})

		for x := range dashboard.Variables {
			for y := range dashboard.Variables[x] {
				dashboard.Variables[x][y].Dashboard = dashboard

				variable := dashboard.Variables[x][y]
				authorized.GET("/"+dashboard.Ident+"/"+variable.Ident, func(c *gin.Context) {
					err := variable.RenderHistory(c.Writer)
					if err != nil {
						c.AbortWithError(400, err)
					}
				})
			}
		}

		router.POST("/"+dashboard.Ident, func(c *gin.Context) {
			dashboard.Update(c.Writer, c.Request)
		})
	}

	index := &server.Index{
		Links: dashboardLinks,
	}
	authorized.GET("/", func(c *gin.Context) {
		index.Render(c.Writer)
	})

	s.webserver = &http.Server{
		Addr:         config.Webserver.Address,
		Handler:      router,
		ReadTimeout:  time.Duration(config.Webserver.ReadTimeoutSeconds) * time.Second,
		WriteTimeout: time.Duration(config.Webserver.WriteTimeoutSeconds) * time.Second,
		IdleTimeout:  time.Duration(config.Webserver.IdleTimeoutSeconds) * time.Second,
	}

	if len(config.Webserver.TLS) > 0 {
		certByName := make(map[string]*tls.Certificate)
		s.webserver.TLSConfig = &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if cert, ok := certByName[hello.ServerName]; ok {
					return cert, nil
				}
				if cert, ok := certByName["*"]; ok {
					return cert, nil
				}
				return nil, errors.New("no certificate found for " + hello.ServerName)
			},
		}
		for i := range config.Webserver.TLS {
			webserverCertificate := workdir.Path(config.Webserver.TLS[i].Certificate)
			webserverPrivateKey := workdir.Path(config.Webserver.TLS[i].PrivateKey)
			if certificateBundle, err := certutil.Bundle(webserverCertificate, true); err == nil {
				webserverCertificate = certificateBundle
			} else {
				log.Warn().Err(err).Str("file", config.Webserver.TLS[i].Certificate).Str("key", config.Webserver.TLS[i].PrivateKey).Msg("failed to create certificate bundle")
			}
			if cert, err := tls.LoadX509KeyPair(webserverCertificate, webserverPrivateKey); err == nil {
				if config.Webserver.TLS[i].Domain != "" {
					certByName[config.Webserver.TLS[i].Domain] = &cert
				} else {
					certByName["*"] = &cert
				}
			} else {
				log.Warn().Err(err).Str("cert", config.Webserver.TLS[i].Certificate).Str("key", config.Webserver.TLS[i].PrivateKey).Msg("failed to load certificate and key")
			}
		}

		go func() {
			log.Info().Str("address", config.Webserver.Address).Msg("starting https webserver")
			if err := s.webserver.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Error().Err(err).Str("address", config.Webserver.Address).Msg("failed to start http webserver")
			}
		}()
	} else {
		go func() {
			log.Info().Str("address", config.Webserver.Address).Msg("starting http webserver")
			if err := s.webserver.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error().Err(err).Str("address", config.Webserver.Address).Msg("failed to start http webserver")
			}
		}()
	}

	log.Info().Str("name", "dashy").Msg("service started")
	return nil
}

// Monitor independently of requests so closed browsers are detected even without traffic.
func (s *Service) sessionMonitor() {
 ticker := time.NewTicker(15 * time.Second)
 defer ticker.Stop()
 for {
  select {
  case <-s.monitorStop: return
  case <-ticker.C: s.cleanupExpiredSessions()
  }
 }
}

func (s *Service) cleanupExpiredSessions() {
 now := time.Now()
 s.sessionMutex.Lock()
 defer s.sessionMutex.Unlock()
 for id, sess := range s.sessions {
  if !sess.expires.After(now) {
   audit("SESSION_EXPIRED", sess.username, sess.lastIP, sess.auditID, "session_timeout", sess.userAgent)
   delete(s.sessions, id)
   continue
  }
  if !sess.inactive && now.Sub(sess.lastHeartbeat) >= inactivityThreshold {
   sess.inactive = true
   audit("SESSION_INACTIVE", sess.username, sess.lastIP, sess.auditID, "heartbeat_missing_browser_or_network", sess.userAgent)
  }
 }
}

func (s *Service) heartbeatHandler(c *gin.Context) {
 cookie, err := c.Request.Cookie(sessionCookieName)
 if err != nil { c.Status(http.StatusUnauthorized); return }
 s.sessionMutex.Lock()
 if sess, ok := s.sessions[cookie.Value]; ok && sess.expires.After(time.Now()) {
  sess.lastHeartbeat = time.Now()
  sess.lastIP = peerIP(c)
  if sess.inactive { sess.inactive = false }
 }
 s.sessionMutex.Unlock()
 c.Status(http.StatusNoContent)
}

func (s *Service) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		s.cleanupExpiredSessions()
		cookie, err := c.Request.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
            audit("INVALID_SESSION", "", peerIP(c), "", "missing_session", c.Request.UserAgent())
			s.redirectToLogin(c)
			c.Abort()
			return
		}

		s.sessionMutex.Lock()
		session, ok := s.sessions[cookie.Value]
		if ok && session.expires.After(time.Now()) {
			session.expires = time.Now().Add(s.sessionTimeout)
            session.lastIP = peerIP(c)
			s.sessionMutex.Unlock()
			http.SetCookie(c.Writer, &http.Cookie{
				Name:     sessionCookieName,
				Value:    cookie.Value,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int(s.sessionTimeout.Seconds()),
			})
			return
		}
		s.sessionMutex.Unlock()

        audit("INVALID_SESSION", "", peerIP(c), "", "unknown_or_expired_session", c.Request.UserAgent())
		s.redirectToLogin(c)
		c.Abort()
	}
}

func (s *Service) redirectToLogin(c *gin.Context) {
	redirectTarget := c.Request.RequestURI
	if redirectTarget == "" {
		redirectTarget = "/"
	}
	c.Redirect(http.StatusSeeOther, "/login?redirect="+url.QueryEscape(redirectTarget))
}

func (s *Service) loginGet(c *gin.Context) {
	if s.isAuthenticated(c) {
		redirect := c.Query("redirect")
		if redirect == "" {
			redirect = "/"
		}
		c.Redirect(http.StatusSeeOther, localRedirect(redirect))
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	renderLoginPage(c.Writer, c.Query("error"), c.Query("redirect"))
}

func (s *Service) loginPost(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	redirect := c.PostForm("redirect")
	if redirect == "" {
		redirect = "/"
	}

	if username == "" || password == "" || !s.authProvider.IsValid(username, password) {
        audit("LOGIN_FAILED", username, peerIP(c), "", "invalid_credentials", c.Request.UserAgent())
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(http.StatusUnauthorized)
		renderLoginPage(c.Writer, "Invalid username or password", redirect)
		return
	}

	sessionID, err := newSessionID()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

    auditID, err := newSessionID()
    if err != nil { c.AbortWithStatus(http.StatusInternalServerError); return }
	s.sessionMutex.Lock()
	s.sessions[sessionID] = &session{
		username: username,
		expires:  time.Now().Add(s.sessionTimeout),
        lastHeartbeat: time.Now(), lastIP: peerIP(c), userAgent: c.Request.UserAgent(), auditID: auditID[:16],
	}
	s.sessionMutex.Unlock()
    audit("LOGIN_SUCCESS", username, peerIP(c), auditID[:16], "", c.Request.UserAgent())

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.sessionTimeout.Seconds()),
	})

	c.Redirect(http.StatusSeeOther, localRedirect(redirect))
}

func (s *Service) logoutHandler(c *gin.Context) {
	cookie, err := c.Request.Cookie(sessionCookieName)
	if err == nil && cookie.Value != "" {
		s.sessionMutex.Lock()
        if sess, exists := s.sessions[cookie.Value]; exists {
          audit("LOGOUT", sess.username, peerIP(c), sess.auditID, "manual", c.Request.UserAgent())
        }
		delete(s.sessions, cookie.Value)
		s.sessionMutex.Unlock()
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	redirectTarget := "/"
	if s.authProvider != nil {
		redirectTarget = "/login"
	}
	c.Redirect(http.StatusSeeOther, redirectTarget)
}

func (s *Service) isAuthenticated(c *gin.Context) bool {
	cookie, err := c.Request.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}

	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	if session, ok := s.sessions[cookie.Value]; ok && session.expires.After(time.Now()) {
		return true
	}

	return false
}

func renderLoginPage(w http.ResponseWriter, errorMessage string, redirect string) {
	if redirect == "" {
		redirect = "/"
	}

	messageBlock := ""
	if errorMessage != "" {
		messageBlock = fmt.Sprintf(`<div class="notification is-danger">%s</div>`, errorMessage)
	}

	fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login</title>
  <link rel="stylesheet" href="/bulma.css">
</head>
<body>
  <section class="section">
    <div class="container">
      <div class="column is-half is-offset-one-quarter">
        <h1 class="title">Dashy Login</h1>
        <p class="subtitle">Sign in to access your dashboards.</p>
        %s
        <form method="post" action="/login">
          <input type="hidden" name="redirect" value="%s">
          <div class="field">
            <label class="label">Username</label>
            <div class="control">
              <input class="input" type="text" name="username" required autofocus>
            </div>
          </div>
          <div class="field">
            <label class="label">Password</label>
            <div class="control">
              <input class="input" type="password" name="password" required>
            </div>
          </div>
          <div class="field">
            <div class="control">
              <button class="button is-primary" type="submit">Login</button>
            </div>
          </div>
        </form>
      </div>
    </div>
  </section>
</body>
</html>`, messageBlock, htmlEscape(redirect))
}

func htmlEscape(value string) string {
	return html.EscapeString(value)
}

func (s *Service) Stop() error {
	log.Info().Str("name", "dashy").Msg("stopping service")

    if s.monitorStop != nil { close(s.monitorStop); s.monitorStop = nil }
	// Shutdown Webserver
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.webserver.SetKeepAlivesEnabled(false)
	if err := s.webserver.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("graceful webserver shutdown failed")
	}

	log.Info().Str("name", "dashy").Msg("stopped service")
	return nil
}

func main() {
	servicekit.Wrap(servicekit.Config{
		Name:        "dashy",
		Version:     "2.5.0",
		Description: "Dashboard for Operational Values",
	}, new(Service))
}
