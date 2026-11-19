package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed panel.html
var panelAssets embed.FS

type metricKey struct{}
type tunnelStats struct {
	active, carriers, sent, received atomic.Int64
	mu                               sync.Mutex
	logs                             []string
}

func statsFrom(ctx context.Context) *tunnelStats {
	m, _ := ctx.Value(metricKey{}).(*tunnelStats)
	return m
}
func carrierDelta(ctx context.Context, n int64) {
	if m := statsFrom(ctx); m != nil {
		m.carriers.Add(n)
	}
}
func event(ctx context.Context, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if m := statsFrom(ctx); m != nil {
		m.mu.Lock()
		if len(m.logs) >= 120 {
			copy(m.logs, m.logs[1:])
			m.logs = m.logs[:119]
		}
		m.logs = append(m.logs, time.Now().UTC().Format(time.RFC3339)+" "+message)
		m.mu.Unlock()
	} else {
		log.Print(message)
	}
}

type measuredWriter struct {
	io.Writer
	count *atomic.Int64
}

func (w measuredWriter) Write(p []byte) (int, error) {
	n, e := w.Writer.Write(p)
	w.count.Add(int64(n))
	return n, e
}
func copyMeasured(dst io.Writer, src io.Reader, m *tunnelStats, sent bool) (int64, error) {
	if m == nil {
		return io.Copy(dst, src)
	}
	counter := &m.received
	if sent {
		counter = &m.sent
	}
	return io.Copy(measuredWriter{dst, counter}, src)
}

type tunnelConfig struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Mode      string `json:"mode"`
	Tunnel    string `json:"tunnel"`
	Local     string `json:"local"`
	TokenFile string `json:"token_file"`
	CertFile  string `json:"cert_file"`
	KeyFile   string `json:"key_file"`
	CAFile    string `json:"ca_file"`
	TLSName   string `json:"tls_name"`
	Carriers  int    `json:"carriers"`
	Streams   int    `json:"streams"`
	Enabled   bool   `json:"enabled"`
}

func (c tunnelConfig) args() []string {
	a := []string{c.Mode, "-tunnel", c.Tunnel, "-token-file", c.TokenFile, "-carriers", strconv.Itoa(c.Carriers), "-streams", strconv.Itoa(c.Streams)}
	if c.Mode == "server" {
		return append(a, "-listen", c.Local, "-cert", c.CertFile, "-key", c.KeyFile)
	}
	a = append(a, "-target", c.Local, "-ca", c.CAFile)
	if c.TLSName != "" {
		a = append(a, "-tls-name", c.TLSName)
	}
	return a
}
func (c tunnelConfig) validate() error {
	if len(c.Name) < 1 || len(c.Name) > 80 || (c.Mode != "server" && c.Mode != "agent") {
		return errors.New("نام یا نقش تانل معتبر نیست")
	}
	if c.Carriers < 1 || c.Carriers > maxCarriers || c.Streams < 1 || c.Streams > maxStreams {
		return errors.New("تعداد اتصال‌ها باید ۱ تا ۳۲۰ و جریان‌ها ۱ تا ۱۲۸ باشد")
	}
	for _, a := range []string{c.Tunnel, c.Local} {
		_, p, e := net.SplitHostPort(a)
		n, e2 := strconv.Atoi(p)
		if e != nil || e2 != nil || n < 1 || n > 65535 {
			return errors.New("آدرس‌ها باید به شکل host:port و با پورت معتبر باشند")
		}
	}
	paths := []string{c.TokenFile}
	if c.Mode == "server" {
		paths = append(paths, c.CertFile, c.KeyFile)
	} else {
		paths = append(paths, c.CAFile)
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			return errors.New("مسیر فایل‌های توکن و گواهی باید کامل باشد")
		}
		info, e := os.Stat(p)
		if e != nil || !info.Mode().IsRegular() {
			return errors.New("فایل توکن یا گواهی پیدا نشد")
		}
	}
	return nil
}

type managedTunnel struct {
	config    tunnelConfig
	stats     *tunnelStats
	cancel    context.CancelFunc
	done      chan struct{}
	running   bool
	lastError string
}
type loginSession struct {
	expires time.Time
	csrf    string
}
type loginAttempt struct {
	count int
	since time.Time
}
type panel struct {
	actionMu sync.Mutex
	mu       sync.Mutex
	ctx      context.Context
	path     string
	tunnels  map[string]*managedTunnel
	sessions map[string]loginSession
	attempts map[string]loginAttempt
	password [32]byte
	secure   bool
	started  time.Time
}

func randomID() string {
	var b [24]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func newPanel(ctx context.Context, path, password string, secure bool) (*panel, error) {
	p := &panel{ctx: ctx, path: path, password: sha256.Sum256([]byte(password)), secure: secure, started: time.Now(), tunnels: map[string]*managedTunnel{}, sessions: map[string]loginSession{}, attempts: map[string]loginAttempt{}}
	data, e := os.ReadFile(path)
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	if e == nil {
		var configs []tunnelConfig
		if e = json.Unmarshal(data, &configs); e != nil {
			return nil, e
		}
		if len(configs) > 64 {
			return nil, errors.New("too many tunnels")
		}
		for _, c := range configs {
			if c.ID == "" || p.tunnels[c.ID] != nil {
				return nil, errors.New("invalid or duplicate tunnel id")
			}
			p.tunnels[c.ID] = &managedTunnel{config: c, stats: &tunnelStats{}}
		}
	}
	return p, nil
}
func (p *panel) saveLocked() error {
	configs := make([]tunnelConfig, 0, len(p.tunnels))
	for _, t := range p.tunnels {
		configs = append(configs, t.config)
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].ID < configs[j].ID })
	data, e := json.MarshalIndent(configs, "", "  ")
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(p.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(p.path), ".panel-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, p.path)
}

// p.mu must be held. A tunnel cannot restart until all carrier workers have exited.
func (p *panel) startLocked(t *managedTunnel) {
	if t.running {
		return
	}
	ctx, cancel := context.WithCancel(p.ctx)
	t.cancel = cancel
	t.done = make(chan struct{})
	t.running = true
	t.lastError = ""
	t.stats = &tunnelStats{}
	args := t.config.args()
	stats := t.stats
	go func() {
		err := run(context.WithValue(ctx, metricKey{}, stats), args)
		p.mu.Lock()
		defer p.mu.Unlock()
		t.running = false
		t.cancel = nil
		if err != nil {
			t.lastError = err.Error()
			event(context.WithValue(ctx, metricKey{}, stats), "stopped: %v", err)
		}
		close(t.done)
	}()
}
func (p *panel) stop(id string) error {
	p.mu.Lock()
	t := p.tunnels[id]
	if t == nil {
		p.mu.Unlock()
		return errors.New("تانل پیدا نشد")
	}
	done := t.done
	if t.cancel != nil {
		t.cancel()
	}
	p.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			return errors.New("توقف هنوز کامل نشده است؛ دوباره بررسی کنید")
		}
	}
	return nil
}
func jsonResponse(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
func decodeBody(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return errors.New("invalid trailing data")
	}
	return nil
}
func (p *panel) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.URL.Path == "/" && r.Method == "GET" {
			b, _ := panelAssets.ReadFile("panel.html")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(b)
			return
		}
		if r.URL.Path == "/api/login" && r.Method == "POST" {
			p.login(w, r)
			return
		}
		cookie, e := r.Cookie("pt_session")
		if e != nil {
			jsonResponse(w, 401, map[string]string{"error": "ورود لازم است"})
			return
		}
		p.mu.Lock()
		session, ok := p.sessions[cookie.Value]
		if ok && time.Now().After(session.expires) {
			delete(p.sessions, cookie.Value)
			ok = false
		}
		p.mu.Unlock()
		if !ok {
			jsonResponse(w, 401, map[string]string{"error": "نشست منقضی شده است"})
			return
		}
		if r.Method != "GET" && (subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(session.csrf)) != 1 || !sameOrigin(r)) {
			jsonResponse(w, 403, map[string]string{"error": "درخواست نامعتبر است"})
			return
		}
		switch {
		case r.URL.Path == "/api/session" && r.Method == "GET":
			jsonResponse(w, 200, map[string]string{"csrf": session.csrf})
		case r.URL.Path == "/api/logout" && r.Method == "POST":
			p.mu.Lock()
			delete(p.sessions, cookie.Value)
			p.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "pt_session", Value: "", Path: "/", HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
			jsonResponse(w, 200, map[string]bool{"ok": true})
		case r.URL.Path == "/api/status" && r.Method == "GET":
			p.status(w)
		case r.URL.Path == "/api/config" && r.Method == "POST":
			p.putConfig(w, r)
		case r.URL.Path == "/api/action" && r.Method == "POST":
			p.action(w, r)
		case r.URL.Path == "/api/backup" && r.Method == "GET":
			p.mu.Lock()
			configs := []tunnelConfig{}
			for _, t := range p.tunnels {
				configs = append(configs, t.config)
			}
			p.mu.Unlock()
			w.Header().Set("Content-Disposition", `attachment; filename="parallel-tunnel-config.json"`)
			jsonResponse(w, 200, configs)
		default:
			jsonResponse(w, 404, map[string]string{"error": "مسیر پیدا نشد"})
		}
	})
}
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return origin == "" || origin == scheme+"://"+r.Host
}
func (p *panel) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		jsonResponse(w, 403, map[string]string{"error": "درخواست نامعتبر"})
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now()
	p.mu.Lock()
	for k, a := range p.attempts {
		if now.Sub(a.since) > 15*time.Minute {
			delete(p.attempts, k)
		}
	}
	a := p.attempts[host]
	if a.since.IsZero() {
		a.since = now
	}
	if a.count >= 5 || len(p.attempts) > 4096 {
		p.mu.Unlock()
		jsonResponse(w, 429, map[string]string{"error": "تلاش زیاد؛ ۱۵ دقیقه بعد امتحان کنید"})
		return
	}
	a.count++
	p.attempts[host] = a
	p.mu.Unlock()
	var input struct {
		Password string `json:"password"`
	}
	if decodeBody(w, r, &input) != nil {
		jsonResponse(w, 400, map[string]string{"error": "درخواست نامعتبر"})
		return
	}
	sum := sha256.Sum256([]byte(input.Password))
	if subtle.ConstantTimeCompare(sum[:], p.password[:]) != 1 {
		jsonResponse(w, 401, map[string]string{"error": "رمز نادرست است"})
		return
	}
	id, csrf := randomID(), randomID()
	p.mu.Lock()
	for k, s := range p.sessions {
		if now.After(s.expires) {
			delete(p.sessions, k)
		}
	}
	if len(p.sessions) >= 32 {
		p.mu.Unlock()
		jsonResponse(w, 429, map[string]string{"error": "تعداد نشست‌ها زیاد است"})
		return
	}
	delete(p.attempts, host)
	p.sessions[id] = loginSession{now.Add(8 * time.Hour), csrf}
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "pt_session", Value: id, Path: "/", HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
	jsonResponse(w, 200, map[string]string{"csrf": csrf})
}
func (p *panel) status(w http.ResponseWriter) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rows := []any{}
	ids := make([]string, 0, len(p.tunnels))
	for id := range p.tunnels {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t := p.tunnels[id]
		t.stats.mu.Lock()
		logs := append([]string{}, t.stats.logs...)
		t.stats.mu.Unlock()
		rows = append(rows, map[string]any{"config": t.config, "running": t.running, "error": t.lastError, "active": t.stats.active.Load(), "carriers": t.stats.carriers.Load(), "sent": t.stats.sent.Load(), "received": t.stats.received.Load(), "logs": logs})
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	jsonResponse(w, 200, map[string]any{"tunnels": rows, "uptime": int(time.Since(p.started).Seconds()), "process_memory": memory.Sys, "heap": memory.HeapAlloc, "goroutines": runtime.NumGoroutine(), "cpus": runtime.NumCPU()})
}
func (p *panel) putConfig(w http.ResponseWriter, r *http.Request) {
	p.actionMu.Lock()
	defer p.actionMu.Unlock()
	var c tunnelConfig
	if e := decodeBody(w, r, &c); e != nil {
		jsonResponse(w, 400, map[string]string{"error": "تنظیمات معتبر نیست"})
		return
	}
	if e := c.validate(); e != nil {
		jsonResponse(w, 400, map[string]string{"error": e.Error()})
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var previous tunnelConfig
	existing := p.tunnels[c.ID]
	if c.ID != "" && existing == nil {
		jsonResponse(w, 404, map[string]string{"error": "تانل پیدا نشد"})
		return
	}
	if existing != nil && existing.running {
		jsonResponse(w, 409, map[string]string{"error": "پیش از ویرایش، تانل را متوقف کنید"})
		return
	}
	if existing == nil {
		if len(p.tunnels) >= 64 {
			jsonResponse(w, 400, map[string]string{"error": "سقف ۶۴ تانل"})
			return
		}
		c.ID = randomID()
		existing = &managedTunnel{stats: &tunnelStats{}}
	} else {
		previous = existing.config
	}
	existing.config = c
	p.tunnels[c.ID] = existing
	if e := p.saveLocked(); e != nil {
		if previous.ID == "" {
			delete(p.tunnels, c.ID)
		} else {
			existing.config = previous
		}
		jsonResponse(w, 500, map[string]string{"error": "ذخیره تنظیمات ناموفق بود"})
		return
	}
	if c.Enabled {
		p.startLocked(existing)
	}
	jsonResponse(w, 200, map[string]string{"id": c.ID})
}
func (p *panel) action(w http.ResponseWriter, r *http.Request) {
	p.actionMu.Lock()
	defer p.actionMu.Unlock()
	var input struct {
		ID     string `json:"id"`
		Action string `json:"action"`
	}
	if decodeBody(w, r, &input) != nil {
		jsonResponse(w, 400, map[string]string{"error": "درخواست نامعتبر"})
		return
	}
	if input.Action != "start" && input.Action != "stop" && input.Action != "delete" {
		jsonResponse(w, 400, map[string]string{"error": "عملیات نامعتبر"})
		return
	}
	// Persist enabled state before changing the running process.
	p.mu.Lock()
	t := p.tunnels[input.ID]
	if t == nil {
		p.mu.Unlock()
		jsonResponse(w, 404, map[string]string{"error": "تانل پیدا نشد"})
		return
	}
	old := t.config.Enabled
	t.config.Enabled = input.Action == "start"
	if e := p.saveLocked(); e != nil {
		t.config.Enabled = old
		p.mu.Unlock()
		jsonResponse(w, 500, map[string]string{"error": "ذخیره ناموفق"})
		return
	}
	if input.Action == "start" {
		if e := t.config.validate(); e != nil {
			t.config.Enabled = old
			p.saveLocked()
			p.mu.Unlock()
			jsonResponse(w, 400, map[string]string{"error": e.Error()})
			return
		}
		p.startLocked(t)
		p.mu.Unlock()
		jsonResponse(w, 200, map[string]bool{"ok": true})
		return
	}
	p.mu.Unlock()
	if e := p.stop(input.ID); e != nil {
		jsonResponse(w, 409, map[string]string{"error": e.Error()})
		return
	}
	if input.Action == "delete" {
		p.mu.Lock()
		if t.running {
			p.mu.Unlock()
			jsonResponse(w, 409, map[string]string{"error": "تانل در حال اجراست"})
			return
		}
		delete(p.tunnels, input.ID)
		if e := p.saveLocked(); e != nil {
			p.tunnels[input.ID] = t
			p.mu.Unlock()
			jsonResponse(w, 500, map[string]string{"error": "حذف ذخیره نشد"})
			return
		}
		p.mu.Unlock()
	}
	jsonResponse(w, 200, map[string]bool{"ok": true})
}
func runPanel(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("panel", flag.ContinueOnError)
	addr := f.String("listen", "127.0.0.1:9090", "panel address; use SSH forwarding by default")
	path := f.String("config", "/etc/parallel-tunnel/panel.json", "configuration file")
	passwordFile := f.String("password-file", "", "file containing a password of at least 16 characters")
	cert := f.String("cert", "", "panel HTTPS certificate")
	key := f.String("key", "", "panel HTTPS private key")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	host, _, e := net.SplitHostPort(*addr)
	if e != nil {
		return e
	}
	ip := net.ParseIP(host)
	secure := *cert != "" && *key != ""
	if (ip == nil || !ip.IsLoopback()) && !secure {
		return errors.New("non-loopback panel requires HTTPS -cert and -key")
	}
	if (*cert == "") != (*key == "") {
		return errors.New("provide both panel certificate and key")
	}
	secret, e := os.ReadFile(*passwordFile)
	if e != nil {
		return e
	}
	password := strings.TrimSpace(string(secret))
	if len(password) < 16 {
		return errors.New("panel password must contain at least 16 characters")
	}
	p, e := newPanel(ctx, *path, password, secure)
	if e != nil {
		return e
	}
	p.mu.Lock()
	for _, t := range p.tunnels {
		if t.config.Enabled {
			if e := t.config.validate(); e != nil {
				t.lastError = e.Error()
			} else {
				p.startLocked(t)
			}
		}
	}
	p.mu.Unlock()
	server := &http.Server{Addr: *addr, Handler: p.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.Shutdown(shutdownCtx)
		case <-done:
		}
	}()
	log.Printf("panel listening on %s", *addr)
	if secure {
		e = server.ListenAndServeTLS(*cert, *key)
	} else {
		e = server.ListenAndServe()
	}
	close(done)
	p.mu.Lock()
	ids := []string{}
	for id := range p.tunnels {
		ids = append(ids, id)
	}
	p.mu.Unlock()
	for _, id := range ids {
		p.stop(id)
	}
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
