package sevsnp

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
)

const (
	amdKDSHost                      = "kdsintf.amd.com"
	defaultKDSMaxAttempts           = 4
	defaultKDSInitialBackoff        = 250 * time.Millisecond
	defaultKDSMaxBackoff            = 2 * time.Second
	defaultKDSAttemptTimeout        = 10 * time.Second
	defaultKDSMaxResponseSize int64 = 1 << 20
	defaultKDSCacheEntries          = 256
	defaultKDSCacheBytes      int64 = 32 << 20
	defaultKDSMaxInflight           = 64
)

var errKDSBusy = errors.New("too many AMD KDS fetches in flight")

var supportedProducts = map[string]struct{}{
	"Milan": {},
	"Genoa": {},
	"Turin": {},
}

type KDSGetterOptions struct {
	AllowedProducts []string
	MaxAttempts     int
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
	AttemptTimeout  time.Duration
	MaxResponseSize int64
	CacheDir        string
	CacheMaxEntries int
	CacheMaxBytes   int64
	// MaxInflight bounds the fetches running at once. A request that would
	// start one more fails instead.
	MaxInflight int
	Sleep       func(context.Context, time.Duration) error
	Now         func() time.Time

	// TestBaseURL only permits a local test server. It is never populated from runtime config.
	TestBaseURL string
}

type KDSGetter struct {
	client          *http.Client
	allowedProducts map[string]struct{}
	maxAttempts     int
	initialBackoff  time.Duration
	maxBackoff      time.Duration
	attemptTimeout  time.Duration
	maxResponseSize int64
	cacheDir        string
	cacheMaxEntries int
	cacheMaxBytes   int64
	maxInflight     int
	sleep           func(context.Context, time.Duration) error
	now             func() time.Time
	testBaseURL     *url.URL

	mu         sync.Mutex
	cache      map[string]kdsEntry
	cacheOrder []string
	cacheBytes int64
	inflight   map[string]*kdsCall
}

// kdsEntry is a cached KDS body. A CRL is served only before expires, its
// NextUpdate; other bodies have a zero expires and are always served.
type kdsEntry struct {
	body    []byte
	expires time.Time
}

func (entry kdsEntry) current(now time.Time) bool {
	return entry.expires.IsZero() || now.Before(entry.expires)
}

type kdsCall struct {
	done chan struct{}
	body []byte
	err  error
}

type kdsHTTPError struct {
	status     int
	retryAfter time.Duration
}

func (err *kdsHTTPError) Error() string { return fmt.Sprintf("AMD KDS returned HTTP %d", err.status) }

func NewKDSGetter(opts KDSGetterOptions) (*KDSGetter, error) {
	allowed, err := allowedProductSet(opts.AllowedProducts)
	if err != nil {
		return nil, err
	}
	opts = withKDSDefaults(opts)
	getter := &KDSGetter{
		client:          &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		allowedProducts: allowed,
		maxAttempts:     opts.MaxAttempts,
		initialBackoff:  opts.InitialBackoff,
		maxBackoff:      opts.MaxBackoff,
		attemptTimeout:  opts.AttemptTimeout,
		maxResponseSize: opts.MaxResponseSize,
		cacheDir:        opts.CacheDir,
		cacheMaxEntries: opts.CacheMaxEntries,
		cacheMaxBytes:   opts.CacheMaxBytes,
		maxInflight:     opts.MaxInflight,
		sleep:           opts.Sleep,
		now:             opts.Now,
		cache:           make(map[string]kdsEntry),
		inflight:        make(map[string]*kdsCall),
	}
	if opts.TestBaseURL != "" {
		base, err := url.Parse(opts.TestBaseURL)
		if err != nil || base.Scheme != "http" || base.Host == "" || base.User != nil || base.Fragment != "" {
			return nil, errors.New("test KDS base URL is invalid")
		}
		getter.testBaseURL = base
	}
	if getter.cacheDir != "" {
		if err := os.MkdirAll(getter.cacheDir, 0o700); err != nil {
			return nil, fmt.Errorf("create AMD KDS cache directory: %w", err)
		}
	}
	return getter, nil
}

func allowedProductSet(products []string) (map[string]struct{}, error) {
	allowed := make(map[string]struct{}, len(supportedProducts))
	if len(products) == 0 {
		for product := range supportedProducts {
			allowed[product] = struct{}{}
		}
	} else {
		for _, product := range products {
			if _, ok := supportedProducts[product]; !ok {
				return nil, fmt.Errorf("unsupported AMD product %q", product)
			}
			allowed[product] = struct{}{}
		}
	}
	return allowed, nil
}

func withKDSDefaults(opts KDSGetterOptions) KDSGetterOptions {
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = defaultKDSMaxAttempts
	}
	if opts.InitialBackoff <= 0 {
		opts.InitialBackoff = defaultKDSInitialBackoff
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = defaultKDSMaxBackoff
	}
	if opts.AttemptTimeout <= 0 {
		opts.AttemptTimeout = defaultKDSAttemptTimeout
	}
	if opts.MaxResponseSize <= 0 {
		opts.MaxResponseSize = defaultKDSMaxResponseSize
	}
	if opts.CacheMaxEntries <= 0 {
		opts.CacheMaxEntries = defaultKDSCacheEntries
	}
	if opts.CacheMaxBytes <= 0 {
		opts.CacheMaxBytes = defaultKDSCacheBytes
	}
	if opts.MaxInflight <= 0 {
		opts.MaxInflight = defaultKDSMaxInflight
	}
	if opts.Sleep == nil {
		opts.Sleep = sleepContext
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return opts
}

func (getter *KDSGetter) Get(rawURL string) ([]byte, error) {
	return getter.GetContext(context.Background(), rawURL)
}

// GetContext returns the AMD KDS resource at rawURL from the cache, or fetches
// it. The fetch runs detached from ctx and fills the cache even when ctx ends
// first; its duration is bounded by the retry settings alone. Callers asking
// for a resource already being fetched share that fetch.
func (getter *KDSGetter) GetContext(ctx context.Context, rawURL string) ([]byte, error) {
	if getter == nil {
		return nil, errors.New("AMD KDS getter is nil")
	}
	key, requestURL, err := getter.canonicalURL(rawURL)
	if err != nil {
		return nil, err
	}
	getter.mu.Lock()
	if entry, ok := getter.cache[key]; ok && entry.current(getter.now()) {
		getter.mu.Unlock()
		return cloneBytes(entry.body), nil
	}
	call, ok := getter.inflight[key]
	if !ok {
		if len(getter.inflight) >= getter.maxInflight {
			getter.mu.Unlock()
			return nil, errKDSBusy
		}
		call = &kdsCall{done: make(chan struct{})}
		getter.inflight[key] = call
		go getter.load(key, requestURL, call)
	}
	getter.mu.Unlock()
	select {
	case <-call.done:
		return cloneBytes(call.body), call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// load reads key from the disk cache or fetches it, stores the result in the
// memory cache, and completes call.
func (getter *KDSGetter) load(key, requestURL string, call *kdsCall) {
	entry, err := getter.readPersistent(key)
	if err != nil {
		entry, err = getter.fetch(key, requestURL)
	}
	getter.mu.Lock()
	defer getter.mu.Unlock()
	if err == nil {
		getter.storeMemory(key, entry)
		call.body = entry.body
	}
	call.err = err
	delete(getter.inflight, key)
	close(call.done)
}

func (getter *KDSGetter) canonicalURL(rawURL string) (string, string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", "", fmt.Errorf("parse AMD KDS URL: %w", err)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return "", "", errors.New("AMD KDS URL must not contain userinfo or fragment")
	}
	if getter.testBaseURL == nil && (parsed.Scheme != "https" || parsed.Hostname() != amdKDSHost || (parsed.Port() != "" && parsed.Port() != "443")) {
		return "", "", errors.New("AMD KDS URL is not an allowed HTTPS endpoint")
	}
	var canonical string
	if certificate, err := kds.ParseVCEKCertURL(rawURL); err == nil {
		if _, ok := getter.allowedProducts[certificate.ProductLine]; !ok {
			return "", "", errors.New("AMD KDS product is not allowed")
		}
		canonical = kds.VCEKCertURL(certificate.ProductLine, certificate.HWID, kds.TCBVersion(certificate.TCB))
	} else if product, ok := getter.crlProduct(rawURL); ok {
		canonical = kds.CrlLinkByKey(product, abi.VcekReportSigner)
	} else {
		product, function, parseErr := kds.ParseProductCertChainURL(rawURL)
		if parseErr != nil || function != kds.VcekCertFunction {
			return "", "", errors.New("AMD KDS URL path is not allowed")
		}
		if _, ok := getter.allowedProducts[product]; !ok {
			return "", "", errors.New("AMD KDS product is not allowed")
		}
		canonical = kds.ProductCertChainURL(abi.VcekReportSigner, product)
	}
	if getter.testBaseURL != nil {
		remote, err := url.Parse(canonical)
		if err != nil {
			return "", "", err
		}
		canonicalURL := *getter.testBaseURL
		canonicalURL.Path = remote.Path
		canonicalURL.RawQuery = remote.RawQuery
		return canonical, canonicalURL.String(), nil
	}
	return canonical, canonical, nil
}

func (getter *KDSGetter) crlProduct(rawURL string) (string, bool) {
	for product := range getter.allowedProducts {
		if rawURL == kds.CrlLinkByKey(product, abi.VcekReportSigner) {
			return product, true
		}
	}
	return "", false
}

func (getter *KDSGetter) fetch(cacheURL, endpoint string) (kdsEntry, error) {
	ctx := context.Background()
	var lastErr error
	for attempt := 0; attempt < getter.maxAttempts; attempt++ {
		body, err := getter.fetchOnce(ctx, endpoint)
		if err == nil {
			var expires time.Time
			if expires, err = validateKDSBody(cacheURL, body, getter.now()); err == nil {
				_ = getter.writePersistent(cacheURL, body)
				return kdsEntry{body: body, expires: expires}, nil
			}
		}
		lastErr = err
		if !retryableKDSError(err) || attempt+1 == getter.maxAttempts {
			break
		}
		delay := getter.backoff(attempt)
		var httpErr *kdsHTTPError
		if errors.As(err, &httpErr) && httpErr.retryAfter > delay {
			delay = httpErr.retryAfter
		}
		if delay > 10*time.Second {
			delay = 10 * time.Second
		}
		if err := getter.sleep(ctx, delay); err != nil {
			return kdsEntry{}, fmt.Errorf("wait to retry AMD KDS request: %w", err)
		}
	}
	return kdsEntry{}, fmt.Errorf("fetch AMD KDS resource: %w", lastErr)
}

func (getter *KDSGetter) fetchOnce(ctx context.Context, endpoint string) ([]byte, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, getter.attemptTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(attemptCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := getter.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &kdsHTTPError{status: resp.StatusCode, retryAfter: retryAfter(resp.Header.Get("Retry-After"), time.Now())}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, getter.maxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > getter.maxResponseSize {
		return nil, fmt.Errorf("AMD KDS response exceeds %d bytes", getter.maxResponseSize)
	}
	return body, nil
}

func (getter *KDSGetter) storeMemory(key string, entry kdsEntry) {
	if existing, ok := getter.cache[key]; ok {
		getter.cacheBytes -= int64(len(existing.body))
	} else {
		getter.cacheOrder = append(getter.cacheOrder, key)
	}
	getter.cache[key] = kdsEntry{body: cloneBytes(entry.body), expires: entry.expires}
	getter.cacheBytes += int64(len(entry.body))
	for len(getter.cacheOrder) > getter.cacheMaxEntries || getter.cacheBytes > getter.cacheMaxBytes {
		oldest := getter.cacheOrder[0]
		getter.cacheOrder = getter.cacheOrder[1:]
		getter.cacheBytes -= int64(len(getter.cache[oldest].body))
		delete(getter.cache, oldest)
	}
}

func (getter *KDSGetter) cachePath(key string) string {
	return filepath.Join(getter.cacheDir, cacheKey(key)+".cache")
}

func cacheKey(key string) string { sum := sha256.Sum256([]byte(key)); return fmt.Sprintf("%x", sum[:]) }

// readPersistent loads and validates a disk cache entry, and removes an entry
// that is invalid or a CRL that is no longer current. The key doubles as the
// endpoint descriptor used to pick the correct body format for validation.
func (getter *KDSGetter) readPersistent(key string) (kdsEntry, error) {
	if getter.cacheDir == "" {
		return kdsEntry{}, os.ErrNotExist
	}
	body, err := os.ReadFile(getter.cachePath(key))
	if err != nil {
		return kdsEntry{}, err
	}
	if int64(len(body)) > getter.maxResponseSize {
		_ = os.Remove(getter.cachePath(key))
		return kdsEntry{}, errors.New("AMD KDS disk cache entry is too large")
	}
	expires, err := validateKDSBody(key, body, getter.now())
	if err != nil {
		_ = os.Remove(getter.cachePath(key))
		return kdsEntry{}, fmt.Errorf("AMD KDS disk cache entry: %w", err)
	}
	return kdsEntry{body: body, expires: expires}, nil
}

func (getter *KDSGetter) writePersistent(key string, body []byte) error {
	if getter.cacheDir == "" {
		return nil
	}
	if int64(len(body)) > getter.maxResponseSize {
		return errors.New("AMD KDS cache body is too large")
	}
	entries, err := os.ReadDir(getter.cacheDir)
	if err != nil {
		return err
	}
	type entry struct {
		path string
		info os.FileInfo
	}
	var files []entry
	var total int64
	for _, candidate := range entries {
		info, infoErr := candidate.Info()
		if infoErr != nil || !info.Mode().IsRegular() {
			continue
		}
		files = append(files, entry{filepath.Join(getter.cacheDir, candidate.Name()), info})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].info.ModTime().Before(files[j].info.ModTime()) })
	for (len(files) >= getter.cacheMaxEntries || total+int64(len(body)) > getter.cacheMaxBytes) && len(files) > 0 {
		_ = os.Remove(files[0].path)
		total -= files[0].info.Size()
		files = files[1:]
	}
	if total+int64(len(body)) > getter.cacheMaxBytes {
		return errors.New("AMD KDS cache capacity is too small")
	}
	temporary, err := os.CreateTemp(getter.cacheDir, ".tmp-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, getter.cachePath(key))
}

// validateKDSBody checks that body parses as the resource endpoint names. A
// CRL must also be current at now; its NextUpdate is returned as the time the
// body stops being servable. Other bodies return a zero time.
func validateKDSBody(endpoint string, body []byte, now time.Time) (time.Time, error) {
	if _, err := kds.ParseVCEKCertURL(endpoint); err == nil {
		if _, err := x509.ParseCertificate(body); err != nil {
			return time.Time{}, fmt.Errorf("parse AMD KDS VCEK: %w", err)
		}
		return time.Time{}, nil
	}
	if strings.HasSuffix(endpoint, "/crl") {
		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse AMD KDS CRL: %w", err)
		}
		if now.Before(crl.ThisUpdate) || !now.Before(crl.NextUpdate) {
			return time.Time{}, fmt.Errorf("AMD KDS CRL is not current: valid from %s until %s", crl.ThisUpdate.UTC().Format(time.RFC3339), crl.NextUpdate.UTC().Format(time.RFC3339))
		}
		return crl.NextUpdate, nil
	}
	ask, ark, err := kds.ParseProductCertChain(body)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse AMD KDS product chain: %w", err)
	}
	if _, err := x509.ParseCertificate(ask); err != nil {
		return time.Time{}, fmt.Errorf("parse AMD KDS ASK: %w", err)
	}
	if _, err := x509.ParseCertificate(ark); err != nil {
		return time.Time{}, fmt.Errorf("parse AMD KDS ARK: %w", err)
	}
	return time.Time{}, nil
}

func (getter *KDSGetter) backoff(attempt int) time.Duration {
	delay := getter.initialBackoff
	for range attempt {
		if delay >= getter.maxBackoff/2 {
			return getter.maxBackoff
		}
		delay *= 2
	}
	if delay > getter.maxBackoff {
		return getter.maxBackoff
	}
	return delay
}

func retryableKDSError(err error) bool {
	var httpErr *kdsHTTPError
	if errors.As(err, &httpErr) {
		return httpErr.status == http.StatusTooManyRequests || httpErr.status >= http.StatusInternalServerError
	}
	return true
}

func retryAfter(value string, now time.Time) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
		return 0
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	return when.Sub(now)
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func cloneBytes(value []byte) []byte { return append([]byte(nil), value...) }
