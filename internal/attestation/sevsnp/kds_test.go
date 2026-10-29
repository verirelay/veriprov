package sevsnp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	guesttesting "github.com/google/go-sev-guest/testing"
)

func TestNewKDSGetterValidation(t *testing.T) {
	t.Run("defaults allowed products", func(t *testing.T) {
		getter, err := NewKDSGetter(KDSGetterOptions{})
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]struct{}{"Milan": {}, "Genoa": {}, "Turin": {}}
		if !reflect.DeepEqual(getter.allowedProducts, want) {
			t.Fatalf("allowedProducts = %v, want %v", getter.allowedProducts, want)
		}
	})

	t.Run("unsupported product", func(t *testing.T) {
		_, err := NewKDSGetter(KDSGetterOptions{AllowedProducts: []string{"Milan", "Rome"}})
		if err == nil || err.Error() != `unsupported AMD product "Rome"` {
			t.Fatalf("NewKDSGetter() error = %v, want unsupported AMD product %q", err, "Rome")
		}
	})

	for _, testURL := range []string{"https://127.0.0.1", "http://", "http://u@127.0.0.1", "http://127.0.0.1#f", "://bad"} {
		t.Run("invalid TestBaseURL "+testURL, func(t *testing.T) {
			_, err := NewKDSGetter(KDSGetterOptions{TestBaseURL: testURL})
			if err == nil || err.Error() != "test KDS base URL is invalid" {
				t.Fatalf("NewKDSGetter() error = %v, want %q", err, "test KDS base URL is invalid")
			}
		})
	}

	t.Run("cache directory creation error", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(file, []byte("file"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := NewKDSGetter(KDSGetterOptions{CacheDir: filepath.Join(file, "sub")})
		if err == nil || !strings.HasPrefix(err.Error(), "create AMD KDS cache directory: ") {
			t.Fatalf("NewKDSGetter() error = %v, want cache directory creation error", err)
		}
	})

	t.Run("unsupported product precedes invalid TestBaseURL", func(t *testing.T) {
		_, err := NewKDSGetter(KDSGetterOptions{AllowedProducts: []string{"Rome"}, TestBaseURL: "https://127.0.0.1"})
		if err == nil || err.Error() != `unsupported AMD product "Rome"` {
			t.Fatalf("NewKDSGetter() error = %v, want unsupported AMD product %q", err, "Rome")
		}
	})

	t.Run("invalid TestBaseURL precedes cache directory creation", func(t *testing.T) {
		cacheDir := filepath.Join(t.TempDir(), "cache")
		_, err := NewKDSGetter(KDSGetterOptions{TestBaseURL: "https://127.0.0.1", CacheDir: cacheDir})
		if err == nil || err.Error() != "test KDS base URL is invalid" {
			t.Fatalf("NewKDSGetter() error = %v, want %q", err, "test KDS base URL is invalid")
		}
		if _, err := os.Stat(cacheDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cache directory stat error = %v, want os.ErrNotExist", err)
		}
	})
}

func TestNewKDSGetterDefaults(t *testing.T) {
	getter, err := NewKDSGetter(KDSGetterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if getter.maxAttempts != defaultKDSMaxAttempts ||
		getter.initialBackoff != defaultKDSInitialBackoff ||
		getter.maxBackoff != defaultKDSMaxBackoff ||
		getter.attemptTimeout != defaultKDSAttemptTimeout ||
		getter.maxResponseSize != defaultKDSMaxResponseSize ||
		getter.cacheMaxEntries != defaultKDSCacheEntries ||
		getter.cacheMaxBytes != defaultKDSCacheBytes ||
		getter.maxInflight != defaultKDSMaxInflight {
		t.Fatalf("getter defaults = %+v", getter)
	}
	if getter.sleep == nil {
		t.Fatal("getter.sleep is nil")
	}
	if getter.client == nil || getter.client.CheckRedirect == nil {
		t.Fatal("getter.client or getter.client.CheckRedirect is nil")
	}
}

type kdsTestServer struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests int
}

func (server *kdsTestServer) count() int {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.requests
}

func newKDSGetterForTest(t *testing.T, handler http.HandlerFunc, options KDSGetterOptions) (*KDSGetter, *kdsTestServer) {
	t.Helper()
	recorder := &kdsTestServer{}
	recorder.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder.mu.Lock()
		recorder.requests++
		recorder.mu.Unlock()
		handler(writer, request)
	}))
	t.Cleanup(recorder.server.Close)
	if len(options.AllowedProducts) == 0 {
		options.AllowedProducts = []string{"Milan"}
	}
	options.TestBaseURL = recorder.server.URL
	if options.Sleep == nil {
		options.Sleep = func(context.Context, time.Duration) error { return nil }
	}
	getter, err := NewKDSGetter(options)
	if err != nil {
		t.Fatal(err)
	}
	return getter, recorder
}

func testKDSURL() string {
	return kds.VCEKCertURL("Milan", bytes.Repeat([]byte{1}, abi.ChipIDSize), 0)
}

func testKDSBody(t *testing.T) []byte {
	t.Helper()
	signer, err := guesttesting.DefaultTestOnlyCertChain("Milan-B0", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	fake, err := guesttesting.FakeKDSFromSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	body, err := fake.Get(kds.VCEKCertURL("Milan", signer.HWID[:], signer.TCB))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestKDSCanonicalURLRejectsUntrustedEndpoints(t *testing.T) {
	getter, server := newKDSGetterForTest(t, func(http.ResponseWriter, *http.Request) {}, KDSGetterOptions{})
	valid := testKDSURL()
	cases := []string{
		"http://kdsintf.amd.com/vcek/v1/Milan/cert_chain",
		"https://evil.example/vcek/v1/Milan/cert_chain",
		"https://kdsintf.amd.com.evil.example/vcek/v1/Milan/cert_chain",
		"https://user@kdsintf.amd.com/vcek/v1/Milan/cert_chain",
		"https://kdsintf.amd.com/vcek/v1/Milan/cert_chain#fragment",
		"https://kdsintf.amd.com:444/vcek/v1/Milan/cert_chain",
		"https://kdsintf.amd.com/vlek/v1/Milan/cert_chain",
		"https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain",
	}
	for _, rawURL := range cases {
		if _, _, err := getter.canonicalURL(rawURL); err == nil {
			t.Fatalf("canonicalURL(%q) succeeded", rawURL)
		}
	}
	if _, _, err := getter.canonicalURL(valid); err != nil {
		t.Fatalf("canonicalURL(valid): %v", err)
	}
	if server.count() != 0 {
		t.Fatalf("requests = %d, want 0", server.count())
	}
}

func TestKDSAllowsOnlyVCEKCRLForAllowedProduct(t *testing.T) {
	getter, _ := newKDSGetterForTest(t, func(http.ResponseWriter, *http.Request) {}, KDSGetterOptions{})
	if _, _, err := getter.canonicalURL(kds.CrlLinkByKey("Milan", abi.VcekReportSigner)); err != nil {
		t.Fatalf("VCEK CRL rejected: %v", err)
	}
	if _, _, err := getter.canonicalURL(kds.CrlLinkByKey("Milan", abi.VlekReportSigner)); err == nil {
		t.Fatal("VLEK CRL accepted")
	}
	if _, _, err := getter.canonicalURL(kds.CrlLinkByKey("Genoa", abi.VcekReportSigner)); err == nil {
		t.Fatal("disallowed-product CRL accepted")
	}
}

func TestKDSFetchOutlivesCanceledCaller(t *testing.T) {
	body := testKDSBody(t)
	started := make(chan struct{})
	release := make(chan struct{})
	getter, server := newKDSGetterForTest(t, func(writer http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = writer.Write(body)
	}, KDSGetterOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	errorsOut := make(chan error, 1)
	go func() {
		_, err := getter.GetContext(ctx, testKDSURL())
		errorsOut <- err
	}()
	<-started
	cancel()
	if err := <-errorsOut; !errors.Is(err, context.Canceled) {
		t.Fatalf("GetContext() error = %v, want context.Canceled", err)
	}
	close(release)
	got, err := getter.Get(testKDSURL())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("body mismatch")
	}
	if server.count() != 1 {
		t.Fatalf("requests = %d, want 1", server.count())
	}
}

func TestKDSBoundsFetchesInFlight(t *testing.T) {
	body := testKDSBody(t)
	started := make(chan struct{})
	release := make(chan struct{})
	getter, server := newKDSGetterForTest(t, func(writer http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = writer.Write(body)
	}, KDSGetterOptions{MaxInflight: 1})
	errorsOut := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := getter.Get(testKDSURL())
			errorsOut <- err
		}()
	}
	<-started
	otherURL := kds.VCEKCertURL("Milan", bytes.Repeat([]byte{2}, abi.ChipIDSize), 0)
	if _, err := getter.Get(otherURL); !errors.Is(err, errKDSBusy) {
		t.Fatalf("second fetch error = %v, want errKDSBusy", err)
	}
	close(release)
	for range 2 {
		if err := <-errorsOut; err != nil {
			t.Fatalf("shared fetch error = %v", err)
		}
	}
	if server.count() != 1 {
		t.Fatalf("requests = %d, want 1", server.count())
	}
}

func testCRLBody(t *testing.T, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()
	signer, err := guesttesting.DefaultTestOnlyCertChain("Milan-B0", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return signedCRL(signer, thisUpdate, nextUpdate)
}

func TestKDSCachedCRLIsRefetchedAfterNextUpdate(t *testing.T) {
	start := time.Now()
	first := testCRLBody(t, start.Add(-time.Minute), start.Add(time.Hour))
	second := testCRLBody(t, start.Add(time.Hour), start.Add(2*time.Hour))
	now := start
	var served atomic.Int32
	cacheDir := t.TempDir()
	getter, server := newKDSGetterForTest(t, func(writer http.ResponseWriter, _ *http.Request) {
		if served.Add(1) == 1 {
			_, _ = writer.Write(first)
			return
		}
		_, _ = writer.Write(second)
	}, KDSGetterOptions{CacheDir: cacheDir, Now: func() time.Time { return now }})
	crlURL := kds.CrlLinkByKey("Milan", abi.VcekReportSigner)
	for range 2 {
		got, err := getter.Get(crlURL)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, first) {
			t.Fatal("did not serve the current CRL")
		}
	}
	if server.count() != 1 {
		t.Fatalf("requests = %d, want 1", server.count())
	}
	now = start.Add(time.Hour)
	got, err := getter.Get(crlURL)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, second) {
		t.Fatal("served an expired CRL")
	}
	if server.count() != 2 {
		t.Fatalf("requests = %d, want 2", server.count())
	}
	restarted, err := NewKDSGetter(KDSGetterOptions{AllowedProducts: []string{"Milan"}, CacheDir: cacheDir, TestBaseURL: server.server.URL, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.Get(crlURL); err != nil || !bytes.Equal(got, second) {
		t.Fatalf("disk cache did not serve the current CRL: %v", err)
	}
	if server.count() != 2 {
		t.Fatalf("requests = %d, want 2", server.count())
	}
}

func TestKDSRejectsCRLThatIsNotCurrent(t *testing.T) {
	now := time.Now()
	cases := map[string][]byte{
		"expired":       testCRLBody(t, now.Add(-2*time.Hour), now.Add(-time.Hour)),
		"not yet valid": testCRLBody(t, now.Add(time.Hour), now.Add(2*time.Hour)),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			getter, _ := newKDSGetterForTest(t, func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write(body) }, KDSGetterOptions{MaxAttempts: 1})
			if _, err := getter.Get(kds.CrlLinkByKey("Milan", abi.VcekReportSigner)); err == nil || !strings.Contains(err.Error(), "not current") {
				t.Fatalf("Get() error = %v, want CRL is not current", err)
			}
		})
	}
}

func TestKDSDoesNotFollowRedirects(t *testing.T) {
	getter, server := newKDSGetterForTest(t, func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}, KDSGetterOptions{MaxAttempts: 4})
	if _, err := getter.Get(testKDSURL()); err == nil {
		t.Fatal("redirect succeeded")
	}
	if server.count() != 1 {
		t.Fatalf("requests = %d, want 1", server.count())
	}
}

func TestKDSRetriesRetryableStatuses(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			body := testKDSBody(t)
			var attempts atomic.Int32
			getter, server := newKDSGetterForTest(t, func(writer http.ResponseWriter, _ *http.Request) {
				if attempts.Add(1) == 1 {
					writer.WriteHeader(status)
					return
				}
				_, _ = writer.Write(body)
			}, KDSGetterOptions{MaxAttempts: 2})
			got, err := getter.Get(testKDSURL())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, body) {
				t.Fatal("body mismatch")
			}
			if server.count() != 2 {
				t.Fatalf("requests = %d, want 2", server.count())
			}
		})
	}
}

func TestKDSDoesNotRetryClientErrors(t *testing.T) {
	getter, server := newKDSGetterForTest(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
	}, KDSGetterOptions{MaxAttempts: 4})
	if _, err := getter.Get(testKDSURL()); err == nil {
		t.Fatal("404 succeeded")
	}
	if server.count() != 1 {
		t.Fatalf("requests = %d, want 1", server.count())
	}
}

func TestKDSRetryAfterOverridesBackoff(t *testing.T) {
	body := testKDSBody(t)
	var attempts atomic.Int32
	var delays []time.Duration
	getter, _ := newKDSGetterForTest(t, func(writer http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			writer.Header().Set("Retry-After", "3")
			writer.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = writer.Write(body)
	}, KDSGetterOptions{MaxAttempts: 2, InitialBackoff: time.Millisecond, Sleep: func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		return nil
	}})
	if _, err := getter.Get(testKDSURL()); err != nil {
		t.Fatal(err)
	}
	if len(delays) != 1 || delays[0] != 3*time.Second {
		t.Fatalf("delays = %v, want [3s]", delays)
	}
}

func TestKDSMemoryCacheReturnsClones(t *testing.T) {
	body := testKDSBody(t)
	getter, server := newKDSGetterForTest(t, func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write(body) }, KDSGetterOptions{})
	first, err := getter.Get(testKDSURL())
	if err != nil {
		t.Fatal(err)
	}
	first[0] ^= 0xff
	second, err := getter.Get(testKDSURL())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, body) {
		t.Fatal("cached body was mutated")
	}
	if server.count() != 1 {
		t.Fatalf("requests = %d, want 1", server.count())
	}
}

func TestKDSInflightRequestsAreMerged(t *testing.T) {
	body := testKDSBody(t)
	started := make(chan struct{})
	release := make(chan struct{})
	getter, server := newKDSGetterForTest(t, func(writer http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = writer.Write(body)
	}, KDSGetterOptions{})
	const callers = 8
	errorsOut := make(chan error, callers)
	for range callers {
		go func() {
			got, err := getter.Get(testKDSURL())
			if err == nil && !bytes.Equal(got, body) {
				err = errors.New("body mismatch")
			}
			errorsOut <- err
		}()
	}
	<-started
	close(release)
	for range callers {
		if err := <-errorsOut; err != nil {
			t.Fatal(err)
		}
	}
	if server.count() != 1 {
		t.Fatalf("requests = %d, want 1", server.count())
	}
}

func TestKDSDiskCacheSurvivesGetterReplacement(t *testing.T) {
	body := testKDSBody(t)
	cacheDir := t.TempDir()
	getter, server := newKDSGetterForTest(t, func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write(body) }, KDSGetterOptions{CacheDir: cacheDir})
	if _, err := getter.Get(testKDSURL()); err != nil {
		t.Fatal(err)
	}
	if server.count() != 1 {
		t.Fatalf("requests = %d, want 1", server.count())
	}
	second, err := NewKDSGetter(KDSGetterOptions{AllowedProducts: []string{"Milan"}, CacheDir: cacheDir, TestBaseURL: server.server.URL})
	if err != nil {
		t.Fatal(err)
	}
	got, err := second.Get(testKDSURL())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("disk cache body mismatch")
	}
	if server.count() != 1 {
		t.Fatalf("requests = %d, want 1", server.count())
	}
}

func TestKDSInvalidDiskCacheIsRefetched(t *testing.T) {
	body := testKDSBody(t)
	cacheDir := t.TempDir()
	getter, server := newKDSGetterForTest(t, func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write(body) }, KDSGetterOptions{CacheDir: cacheDir})
	key, _, err := getter.canonicalURL(testKDSURL())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(getter.cachePath(key), []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := getter.Get(testKDSURL()); err != nil {
		t.Fatal(err)
	}
	if server.count() != 1 {
		t.Fatalf("requests = %d, want 1", server.count())
	}
}
