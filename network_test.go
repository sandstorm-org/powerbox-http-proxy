package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	capnp "capnproto.org/go/capnp/v3"
	"capnproto.org/go/capnp/v3/rpc"
	"sandstorm.org/go/tempest/capnp/grain"
	"sandstorm.org/go/tempest/capnp/ip"
	"sandstorm.org/go/tempest/capnp/powerbox"
	"sandstorm.org/go/tempest/capnp/util"
	"sandstorm.org/go/tempest/pkg/exp/util/bytestream"
)

type testNetworkAPI struct {
	grain.SandstormApi_Server
	target   string
	revoked  atomic.Bool
	failDrop atomic.Bool
}

func (a *testNetworkAPI) Restore(ctx context.Context, call grain.SandstormApi_restore) error {
	if a.revoked.Load() {
		return errors.New("revoked")
	}
	result, err := call.AllocResults()
	if err != nil {
		return err
	}
	network := ip.IpNetwork_ServerToClient(&testIPNetwork{target: a.target})
	return result.SetCap(capnp.Client(network))
}
func (a *testNetworkAPI) Drop(ctx context.Context, call grain.SandstormApi_drop) error {
	if a.failDrop.Load() {
		return errors.New("drop failed")
	}
	a.revoked.Store(true)
	_, err := call.AllocResults()
	return err
}

type testIPNetwork struct {
	ip.IpNetwork_Server
	target string
}

func (n *testIPNetwork) GetRemoteHostByName(ctx context.Context, call ip.IpNetwork_getRemoteHostByName) error {
	host, _ := call.Args().Address()
	if host != "example.test" && host != "example.com" {
		return errors.New("unexpected host: " + host)
	}
	result, err := call.AllocResults()
	if err != nil {
		return err
	}
	remote := ip.IpRemoteHost_ServerToClient(&testRemoteHost{target: n.target})
	return result.SetHost(remote)
}

type testRemoteHost struct {
	ip.IpRemoteHost_Server
	target string
}

func (h *testRemoteHost) GetTcpPort(ctx context.Context, call ip.IpRemoteHost_getTcpPort) error {
	if call.Args().PortNum() != 80 && call.Args().PortNum() != 443 {
		return errors.New("unexpected port")
	}
	result, err := call.AllocResults()
	if err != nil {
		return err
	}
	port := ip.TcpPort_ServerToClient(&testTCPPort{target: h.target})
	return result.SetPort(port)
}

type testTCPPort struct {
	ip.TcpPort_Server
	target string
}

func (p *testTCPPort) Connect(ctx context.Context, call ip.TcpPort_connect) error {
	socket, err := net.Dial("tcp", p.target)
	if err != nil {
		return err
	}
	downstream := call.Args().Downstream().AddRef()
	// The request context ends when Connect returns; the stream lives longer.
	go func() {
		defer downstream.Release()
		defer socket.Close()
		writer := bytestream.ToWriteCloser(context.Background(), downstream)
		io.Copy(writer, socket)
		writer.Close()
	}()
	result, err := call.AllocResults()
	if err != nil {
		return err
	}
	upstream := util.ByteStream_ServerToClient(&testSocketStream{socket: socket})
	return result.SetUpstream(upstream)
}

func networkTestServer(t *testing.T, target string) (Server, *testNetworkAPI) {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	storage, err := NewStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(storage, nil)
	api := &testNetworkAPI{target: target}
	srv.network.openAPI = func(ctx context.Context) (*rpc.Conn, grain.SandstormApi, func(), error) {
		local, remote := net.Pipe()
		server := rpc.NewConn(rpc.NewStreamTransport(remote), &rpc.Options{BootstrapClient: capnp.Client(grain.SandstormApi_ServerToClient(api))})
		client := rpc.NewConn(rpc.NewStreamTransport(local), nil)
		capability := grain.SandstormApi(client.Bootstrap(ctx))
		return client, capability, func() { capability.Release(); server.Close() }, nil
	}
	return srv, api
}
func configureNetwork(t *testing.T, srv Server) {
	t.Helper()
	if err := srv.storage.SetTokenFor(networkKey, base64.StdEncoding.EncodeToString([]byte("test-network"))); err != nil {
		t.Fatal(err)
	}
}
func networkControl(srv Server, method string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/_sandstorm/network", nil)
	result := httptest.NewRecorder()
	srv.NetworkHandler().ServeHTTP(result, req)
	return result
}
func TestNetworkControls(t *testing.T) {
	srv, _ := networkTestServer(t, "")
	if got := networkControl(srv, "PATCH").Code; got != 405 {
		t.Fatalf("method: %d", got)
	}
	if got := networkControl(srv, "POST").Code; got != 400 {
		t.Fatalf("empty claim: %d", got)
	}
	status := networkControl(srv, "GET")
	if status.Code != 200 || !strings.Contains(status.Body.String(), `"configured":false`) {
		t.Fatal(status)
	}
	data, err := base64.StdEncoding.DecodeString(networkDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	msg, err := capnp.UnmarshalPacked(data)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := powerbox.ReadRootPowerboxDescriptor(msg)
	if err != nil {
		t.Fatal(err)
	}
	tags, _ := desc.Tags()
	if tags.Len() != 1 || tags.At(0).Id() != ip.IpNetwork_TypeID {
		t.Fatal("wrong descriptor")
	}
}
func TestNetworkTransportAndDisconnect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials leaked")
		}
		w.Write([]byte("network article"))
	}))
	defer upstream.Close()
	srv, api := networkTestServer(t, strings.TrimPrefix(upstream.URL, "http://"))
	req := httptest.NewRequest("GET", "http://example.test/article", nil)
	if _, _, configured := srv.networkRequest(req); configured {
		t.Fatal("network enabled by default")
	}
	configureNetwork(t, srv)
	req.Header.Set("Proxy-Authorization", "secret")
	resp, err, configured := srv.networkRequest(req)
	if err != nil || !configured {
		t.Fatalf("request: %v, %v", configured, err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "network article" {
		t.Fatalf("body: %q %v", body, err)
	}
	// New Server instances restore the saved setting (as after a grain restart).
	restarted := NewServer(srv.storage, nil)
	restarted.network.openAPI = srv.network.openAPI
	resp, err, _ = restarted.networkRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := networkControl(srv, "DELETE").Code; got != 204 {
		t.Fatal(got)
	}
	if !api.revoked.Load() {
		t.Fatal("durable capability was not dropped")
	}
	if _, _, configured := srv.networkRequest(req); configured {
		t.Fatal("did not return to per-site access")
	}
	configureNetwork(t, srv)
	if _, err, configured := srv.networkRequest(req); !configured || err == nil {
		t.Fatal("revoked grant should fail without prompting or direct networking")
	}
}
func TestNetworkDisconnectStopsActiveDownload(t *testing.T) {
	finished := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("start"))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-finished:
		}
	}))
	defer upstream.Close()
	defer close(finished)
	srv, _ := networkTestServer(t, strings.TrimPrefix(upstream.URL, "http://"))
	configureNetwork(t, srv)
	resp, err, _ := srv.networkRequest(httptest.NewRequest("GET", "http://example.test/slow", nil))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := io.ReadAll(resp.Body); resp.Body.Close(); done <- err }()
	if got := networkControl(srv, "DELETE").Code; got != 204 {
		t.Fatal(got)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("download completed despite revocation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("download survived disconnect")
	}
}
func TestNetworkTLSVerification(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("bad certificate")) }))
	defer upstream.Close()
	srv, _ := networkTestServer(t, strings.TrimPrefix(upstream.URL, "https://"))
	configureNetwork(t, srv)
	_, err, configured := srv.networkRequest(httptest.NewRequest("GET", "https://example.test/", nil))
	if !configured || err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("TLS certificate accepted: %v", err)
	}
}

type networkClaimTransport func(*http.Request) (*http.Response, error)

func (f networkClaimTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestNetworkClaimPermissionsAndErrors(t *testing.T) {
	original := http.DefaultClient
	defer func() { http.DefaultClient = original }()
	for _, c := range []struct {
		code  int
		body  string
		valid bool
	}{
		{200, `{"cap":"dG9rZW4="}`, true}, {403, `{"cap":"dG9rZW4="}`, false},
		{200, `{}`, false}, {200, `{"cap":"invalid!"}`, false},
	} {
		http.DefaultClient = &http.Client{Transport: networkClaimTransport(func(r *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"requiredPermissions":["access"]`) || !strings.Contains(string(body), `"requestToken":"claim"`) {
				t.Errorf("wrong claim: %s", body)
			}
			if r.URL.Path != "/session/session/claim" {
				t.Errorf("wrong session: %s", r.URL.Path)
			}
			if _, ok := r.Context().Deadline(); !ok {
				t.Error("claim has no deadline")
			}
			return &http.Response{StatusCode: c.code, Body: io.NopCloser(strings.NewReader(c.body))}, nil
		})}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := claimNetwork(ctx, &PowerboxResult{ClaimToken: "claim", SessionId: "session"}, []string{"access"})
		cancel()
		if (err == nil) != c.valid {
			t.Errorf("claim %d %s: %v", c.code, c.body, err)
		}
	}
}

func TestNetworkFailedDisconnectCanRetry(t *testing.T) {
	srv, api := networkTestServer(t, "")
	configureNetwork(t, srv)
	api.failDrop.Store(true)
	if got := networkControl(srv, "DELETE").Code; got != 502 {
		t.Fatalf("drop failure: %d", got)
	}
	if _, err := srv.storage.GetTokenFor(networkKey); err != nil {
		t.Fatal("lost retry token", err)
	}
	api.failDrop.Store(false)
	for i := 0; i < 2; i++ {
		if got := networkControl(srv, "DELETE").Code; got != 204 {
			t.Fatalf("disconnect/retry: %d", got)
		}
	}
}

func TestNetworkDisconnectDuringDial(t *testing.T) {
	srv, _ := networkTestServer(t, "")
	configureNetwork(t, srv)
	opener := srv.network.openAPI
	entered, resume := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	srv.network.openAPI = func(ctx context.Context) (*rpc.Conn, grain.SandstormApi, func(), error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-resume
		}
		return opener(ctx)
	}
	done := make(chan error, 1)
	go func() {
		_, err, _ := srv.networkRequest(httptest.NewRequest("GET", "http://example.test/", nil))
		done <- err
	}()
	<-entered
	// This must complete while the outgoing request is still dialing.
	result := networkControl(srv, "DELETE")
	close(resume)
	if result.Code != 204 {
		t.Fatal(result)
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "configuration changed") {
		t.Fatalf("in-flight dial survived disconnect: %v", err)
	}
	srv.network.mu.Lock()
	defer srv.network.mu.Unlock()
	if len(srv.network.active) != 0 {
		t.Fatal("stale connection registered")
	}
}

func TestNetworkRequestCancellation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("start"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer upstream.Close()
	srv, _ := networkTestServer(t, strings.TrimPrefix(upstream.URL, "http://"))
	configureNetwork(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest("GET", "http://example.test/", nil).WithContext(ctx)
	resp, err, _ := srv.networkRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err == nil {
		t.Fatal("canceled response completed")
	}
	srv.network.mu.Lock()
	defer srv.network.mu.Unlock()
	if len(srv.network.active) != 0 {
		t.Fatal("canceled connection retained")
	}
}

func TestNetworkClaimSaveFailureDropsToken(t *testing.T) {
	srv, api := networkTestServer(t, "")
	// Read still works, but the transaction cannot insert the new grant.
	_, err := srv.storage.db.Exec(`CREATE TRIGGER fail_network_save BEFORE INSERT ON powerbox_proxy_tokens
        BEGIN SELECT RAISE(FAIL, 'save failed'); END`)
	if err != nil {
		t.Fatal(err)
	}
	original := http.DefaultClient
	defer func() { http.DefaultClient = original }()
	http.DefaultClient = &http.Client{Transport: networkClaimTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"cap":"dG9rZW4="}`))}, nil
	})}
	req := httptest.NewRequest("POST", "/_sandstorm/network", strings.NewReader(`{"token":"claim","sessionId":"session"}`))
	result := httptest.NewRecorder()
	srv.NetworkHandler().ServeHTTP(result, req)
	if result.Code != 500 || !api.revoked.Load() {
		t.Fatalf("unsaved grant not dropped: %v", result)
	}
}

func TestNetworkHTTPSConnect(t *testing.T) {
	srv, api := networkTestServer(t, "")
	var err error
	srv.spoofer, err = GenSpoofer()
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer application-token" {
			t.Error("application authorization lost")
		}
		w.Write([]byte("secure article"))
	}))
	defer upstream.Close()
	api.target = strings.TrimPrefix(upstream.URL, "https://")
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	srv.network.transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	configureNetwork(t, srv)
	proxy := httptest.NewServer(srv.ProxyHandler())
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	proxyRoots := x509.NewCertPool()
	cert, err := x509.ParseCertificate(srv.spoofer.RawCACert())
	if err != nil {
		t.Fatal(err)
	}
	proxyRoots.AddCert(cert)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{
		// Existing proxy certificates have only a Common Name. Verify their
		// chain and that name here; origin TLS uses normal hostname verification.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.PeerCertificates[0].Subject.CommonName != "example.com" {
				return errors.New("wrong proxy certificate name")
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: proxyRoots})
			return err
		},
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	req, _ := http.NewRequest("GET", "https://example.com/article", nil)
	req.Header.Set("Authorization", "Bearer application-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "secure article" {
		t.Fatalf("body: %q, %v", body, err)
	}
}

// Like a real TCP capability, releasing the upstream closes the socket.
type testSocketStream struct{ socket net.Conn }

func (s *testSocketStream) Write(ctx context.Context, call util.ByteStream_write) error {
	data, err := call.Args().Data()
	if err != nil {
		return err
	}
	_, err = s.socket.Write(data)
	return err
}
func (s *testSocketStream) Done(context.Context, util.ByteStream_done) error             { return s.socket.Close() }
func (s *testSocketStream) ExpectSize(context.Context, util.ByteStream_expectSize) error { return nil }
func (s *testSocketStream) Shutdown()                                                    { s.socket.Close() }

func TestNetworkClaimAndPersistence(t *testing.T) {
	for _, permissions := range [][]string{nil, {"access", "manageNetwork"}} {
		t.Run(fmt.Sprint(permissions), func(t *testing.T) {
			srv, _ := networkTestServer(t, "")
			original := http.DefaultClient
			defer func() { http.DefaultClient = original }()
			var claims int
			http.DefaultClient = &http.Client{Transport: networkClaimTransport(func(r *http.Request) (*http.Response, error) {
				claims++
				var body struct {
					RequestToken        string   `json:"requestToken"`
					RequiredPermissions []string `json:"requiredPermissions"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body.RequestToken != "claim" || body.RequiredPermissions == nil || !slices.Equal(body.RequiredPermissions, permissions) {
					t.Fatalf("wrong claim: %+v", body)
				}
				if r.URL.Path != "/session/session/claim" {
					t.Fatalf("wrong session: %s", r.URL.Path)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"cap":"dG9rZW4="}`))}, nil
			})}
			payload, _ := json.Marshal(map[string]interface{}{"token": "claim", "sessionId": "session", "requiredPermissions": permissions})
			for _, expected := range []int{204, 409} {
				result := httptest.NewRecorder()
				srv.NetworkHandler().ServeHTTP(result, httptest.NewRequest("POST", "/_sandstorm/network", bytes.NewReader(payload)))
				if result.Code != expected {
					t.Fatalf("claim: %v", result)
				}
			}
			if claims != 1 {
				t.Fatalf("duplicate claim reached bridge: %d", claims)
			}
			restarted := NewServer(srv.storage, nil)
			restarted.network.openAPI = srv.network.openAPI
			result := networkControl(restarted, "GET")
			if result.Code != 200 || !strings.Contains(result.Body.String(), `"configured":true`) || !strings.Contains(result.Body.String(), `"valid":true`) {
				t.Fatalf("grant did not survive restart: %v", result)
			}
		})
	}
}
