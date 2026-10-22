package main

// Optional IpNetwork transport. Website-scoped grants remain the default.
import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	capnp "capnproto.org/go/capnp/v3"
	"capnproto.org/go/capnp/v3/rpc"
	"sandstorm.org/go/tempest/capnp/grain"
	"sandstorm.org/go/tempest/capnp/ip"
	"sandstorm.org/go/tempest/capnp/powerbox"
	bridge "sandstorm.org/go/tempest/capnp/sandstorm-http-bridge"
	"sandstorm.org/go/tempest/pkg/exp/util/bytestream"
)

const networkKey = "sandstorm:ip-network"

// changes serializes configuration changes; mu protects request registration.
// Never hold mu across database or bridge I/O, or while closing a connection.
type networkAccess struct {
	transport  *http.Transport // Cloned per request; connections are never pooled across grants.
	changes    chan struct{}
	mu         sync.Mutex
	generation uint64
	changing   bool
	active     map[*rpc.Conn]context.CancelFunc
	openAPI    func(context.Context) (*rpc.Conn, grain.SandstormApi, func(), error)
}

func newNetworkAccess() *networkAccess {
	return &networkAccess{
		active:  make(map[*rpc.Conn]context.CancelFunc),
		changes: make(chan struct{}, 1),
		openAPI: openNetworkAPI,
		transport: &http.Transport{
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		},
	}
}

func openNetworkAPI(ctx context.Context) (*rpc.Conn, grain.SandstormApi, func(), error) {
	socket, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, "unix", "/tmp/sandstorm-api")
	if err != nil {
		return nil, grain.SandstormApi{}, nil, fmt.Errorf("connect to Sandstorm API: %w", err)
	}
	conn := rpc.NewConn(rpc.NewStreamTransport(socket), nil)
	b := bridge.SandstormHttpBridge(conn.Bootstrap(ctx))
	defer b.Release()
	future, release := b.GetSandstormApi(ctx, nil)
	return conn, future.Api(), release, nil
}

// Bound the bridge call as well as RPC operations so a stalled claim cannot
// hold the settings lock indefinitely.
func claimNetwork(ctx context.Context, result *PowerboxResult, permissions []string) (string, error) {
	if permissions == nil {
		permissions = []string{}
	}
	body, err := json.Marshal(struct {
		RequestToken        string   `json:"requestToken"`
		RequiredPermissions []string `json:"requiredPermissions"`
	}{RequestToken: result.ClaimToken, RequiredPermissions: permissions})
	if err != nil {
		return "", fmt.Errorf("claim network capability: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "http://http-bridge/session/"+result.SessionId+"/claim", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("claim network capability: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("claim network capability: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("bridge rejected network claim")
	}
	var saved struct {
		Cap string `json:"cap"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&saved); err != nil {
		return "", fmt.Errorf("claim network capability: %w", err)
	}
	if saved.Cap == "" {
		return "", errors.New("bridge returned no capability")
	}
	if _, err := base64.StdEncoding.DecodeString(saved.Cap); err != nil {
		return "", fmt.Errorf("claim network capability: %w", err)
	}
	return saved.Cap, nil
}

func (s Server) validNetworkToken(ctx context.Context, token string) (bool, error) {
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return false, fmt.Errorf("restore network capability: %w", err)
	}
	conn, api, release, err := s.network.openAPI(ctx)
	if err != nil {
		return false, fmt.Errorf("restore network capability: %w", err)
	}
	defer conn.Close()
	defer release()
	restored, done := api.Restore(ctx, func(p grain.SandstormApi_restore_Params) error { return p.SetToken(data) })
	defer done()
	_, err = restored.Struct()
	if err != nil {
		return false, fmt.Errorf("restore network capability: %w", err)
	}
	return true, nil
}

func networkDescriptor() string {
	msg, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	chkfatal(err)
	desc, err := powerbox.NewRootPowerboxDescriptor(seg)
	chkfatal(err)
	tags, err := desc.NewTags(1)
	chkfatal(err)
	tags.At(0).SetId(ip.IpNetwork_TypeID)
	tag, err := ip.NewIpNetwork_PowerboxTag(seg)
	chkfatal(err)
	encryption, err := tag.NewEncryption()
	chkfatal(err)
	encryption.SetNone()
	chkfatal(tags.At(0).SetValue(tag.ToPtr()))
	data, err := msg.MarshalPacked()
	chkfatal(err)
	return base64.StdEncoding.EncodeToString(data)
}

// NetworkHandler is an internal API for the grain's backend. The backend must
// authorize callers before exposing network controls to users. In particular,
// do not forward this handler directly through a public reverse-proxy route.
func (s Server) NetworkHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" && r.Method != "POST" && r.Method != "DELETE" {
			w.Header().Set("Allow", "GET, POST, DELETE")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		var body networkClaim
		if r.Method == "POST" {
			if err := readNetworkClaim(ctx, w, r, &body); err != nil {
				http.Error(w, "Invalid claim token or session ID", http.StatusBadRequest)
				return
			}
		}
		// Decode before serializing mutations, so an incomplete body cannot
		// block other controls. Waiting for a mutation also obeys the deadline.
		if r.Method != "GET" {
			select {
			case s.network.changes <- struct{}{}:
				defer func() { <-s.network.changes }()
			case <-ctx.Done():
				http.Error(w, "Network settings request timed out", http.StatusGatewayTimeout)
				return
			}
		}
		token, err := s.storage.GetTokenForContext(ctx, networkKey)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Cannot read network settings", http.StatusInternalServerError)
			return
		}
		switch r.Method {
		case "GET":
			valid := false
			if token != "" {
				valid, _ = s.validNetworkToken(ctx, token)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(struct {
				Configured bool   `json:"configured"`
				Valid      bool   `json:"valid"`
				Descriptor string `json:"descriptor"`
			}{Configured: token != "", Valid: valid, Descriptor: networkDescriptor()})
		case "POST":
			if token != "" {
				http.Error(w, "Disconnect the existing network first", http.StatusConflict)
				return
			}
			saved, err := claimNetwork(ctx, &PowerboxResult{
				ClaimToken: body.Token, SessionId: body.SessionID,
			}, body.RequiredPermissions)
			if err != nil {
				http.Error(w, "Could not claim network access", http.StatusBadGateway)
				return
			}
			err = s.saveNetwork(ctx, saved)
			if err != nil {
				// The request may already be canceled. Still try to drop the
				// durable grant that we could not save.
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
				dropErr := s.dropNetworkToken(cleanupCtx, saved)
				cleanupCancel()
				if dropErr != nil {
					log.Printf("Failed to drop unsaved network capability: %v", dropErr)
				}
				http.Error(w, "Could not save network access", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "DELETE":
			if err := s.disconnectNetwork(ctx, token); err != nil {
				http.Error(w, "Could not disconnect network access; retry disconnecting", http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	})
}

type networkClaim struct {
	Token               string   `json:"token"`
	SessionID           string   `json:"sessionId"`
	RequiredPermissions []string `json:"requiredPermissions"`
}

func readNetworkClaim(ctx context.Context, w http.ResponseWriter, r *http.Request, claim *networkClaim) error {
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	if err := controller.SetReadDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return fmt.Errorf("set network claim read deadline: %w", err)
	}
	// A context alone does not interrupt HTTP body reads. Wake the connection
	// on cancellation as well, and finish the callback before resetting it.
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		controller.SetReadDeadline(time.Now())
		close(interrupted)
	})
	defer func() {
		if !stop() {
			<-interrupted
		}
		controller.SetReadDeadline(time.Time{})
	}()
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(claim); err != nil {
		return fmt.Errorf("decode network claim: %w", err)
	}
	if claim.Token == "" || claim.SessionID == "" {
		return errors.New("missing claim token or session ID")
	}
	return ctx.Err()
}

// Caller holds changes. Mark the transition before touching storage, so request
// snapshots taken before or during the write cannot register an obsolete grant.
func (s Server) saveNetwork(ctx context.Context, token string) error {
	s.network.mu.Lock()
	s.network.changing = true
	s.network.generation++
	s.network.mu.Unlock()
	defer func() {
		s.network.mu.Lock()
		s.network.changing = false
		s.network.mu.Unlock()
	}()
	if err := s.storage.SetTokenForContext(ctx, networkKey, token); err != nil {
		return fmt.Errorf("save network capability: %w", err)
	}
	return nil
}

func (s Server) dropNetworkToken(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return fmt.Errorf("drop network capability: %w", err)
	}
	conn, api, release, err := s.network.openAPI(ctx)
	if err != nil {
		return fmt.Errorf("drop network capability: %w", err)
	}
	defer conn.Close()
	defer release()
	result, done := api.Drop(ctx, func(p grain.SandstormApi_drop_Params) error { return p.SetToken(data) })
	defer done()
	_, err = result.Struct()
	if err != nil {
		return fmt.Errorf("drop network capability: %w", err)
	}
	return nil
}

// Caller holds changes. Block new requests while disconnecting and invalidate
// requests still opening a bridge connection, then close registered streams.
func (s Server) disconnectNetwork(ctx context.Context, token string) error {
	s.network.mu.Lock()
	s.network.changing = true
	s.network.generation++
	active := make(map[*rpc.Conn]context.CancelFunc, len(s.network.active))
	for conn, cancel := range s.network.active {
		active[conn] = cancel
	}
	s.network.mu.Unlock()
	defer func() {
		s.network.mu.Lock()
		s.network.changing = false
		s.network.mu.Unlock()
	}()
	for conn, cancel := range active {
		cancel()
		conn.Close()
	}
	// Retain the durable token on failure so disconnect can be retried.
	if err := s.dropNetworkToken(ctx, token); err != nil {
		return err
	}
	_, err := s.storage.db.ExecContext(ctx, "DELETE FROM powerbox_proxy_tokens WHERE url = ?", networkKey)
	if err != nil {
		return fmt.Errorf("delete network capability: %w", err)
	}
	return nil
}

// Each request restores the capability afresh. No connection pool can outlive
// revocation; closing its RPC connection also terminates the response stream.
func (s Server) networkRequest(req *http.Request) (*http.Response, error, bool) {
	s.network.mu.Lock()
	if s.network.changing {
		s.network.mu.Unlock()
		return nil, errors.New("network configuration is changing"), true
	}
	generation := s.network.generation
	s.network.mu.Unlock()
	lookupCtx, cancelLookup := context.WithTimeout(req.Context(), 15*time.Second)
	token, err := s.storage.GetTokenForContext(lookupCtx, networkKey)
	cancelLookup()
	s.network.mu.Lock()
	changed := generation != s.network.generation || s.network.changing
	s.network.mu.Unlock()
	if changed {
		return nil, errors.New("network configuration changed"), true
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, false
	}
	if err != nil {
		return nil, fmt.Errorf("read network capability: %w", err), true
	}
	tokenBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("decode network capability: %w", err), true
	}
	ctx, cancel := context.WithCancel(req.Context())
	conn, api, release, err := s.network.openAPI(ctx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("open network API: %w", err), true
	}
	s.network.mu.Lock()
	if generation != s.network.generation || s.network.changing {
		s.network.mu.Unlock()
		cancel()
		release()
		conn.Close()
		return nil, errors.New("network configuration changed"), true
	}
	s.network.active[conn] = cancel
	s.network.mu.Unlock()
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			cancel()
			release()
			conn.Close()
			s.network.mu.Lock()
			delete(s.network.active, conn)
			s.network.mu.Unlock()
		})
	}
	transport := s.network.transport.Clone()
	// Intentionally no HTTP_PROXY: all DNS and TCP go through the capability.
	transport.DialContext = func(_ context.Context, _, address string) (net.Conn, error) {
		// Transport may detach its dial context from the request. This
		// connection belongs to exactly one request, so use its context.
		dialCtx, cancelDial := context.WithTimeout(ctx, 30*time.Second)
		defer cancelDial()
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return nil, err
		}
		restored, finishRestore := api.Restore(dialCtx, func(p grain.SandstormApi_restore_Params) error { return p.SetToken(tokenBytes) })
		defer finishRestore()
		result, err := restored.Struct()
		if err != nil {
			return nil, fmt.Errorf("restore network capability: %w", err)
		}
		capability := ip.IpNetwork(result.Cap())
		remote, finishHost := capability.GetRemoteHostByName(dialCtx, func(p ip.IpNetwork_getRemoteHostByName_Params) error { return p.SetAddress(host) })
		defer finishHost()
		tcp, finishPort := remote.Host().GetTcpPort(dialCtx, func(p ip.IpRemoteHost_getTcpPort_Params) error {
			p.SetPortNum(uint16(port))
			return nil
		})
		defer finishPort()
		streamCtx, stopStream := context.WithCancel(ctx)
		incoming, downstream := bytestream.Pipe()
		connected, finishConnect := tcp.Port().Connect(dialCtx, func(p ip.TcpPort_connect_Params) error { return p.SetDownstream(downstream.AddRef()) })
		downstream.Release()
		if _, err := connected.Struct(); err != nil {
			stopStream()
			incoming.Close()
			finishConnect()
			// Preserve pipelining on success, but identify which RPC failed.
			if _, hostErr := remote.Struct(); hostErr != nil {
				return nil, fmt.Errorf("resolve network host %q: %w", host, hostErr)
			}
			if _, portErr := tcp.Struct(); portErr != nil {
				return nil, fmt.Errorf("get network TCP port %s: %w", address, portErr)
			}
			return nil, fmt.Errorf("connect network TCP stream %s: %w", address, err)
		}
		upstream := connected.Upstream().AddRef()
		writer := bytestream.ToWriteCloser(streamCtx, upstream)
		client, relay := net.Pipe()
		var closeOnce sync.Once
		closeStream := func() {
			closeOnce.Do(func() {
				stopStream()
				relay.Close()
				incoming.Close()
				finishConnect()
			})
		}
		go func() {
			defer closeStream()
			io.Copy(relay, incoming)
		}()
		go func() {
			defer upstream.Release()
			defer closeStream()
			io.Copy(writer, relay)
		}()
		go func() {
			<-ctx.Done()
			closeStream()
		}()
		return client, nil
	}
	clone := req.Clone(ctx)
	clone.RequestURI = ""
	clone.Header.Del("Proxy-Authorization")
	resp, err := transport.RoundTrip(clone)
	if err != nil {
		cleanup()
		return nil, err, true
	}
	resp.Body = &networkBody{ReadCloser: resp.Body, cleanup: cleanup}
	return resp, nil, true
}

type networkBody struct {
	io.ReadCloser
	cleanup func()
}

func (b *networkBody) Close() error {
	defer b.cleanup()
	return b.ReadCloser.Close()
}
