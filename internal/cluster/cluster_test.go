package cluster

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"request-validator/internal/crdt"
)

func mustFreeUDPPort(t *testing.T) int {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	// memberlist needs both TCP and UDP on the same port; we can't
	// reserve that atomically. We just return the UDP one and accept
	// a vanishingly small race risk in tests.
	return udp.LocalAddr().(*net.UDPAddr).Port
}

func startNode(t *testing.T, name string, store *crdt.Store, peers []string) *Node {
	t.Helper()
	port := mustFreeUDPPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	var applied atomic.Int32
	n, err := New(Options{
		NodeName:       name,
		BindAddr:       addr,
		Peers:          peers,
		Store:          store,
		OnDeltaApplied: func() { applied.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	t.Cleanup(n.Stop)
	return n
}

func newStore(t *testing.T, node string) *crdt.Store {
	t.Helper()
	s, err := crdt.New(crdt.Options{Node: node})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func eventually(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("eventually: condition never became true")
}

func TestTwoNodesConverge(t *testing.T) {
	storeA := newStore(t, "A")
	storeB := newStore(t, "B")
	a := startNode(t, "A", storeA, nil)
	startNode(t, "B", storeB, []string{a.LocalAddr()})

	// PUT a group on A, broadcast.
	stamp, err := storeA.PutGroup("g1", map[string]any{"name": "g1"})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"name": "g1"})
	a.BroadcastDelta(crdt.Delta{
		Section: crdt.SectionGroups,
		Key:     "g1",
		Map:     &crdt.MapEntry{Stamp: stamp, Payload: payload},
	})

	eventually(t, 5*time.Second, func() bool {
		var v map[string]any
		_, ok, _ := storeB.Groups.Get("g1", &v)
		return ok && v["name"] == "g1"
	})
}

func TestAntiEntropyOnJoin(t *testing.T) {
	storeA := newStore(t, "A")
	// Seed A with a value *before* B joins.
	if _, err := storeA.PutGroup("seed", map[string]any{"name": "seed"}); err != nil {
		t.Fatal(err)
	}
	a := startNode(t, "A", storeA, nil)

	storeB := newStore(t, "B")
	startNode(t, "B", storeB, []string{a.LocalAddr()})

	eventually(t, 5*time.Second, func() bool {
		var v map[string]any
		_, ok, _ := storeB.Groups.Get("seed", &v)
		return ok && v["name"] == "seed"
	})
}

func TestUnknownEnvelopeVersionDropped(t *testing.T) {
	storeA := newStore(t, "A")
	startNode(t, "A", storeA, nil)

	d := &delegate{node: &Node{opts: Options{Store: storeA}}}
	bad, _ := json.Marshal(envelope{V: 99, Delta: &crdt.Delta{Section: crdt.SectionGroups, Key: "x", Map: &crdt.MapEntry{Stamp: crdt.Stamp{TS: 1, Node: "z"}, Payload: []byte(`{}`)}}})
	d.NotifyMsg(bad)
	var v map[string]any
	if _, ok, _ := storeA.Groups.Get("x", &v); ok {
		t.Fatal("unknown version should be dropped")
	}
}

func TestResolvePeersAgainstLocalhost(t *testing.T) {
	n, _ := New(Options{
		NodeName:     "x",
		BindAddr:     "127.0.0.1:7946",
		DiscoveryDNS: "localhost",
		Store:        newStore(t, "x"),
	})
	peers := n.resolvePeers()
	if len(peers) == 0 {
		t.Fatal("expected at least one peer from localhost lookup")
	}
	for _, p := range peers {
		if !strings.HasSuffix(p, ":7946") {
			t.Errorf("expected each peer to use bind port, got %q", p)
		}
	}
}

func TestResolvePeersUnknownNameYieldsEmpty(t *testing.T) {
	n, _ := New(Options{
		NodeName:     "x",
		BindAddr:     "127.0.0.1:7946",
		DiscoveryDNS: "this.host.should.never.exist.invalid.",
		Store:        newStore(t, "x"),
	})
	peers := n.resolvePeers()
	if len(peers) != 0 {
		t.Fatalf("expected empty peer list, got %v", peers)
	}
}

func TestMembersReturnsAliveNodeAfterStart(t *testing.T) {
	storeA := newStore(t, "A")
	a := startNode(t, "A", storeA, nil)
	members := a.Members()
	if len(members) == 0 {
		t.Fatal("expected at least the local node in Members()")
	}
}

func TestLocalAddrPopulatedAfterStart(t *testing.T) {
	storeA := newStore(t, "A")
	a := startNode(t, "A", storeA, nil)
	if a.LocalAddr() == "" {
		t.Fatal("expected LocalAddr to be populated")
	}
}

func TestEnvelopeRoundTripJSON(t *testing.T) {
	d := crdt.Delta{
		Section: crdt.SectionGroups,
		Key:     "g",
		Map: &crdt.MapEntry{
			Stamp:   crdt.Stamp{TS: 42, Node: "n"},
			Payload: []byte(`{"x":1}`),
		},
	}
	env := envelope{V: 1, Delta: &d}
	payload, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var decoded envelope
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.V != 1 || decoded.Delta == nil || decoded.Delta.Key != "g" {
		t.Fatalf("round-trip mismatch: %+v", decoded)
	}
}

func TestStopIsIdempotent(t *testing.T) {
	storeA := newStore(t, "A")
	a := startNode(t, "A", storeA, nil)
	// First Stop happens via t.Cleanup later; double-call here should
	// not panic.
	a.Stop()
	a.Stop()
}
