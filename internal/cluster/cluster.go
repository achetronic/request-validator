// Package cluster wraps hashicorp/memberlist to gossip CRDT deltas
// between request-validator replicas.
//
// The package is intentionally thin: memberlist owns peer discovery
// (via seed peers or a periodic DNS resolve), failure detection and
// the actual on-the-wire transport; cluster only translates between
// memberlist's Delegate / Broadcast interfaces and the CRDT store.
//
// Two integration points:
//
//   - `BroadcastDelta(d)` is invoked by the admin API on every
//     successful local write. The delta is enqueued for retransmission
//     to a small random subset of peers each gossip tick.
//   - `LocalState` / `MergeRemoteState` (memberlist's anti-entropy
//     push/pull) exchange the full FullState every ~30s so a node
//     missing individual deltas eventually catches up.
//
// Deltas that fail to apply on the remote (validation, compile) end
// up in the local quarantine.
package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/memberlist"

	"request-validator/internal/crdt"
	"request-validator/internal/log"
	rvmetrics "request-validator/internal/metrics"
)

// Options configures a cluster node.
type Options struct {
	// NodeName is the gossip identity of this replica. Must be stable
	// across restarts (use hostname + persisted UUID).
	NodeName string

	// BindAddr is the host:port memberlist listens on. Both UDP and
	// TCP on this port are required for gossip.
	BindAddr string

	// AdvertiseAddr is the host:port other nodes should use to reach
	// this one. Defaults to BindAddr when empty.
	AdvertiseAddr string

	// Peers is a static list of host:port seeds used at boot.
	Peers []string

	// DiscoveryDNS, when non-empty, is resolved periodically and any
	// new IPs are joined. Intended for Kubernetes headless Services.
	DiscoveryDNS string

	// DiscoveryInterval governs DNS refresh frequency. Default 30s.
	DiscoveryInterval time.Duration

	// Store is the local CRDT store; deltas are applied here, and
	// LocalState/MergeRemoteState use its Snapshot/MergeFull.
	Store *crdt.Store

	// OnApplyError, when non-nil, is invoked for every delta that
	// applies to the CRDT layer but causes the downstream rebuild to
	// fail. The caller typically pushes the offending key to its
	// local quarantine.
	OnApplyError func(d crdt.Delta, err error)

	// OnDeltaApplied is invoked after a remote delta has been folded
	// into the local store. Typically schedules a Config rebuild.
	OnDeltaApplied func()
}

// Node is a running cluster member.
type Node struct {
	opts Options
	ml   atomic.Pointer[memberlist.Memberlist]

	delegate *delegate
	bq       *memberlist.TransmitLimitedQueue

	dnsCancel context.CancelFunc
	dnsWG     sync.WaitGroup
}

// New constructs a cluster node but does NOT start it. Call Start to
// join.
func New(opts Options) (*Node, error) {
	if opts.NodeName == "" {
		return nil, errors.New("cluster: NodeName required")
	}
	if opts.BindAddr == "" {
		return nil, errors.New("cluster: BindAddr required")
	}
	if opts.Store == nil {
		return nil, errors.New("cluster: Store required")
	}
	if opts.DiscoveryInterval <= 0 {
		opts.DiscoveryInterval = 30 * time.Second
	}
	return &Node{opts: opts}, nil
}

// Start configures memberlist, joins the cluster and spawns the
// optional DNS discovery loop.
func (n *Node) Start() error {
	host, portStr, err := net.SplitHostPort(n.opts.BindAddr)
	if err != nil {
		return fmt.Errorf("cluster: invalid bind addr %q: %w", n.opts.BindAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("cluster: invalid bind port %q: %w", portStr, err)
	}

	cfg := memberlist.DefaultLANConfig()
	cfg.Name = n.opts.NodeName
	cfg.BindAddr = host
	cfg.BindPort = port
	cfg.AdvertisePort = port
	if n.opts.AdvertiseAddr != "" {
		ahost, aportStr, aerr := net.SplitHostPort(n.opts.AdvertiseAddr)
		if aerr != nil {
			return fmt.Errorf("cluster: invalid advertise addr %q: %w", n.opts.AdvertiseAddr, aerr)
		}
		ap, perr := strconv.Atoi(aportStr)
		if perr != nil {
			return fmt.Errorf("cluster: invalid advertise port %q: %w", aportStr, perr)
		}
		cfg.AdvertiseAddr = ahost
		cfg.AdvertisePort = ap
	}
	cfg.LogOutput = newMemberlistLogShim()

	d := &delegate{node: n}
	cfg.Delegate = d
	cfg.Events = d

	ml, err := memberlist.Create(cfg)
	if err != nil {
		return fmt.Errorf("cluster: memberlist create: %w", err)
	}
	n.ml.Store(ml)
	n.delegate = d
	n.bq = &memberlist.TransmitLimitedQueue{
		NumNodes:       func() int { return ml.NumMembers() },
		RetransmitMult: 3,
	}

	if len(n.opts.Peers) > 0 {
		if _, err := ml.Join(n.opts.Peers); err != nil {
			log.Warnw("cluster: initial join had errors", "err", err.Error())
		}
	}
	if n.opts.DiscoveryDNS != "" {
		ctx, cancel := context.WithCancel(context.Background())
		n.dnsCancel = cancel
		n.dnsWG.Add(1)
		go func() {
			defer n.dnsWG.Done()
			n.runDNSDiscovery(ctx)
		}()
	}
	return nil
}

// Stop leaves the cluster gracefully. Safe to call more than once;
// subsequent calls are no-ops so test cleanups (and any
// defer-on-error patterns in cmd/main.go) don't crash memberlist.
func (n *Node) Stop() {
	if n.dnsCancel != nil {
		n.dnsCancel()
		n.dnsCancel = nil
	}
	n.dnsWG.Wait()
	if ml := n.ml.Swap(nil); ml != nil {
		_ = ml.Leave(5 * time.Second)
		_ = ml.Shutdown()
	}
}

// LocalAddr returns the host:port this node is bound to (post-Start).
func (n *Node) LocalAddr() string {
	ml := n.ml.Load()
	if ml == nil {
		return ""
	}
	addr := ml.LocalNode().Addr.String()
	port := ml.LocalNode().Port
	return fmt.Sprintf("%s:%d", addr, port)
}

// Members returns the current peer list (alive only).
func (n *Node) Members() []string {
	ml := n.ml.Load()
	if ml == nil {
		return nil
	}
	out := make([]string, 0)
	for _, m := range ml.Members() {
		if m.State == memberlist.StateAlive {
			out = append(out, fmt.Sprintf("%s/%s:%d", m.Name, m.Addr, m.Port))
		}
	}
	return out
}

// BroadcastDelta enqueues a delta for gossip. Safe before Start: the
// queue swallows the call silently when no transport is up yet.
func (n *Node) BroadcastDelta(d crdt.Delta) {
	if n.bq == nil {
		return
	}
	payload, err := json.Marshal(envelope{V: 1, Delta: &d})
	if err != nil {
		log.Warnw("cluster: encode delta failed", "err", err.Error())
		return
	}
	n.bq.QueueBroadcast(&simpleBroadcast{payload: payload})
	rvmetrics.GossipMessages.Inc(`direction="out",type="delta"`)
}

func (n *Node) runDNSDiscovery(ctx context.Context) {
	t := time.NewTicker(n.opts.DiscoveryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			peers := n.resolvePeers()
			if len(peers) == 0 {
				continue
			}
			ml := n.ml.Load()
			if ml == nil {
				continue
			}
			if _, err := ml.Join(peers); err != nil {
				log.Warnw("cluster: DNS join error", "err", err.Error())
			}
		}
	}
}

func (n *Node) resolvePeers() []string {
	ips, err := net.LookupHost(n.opts.DiscoveryDNS)
	if err != nil {
		log.Warnw("cluster: DNS lookup failed",
			"name", n.opts.DiscoveryDNS, "err", err.Error())
		return nil
	}
	_, portStr, _ := net.SplitHostPort(n.opts.BindAddr)
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.JoinHostPort(ip, portStr))
	}
	return out
}

// envelope wraps a delta with a version byte so future schema bumps
// stay backwards-compatible.
type envelope struct {
	V     int         `json:"v"`
	Delta *crdt.Delta `json:"delta,omitempty"`
}

type simpleBroadcast struct {
	payload []byte
}

func (b *simpleBroadcast) Invalidates(memberlist.Broadcast) bool { return false }
func (b *simpleBroadcast) Message() []byte                       { return b.payload }
func (b *simpleBroadcast) Finished()                             {}

// delegate fulfils memberlist's Delegate + EventDelegate interfaces.
type delegate struct {
	node *Node
}

func (d *delegate) NodeMeta(limit int) []byte             { return nil }
func (d *delegate) GetBroadcasts(overhead, limit int) [][]byte {
	if d.node.bq == nil {
		return nil
	}
	return d.node.bq.GetBroadcasts(overhead, limit)
}

// NotifyMsg is called for user data sent by another node (broadcasts).
func (d *delegate) NotifyMsg(buf []byte) {
	if len(buf) == 0 {
		return
	}
	rvmetrics.GossipMessages.Inc(`direction="in",type="delta"`)
	cpy := make([]byte, len(buf))
	copy(cpy, buf)
	var env envelope
	if err := json.Unmarshal(cpy, &env); err != nil {
		log.Warnw("cluster: malformed gossip", "err", err.Error())
		return
	}
	if env.V != 1 {
		log.Warnw("cluster: unknown gossip version", "v", env.V)
		return
	}
	if env.Delta == nil {
		return
	}
	changed, err := d.node.opts.Store.ApplyDelta(*env.Delta)
	if err != nil {
		log.Warnw("cluster: bad delta", "err", err.Error())
		if d.node.opts.OnApplyError != nil {
			d.node.opts.OnApplyError(*env.Delta, err)
		}
		return
	}
	if changed && d.node.opts.OnDeltaApplied != nil {
		d.node.opts.OnDeltaApplied()
	}
}

// LocalState is invoked during anti-entropy push/pull; we send the
// whole CRDT FullState so a peer that missed deltas catches up.
func (d *delegate) LocalState(join bool) []byte {
	state := d.node.opts.Store.Snapshot()
	buf, _ := json.Marshal(state)
	return buf
}

// MergeRemoteState applies a peer's full state on top of ours.
func (d *delegate) MergeRemoteState(buf []byte, join bool) {
	if len(buf) == 0 {
		return
	}
	var state crdt.FullState
	if err := json.Unmarshal(buf, &state); err != nil {
		log.Warnw("cluster: bad remote state", "err", err.Error())
		return
	}
	changed := d.node.opts.Store.MergeFull(state)
	if changed > 0 && d.node.opts.OnDeltaApplied != nil {
		d.node.opts.OnDeltaApplied()
	}
}

func (d *delegate) NotifyJoin(n *memberlist.Node) {
	log.Infow("cluster: peer joined", "name", n.Name, "addr", n.Address())
	go d.updateMemberMetric()
}
func (d *delegate) NotifyLeave(n *memberlist.Node) {
	log.Infow("cluster: peer left", "name", n.Name, "addr", n.Address())
	go d.updateMemberMetric()
}
func (d *delegate) NotifyUpdate(n *memberlist.Node) { go d.updateMemberMetric() }

func (d *delegate) updateMemberMetric() {
	ml := d.node.ml.Load()
	if ml == nil {
		return
	}
	alive, suspect, dead, left := 0, 0, 0, 0
	for _, m := range ml.Members() {
		switch m.State {
		case memberlist.StateAlive:
			alive++
		case memberlist.StateSuspect:
			suspect++
		case memberlist.StateDead:
			dead++
		case memberlist.StateLeft:
			left++
		}
	}
	rvmetrics.ClusterMembers.Set(`state="alive"`, int64(alive))
	rvmetrics.ClusterMembers.Set(`state="suspect"`, int64(suspect))
	rvmetrics.ClusterMembers.Set(`state="dead"`, int64(dead))
	rvmetrics.ClusterMembers.Set(`state="left"`, int64(left))
}

// newMemberlistLogShim downgrades memberlist's stdlib-logger output to
// our slog Debug level so we don't pollute INFO logs with peer churn.
func newMemberlistLogShim() *memberlistLog {
	return &memberlistLog{}
}

type memberlistLog struct{}

func (m *memberlistLog) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if line == "" {
		return len(p), nil
	}
	log.Debugw("memberlist", "msg", line)
	return len(p), nil
}
