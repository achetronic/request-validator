// Package cluster owns leader election among replicas via a
// Kubernetes Lease. The admin API uses Leader() to decide whether
// to accept a write locally or redirect to whoever currently holds
// the Lease.
//
// In standalone mode (no Kubernetes available) Bootstrap returns a
// degenerate Cluster whose Leader() always reports "self": writes
// are accepted locally with no replication. That keeps the calling
// code symmetric.
//
// The identity we publish into the Lease's HolderIdentity carries
// the holder's admin address so followers can compute the Location
// header for their 307 without an extra round-trip.
package cluster

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"request-validator/internal/log"
)

// Leader summarises who currently holds the Lease.
type Leader struct {
	// Self is true when this replica is the leader.
	Self bool
	// Identity is the HolderIdentity recorded in the Lease, in the
	// form "<podName>|<adminURL>". Empty if no leader is observed.
	Identity string
	// PodName extracted from Identity (best-effort; empty in
	// standalone mode or when the Identity does not parse).
	PodName string
	// AdminURL extracted from Identity (best-effort).
	AdminURL string
	// LeaseUntil is the latest moment the leader's lease is known
	// to be valid (RenewTime + LeaseDuration on the API side).
	LeaseUntil time.Time
}

// Cluster is the running leader election. Always non-nil after
// Bootstrap returns; methods are safe to call concurrently.
type Cluster struct {
	standalone bool
	selfPod    string
	selfAdmin  string

	leader atomic.Pointer[Leader]

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Options configure a Cluster.
type Options struct {
	// Client is the Kubernetes client used to take the Lease.
	// Nil enables standalone mode.
	Client kubernetes.Interface

	// Namespace and LeaseName identify the Lease object.
	Namespace string
	LeaseName string

	// PodName is the human-readable identity (typically os.Hostname()
	// inside k8s). Required even in standalone mode for log lines.
	PodName string

	// AdminURL is "http://<podIP>:<adminPort>"; used by followers
	// to compute the 307 Location header. Required when Client != nil.
	AdminURL string

	// LeaseDuration / RenewDeadline / RetryPeriod follow client-go
	// conventions. Sensible defaults are 15s / 10s / 2s.
	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration

	// OnLeaderChange is invoked whenever leadership transitions.
	// Use it to log, to update metrics, or to trigger work that
	// only the leader should do.
	OnLeaderChange func(Leader)
}

// Bootstrap starts the election (or returns a standalone Cluster
// when Client is nil) and blocks until either the election begins
// running or an error occurs.
func Bootstrap(ctx context.Context, opts Options) (*Cluster, error) {
	c := &Cluster{
		selfPod:   opts.PodName,
		selfAdmin: opts.AdminURL,
	}
	if opts.Client == nil {
		c.standalone = true
		// In standalone mode we are always the leader.
		l := &Leader{Self: true, Identity: opts.PodName, PodName: opts.PodName, AdminURL: opts.AdminURL}
		c.leader.Store(l)
		if opts.OnLeaderChange != nil {
			opts.OnLeaderChange(*l)
		}
		return c, nil
	}
	if opts.Namespace == "" || opts.LeaseName == "" {
		return nil, errors.New("cluster: Namespace and LeaseName are required")
	}
	if opts.PodName == "" {
		return nil, errors.New("cluster: PodName is required")
	}
	if opts.AdminURL == "" {
		return nil, errors.New("cluster: AdminURL is required")
	}
	if opts.LeaseDuration <= 0 {
		opts.LeaseDuration = 15 * time.Second
	}
	if opts.RenewDeadline <= 0 {
		opts.RenewDeadline = 10 * time.Second
	}
	if opts.RetryPeriod <= 0 {
		opts.RetryPeriod = 2 * time.Second
	}

	identity := encodeIdentity(opts.PodName, opts.AdminURL)
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      opts.LeaseName,
			Namespace: opts.Namespace,
		},
		Client: opts.Client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: identity,
		},
	}

	cfg := leaderelection.LeaderElectionConfig{
		Lock:            lock,
		LeaseDuration:   opts.LeaseDuration,
		RenewDeadline:   opts.RenewDeadline,
		RetryPeriod:     opts.RetryPeriod,
		ReleaseOnCancel: true,
		Name:            "request-validator",
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(_ context.Context) {
				l := &Leader{
					Self:       true,
					Identity:   identity,
					PodName:    opts.PodName,
					AdminURL:   opts.AdminURL,
					LeaseUntil: time.Now().Add(opts.LeaseDuration),
				}
				c.leader.Store(l)
				log.Infow("cluster: became leader", "pod", opts.PodName)
				if opts.OnLeaderChange != nil {
					opts.OnLeaderChange(*l)
				}
			},
			OnStoppedLeading: func() {
				// We may be still alive but lost the lease; flip our
				// snapshot to "I am a follower" with an unknown
				// identity until the next OnNewLeader fires.
				l := &Leader{Self: false}
				c.leader.Store(l)
				log.Warnw("cluster: stopped leading", "pod", opts.PodName)
				if opts.OnLeaderChange != nil {
					opts.OnLeaderChange(*l)
				}
			},
			OnNewLeader: func(newIdentity string) {
				pod, admin := decodeIdentity(newIdentity)
				self := newIdentity == identity
				l := &Leader{
					Self:       self,
					Identity:   newIdentity,
					PodName:    pod,
					AdminURL:   admin,
					LeaseUntil: time.Now().Add(opts.LeaseDuration),
				}
				c.leader.Store(l)
				log.Infow("cluster: leader observed",
					"leader_pod", pod, "leader_admin", admin, "self", self)
				if opts.OnLeaderChange != nil {
					opts.OnLeaderChange(*l)
				}
			},
		},
	}

	le, err := leaderelection.NewLeaderElector(cfg)
	if err != nil {
		return nil, fmt.Errorf("cluster: new elector: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		// LeaderElector.Run blocks; restart on context-cancellation
		// is handled by the parent ctx.
		le.Run(runCtx)
	}()
	return c, nil
}

// Stop releases the Lease (when leader) and joins the background
// goroutine.
func (c *Cluster) Stop() {
	if c == nil || c.standalone {
		return
	}
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
}

// Leader returns the current view of the cluster. Cheap; safe from
// the request hot path.
func (c *Cluster) Leader() Leader {
	if c == nil {
		return Leader{}
	}
	if c.standalone {
		return Leader{Self: true, PodName: c.selfPod, AdminURL: c.selfAdmin, Identity: c.selfPod}
	}
	if p := c.leader.Load(); p != nil {
		return *p
	}
	return Leader{}
}

// IsLeader is shorthand for Leader().Self.
func (c *Cluster) IsLeader() bool { return c.Leader().Self }

// Standalone reports whether the cluster runs without Kubernetes.
func (c *Cluster) Standalone() bool {
	if c == nil {
		return true
	}
	return c.standalone
}

func encodeIdentity(pod, adminURL string) string {
	return pod + "|" + adminURL
}

func decodeIdentity(identity string) (pod, adminURL string) {
	i := strings.IndexByte(identity, '|')
	if i < 0 {
		return identity, ""
	}
	return identity[:i], identity[i+1:]
}
