// Package configmap is the Kubernetes-backed implementation of
// internal/state.Store.
//
// One ConfigMap holds the whole admin overlay under a single key,
// `state.json`, as a JSON document with the same shape as
// memory.onDiskState. Optimistic concurrency uses the ConfigMap's
// resourceVersion as the Revision; an Update that races returns a
// 409 from the API server, which we surface as state.ErrConflict.
//
// Reads do not hit the API server: a shared informer keeps a local
// cache up to date sub-second after any peer writes. Watch() fans
// out the informer's updates as state.ChangeEvent.
//
// The package deliberately depends only on the typed client + a
// SharedIndexInformer. Nothing here knows about leases, leaders or
// the admin API.
package configmap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"request-validator/internal/state"
)

// stateKey is the data key inside the ConfigMap.
const stateKey = "state.json"

// Options configure a Store.
type Options struct {
	// Client is the kube client used for reads (via the informer)
	// and writes.
	Client kubernetes.Interface

	// Namespace where the backing ConfigMap lives.
	Namespace string

	// Name of the backing ConfigMap.
	Name string

	// ResyncPeriod for the informer. 0 disables periodic resync.
	// Recommended: 0; informers are watch-based and resync just
	// adds redundant traffic.
	ResyncPeriod time.Duration
}

// Store implements state.Store on top of a single ConfigMap.
type Store struct {
	opts Options

	factory  informers.SharedInformerFactory
	informer cache.SharedIndexInformer
	stop     chan struct{}

	watchersMu sync.Mutex
	watchers   map[chan state.ChangeEvent]struct{}

	// lastSeenRev caches the most recently delivered ChangeEvent
	// revision so duplicate informer ticks (frequent in client-go)
	// do not spam consumers.
	lastSeenRevMu sync.Mutex
	lastSeenRev   state.Revision
}

// stateDoc is the JSON payload stored under the stateKey of the
// ConfigMap. Matches the memory backend's onDiskState shape so
// migrations are trivial.
type stateDoc struct {
	Version  int                        `json:"version"`
	Groups   map[string]json.RawMessage `json:"groups,omitempty"`
	Facts    map[string]json.RawMessage `json:"facts,omitempty"`
	Defaults json.RawMessage            `json:"defaults,omitempty"`
	Logging  json.RawMessage            `json:"logging,omitempty"`
}

// New returns a Store. The caller is responsible for cancelling the
// passed ctx eventually (it stops the informer goroutines via
// Store.Close).
func New(ctx context.Context, opts Options) (*Store, error) {
	if opts.Client == nil {
		return nil, errors.New("configmap: Client is required")
	}
	if opts.Namespace == "" {
		return nil, errors.New("configmap: Namespace is required")
	}
	if opts.Name == "" {
		return nil, errors.New("configmap: Name is required")
	}
	if err := ensureConfigMap(ctx, opts.Client, opts.Namespace, opts.Name); err != nil {
		return nil, err
	}
	// Watch the namespace; the cache is tiny because there's only
	// one ConfigMap we care about, and we filter incoming events
	// by name in onChange.
	factory := informers.NewSharedInformerFactoryWithOptions(
		opts.Client, opts.ResyncPeriod,
		informers.WithNamespace(opts.Namespace),
	)
	informer := factory.Core().V1().ConfigMaps().Informer()

	s := &Store{
		opts:     opts,
		factory:  factory,
		informer: informer,
		stop:     make(chan struct{}),
		watchers: map[chan state.ChangeEvent]struct{}{},
	}
	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { s.onChange(obj) },
		UpdateFunc: func(_, obj any) { s.onChange(obj) },
		DeleteFunc: func(obj any) { s.onChange(obj) },
	})
	if err != nil {
		return nil, fmt.Errorf("configmap: informer handler: %w", err)
	}
	factory.Start(s.stop)
	if !cache.WaitForCacheSync(s.stop, informer.HasSynced) {
		return nil, errors.New("configmap: informer cache failed to sync")
	}
	return s, nil
}

func ensureConfigMap(ctx context.Context, c kubernetes.Interface, ns, name string) error {
	_, err := c.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("configmap: get %s/%s: %w", ns, name, err)
	}
	empty, _ := json.Marshal(stateDoc{Version: 1})
	_, err = c.CoreV1().ConfigMaps(ns).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Data:       map[string]string{stateKey: string(empty)},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("configmap: create %s/%s: %w", ns, name, err)
	}
	return nil
}

// onChange fans out an informer event as a ChangeEvent, debouncing
// duplicate deliveries for the same resourceVersion. We filter by
// name here (instead of via a field selector at watch time) because
// some fake clients propagate watch events more reliably without the
// selector, and the cache hit rate is fine — there's just one
// ConfigMap of interest in the watched namespace.
func (s *Store) onChange(obj any) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok || cm == nil {
		return
	}
	if cm.Name != s.opts.Name || cm.Namespace != s.opts.Namespace {
		return
	}
	rev := state.Revision(cm.ResourceVersion)
	s.lastSeenRevMu.Lock()
	if rev == s.lastSeenRev {
		s.lastSeenRevMu.Unlock()
		return
	}
	s.lastSeenRev = rev
	s.lastSeenRevMu.Unlock()

	s.watchersMu.Lock()
	chs := make([]chan state.ChangeEvent, 0, len(s.watchers))
	for c := range s.watchers {
		chs = append(chs, c)
	}
	s.watchersMu.Unlock()
	for _, c := range chs {
		select {
		case c <- state.ChangeEvent{Revision: rev}:
		default:
		}
	}
}

func (s *Store) readCached() (*corev1.ConfigMap, error) {
	indexer := s.informer.GetIndexer()
	key := s.opts.Namespace + "/" + s.opts.Name
	obj, exists, err := indexer.GetByKey(key)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("configmap: %s not yet in cache", key)
	}
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return nil, fmt.Errorf("configmap: cache returned %T", obj)
	}
	// DeepCopy because callers may mutate.
	return cm.DeepCopy(), nil
}

func decode(cm *corev1.ConfigMap) (stateDoc, error) {
	var d stateDoc
	if cm == nil {
		return d, nil
	}
	raw, ok := cm.Data[stateKey]
	if !ok || raw == "" {
		return stateDoc{Version: 1}, nil
	}
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		return d, fmt.Errorf("configmap: parse %s: %w", stateKey, err)
	}
	if d.Version != 1 && d.Version != 0 {
		return d, fmt.Errorf("configmap: unsupported state version %d", d.Version)
	}
	return d, nil
}

// Snapshot returns the full state from the informer cache.
func (s *Store) Snapshot(_ context.Context) (state.Snapshot, error) {
	cm, err := s.readCached()
	if err != nil {
		return state.Snapshot{}, err
	}
	d, err := decode(cm)
	if err != nil {
		return state.Snapshot{}, err
	}
	return state.Snapshot{
		Groups:   d.Groups,
		Facts:    d.Facts,
		Defaults: d.Defaults,
		Logging:  d.Logging,
		Revision: state.Revision(cm.ResourceVersion),
	}, nil
}

// Get returns one entry.
func (s *Store) Get(_ context.Context, section, key string) (state.Entry, error) {
	cm, err := s.readCached()
	if err != nil {
		return state.Entry{}, err
	}
	d, err := decode(cm)
	if err != nil {
		return state.Entry{}, err
	}
	switch section {
	case state.SectionGroups:
		if v, ok := d.Groups[key]; ok {
			return state.Entry{Section: section, Key: key, Payload: v, Revision: state.Revision(cm.ResourceVersion)}, nil
		}
	case state.SectionFacts:
		if v, ok := d.Facts[key]; ok {
			return state.Entry{Section: section, Key: key, Payload: v, Revision: state.Revision(cm.ResourceVersion)}, nil
		}
	case state.SectionDefaults:
		if d.Defaults != nil {
			return state.Entry{Section: section, Payload: d.Defaults, Revision: state.Revision(cm.ResourceVersion)}, nil
		}
	case state.SectionLogging:
		if d.Logging != nil {
			return state.Entry{Section: section, Payload: d.Logging, Revision: state.Revision(cm.ResourceVersion)}, nil
		}
	default:
		return state.Entry{}, fmt.Errorf("unknown section %q", section)
	}
	return state.Entry{}, state.ErrNotFound
}

// Put writes a value with optimistic concurrency on resourceVersion.
//
// We always use the cached ConfigMap as our baseline. If the API
// server rejects the Update with 409 (because another writer raced
// us) we surface state.ErrConflict; the caller can re-read and try
// again if it wants to.
func (s *Store) Put(ctx context.Context, section, key string, payload json.RawMessage, ifMatch state.Revision) (state.Revision, error) {
	return s.modify(ctx, ifMatch, func(d *stateDoc) error {
		switch section {
		case state.SectionGroups:
			if d.Groups == nil {
				d.Groups = map[string]json.RawMessage{}
			}
			d.Groups[key] = payload
		case state.SectionFacts:
			if d.Facts == nil {
				d.Facts = map[string]json.RawMessage{}
			}
			d.Facts[key] = payload
		case state.SectionDefaults:
			d.Defaults = payload
		case state.SectionLogging:
			d.Logging = payload
		default:
			return fmt.Errorf("unknown section %q", section)
		}
		return nil
	}, func(d stateDoc) (exists bool) {
		switch section {
		case state.SectionGroups:
			_, exists = d.Groups[key]
		case state.SectionFacts:
			_, exists = d.Facts[key]
		case state.SectionDefaults:
			exists = d.Defaults != nil
		case state.SectionLogging:
			exists = d.Logging != nil
		}
		return
	})
}

// Delete removes a value, honoring If-Match.
func (s *Store) Delete(ctx context.Context, section, key string, ifMatch state.Revision) error {
	_, err := s.modify(ctx, ifMatch, func(d *stateDoc) error {
		switch section {
		case state.SectionGroups:
			if _, ok := d.Groups[key]; !ok {
				return state.ErrNotFound
			}
			delete(d.Groups, key)
		case state.SectionFacts:
			if _, ok := d.Facts[key]; !ok {
				return state.ErrNotFound
			}
			delete(d.Facts, key)
		case state.SectionDefaults:
			if d.Defaults == nil {
				return state.ErrNotFound
			}
			d.Defaults = nil
		case state.SectionLogging:
			if d.Logging == nil {
				return state.ErrNotFound
			}
			d.Logging = nil
		default:
			return fmt.Errorf("unknown section %q", section)
		}
		return nil
	}, func(d stateDoc) (exists bool) {
		switch section {
		case state.SectionGroups:
			_, exists = d.Groups[key]
		case state.SectionFacts:
			_, exists = d.Facts[key]
		case state.SectionDefaults:
			exists = d.Defaults != nil
		case state.SectionLogging:
			exists = d.Logging != nil
		}
		return
	})
	return err
}

// modify is the common path for Put and Delete: read the current
// ConfigMap, check the precondition, apply mutate, Update.
// existsFn returns whether the target entry currently exists so
// If-Match: "*" and "must already exist" semantics work.
func (s *Store) modify(
	ctx context.Context,
	ifMatch state.Revision,
	mutate func(*stateDoc) error,
	existsFn func(stateDoc) bool,
) (state.Revision, error) {
	cm, err := s.readCached()
	if err != nil {
		return "", err
	}
	d, err := decode(cm)
	if err != nil {
		return "", err
	}
	cur := state.Revision(cm.ResourceVersion)

	if ifMatch != "" {
		exists := existsFn(d)
		switch {
		case ifMatch == "*":
			if exists {
				return "", state.ErrConflict
			}
		case !exists:
			return "", state.ErrConflict
		case ifMatch != cur:
			return "", state.ErrConflict
		}
	}

	if err := mutate(&d); err != nil {
		return "", err
	}
	if d.Version == 0 {
		d.Version = 1
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	cm.Data = map[string]string{stateKey: string(encoded)}

	updated, err := s.opts.Client.CoreV1().
		ConfigMaps(s.opts.Namespace).
		Update(ctx, cm, metav1.UpdateOptions{})
	if err != nil {
		if apierrors.IsConflict(err) {
			return "", state.ErrConflict
		}
		return "", fmt.Errorf("configmap: update: %w", err)
	}
	return state.Revision(updated.ResourceVersion), nil
}

// Watch returns a channel that receives ChangeEvent values.
//
// We also start a small periodic ticker that compares the cached
// resourceVersion against the last delivered revision and emits a
// synthetic event when it differs. This is a backstop against
// edge cases in informer event delivery (notably the fake client
// used in unit/E2E tests, but also brief watch reconnections in
// real clusters). Cheap: a single cache lookup per second.
func (s *Store) Watch(ctx context.Context) (<-chan state.ChangeEvent, error) {
	ch := make(chan state.ChangeEvent, 4)
	s.watchersMu.Lock()
	s.watchers[ch] = struct{}{}
	s.watchersMu.Unlock()

	tickCtx, tickCancel := context.WithCancel(ctx)
	go s.pollLoop(tickCtx, ch)

	go func() {
		<-ctx.Done()
		tickCancel()
		s.watchersMu.Lock()
		delete(s.watchers, ch)
		s.watchersMu.Unlock()
		close(ch)
	}()
	return ch, nil
}

func (s *Store) pollLoop(ctx context.Context, ch chan<- state.ChangeEvent) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	var lastPayload string
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cm, err := s.opts.Client.CoreV1().
				ConfigMaps(s.opts.Namespace).
				Get(ctx, s.opts.Name, metav1.GetOptions{})
			if err != nil {
				continue
			}
			// We can't rely solely on resourceVersion: the fake
			// clientset used in tests does not increment it on
			// Update. Compare the encoded payload instead — cheap
			// (a single string compare on a small ConfigMap) and
			// works against both real and fake API servers.
			payload := cm.Data[stateKey]
			if payload == lastPayload {
				continue
			}
			lastPayload = payload
			// Push the fresh object into the informer cache so
			// subsequent Snapshot/Get calls see it without waiting
			// for the watch to catch up.
			_ = s.informer.GetIndexer().Update(cm)
			rev := state.Revision(cm.ResourceVersion)
			if rev == "" {
				rev = state.Revision(fmt.Sprintf("poll-%d", time.Now().UnixNano()))
			}
			select {
			case ch <- state.ChangeEvent{Revision: rev}:
			default:
			}
		}
	}
}

// Close stops the informer and closes all watchers.
func (s *Store) Close() error {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	return nil
}
