package configmap

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"request-validator/internal/state"
)

const (
	testNS   = "rv-test"
	testName = "rv-state"
)

func newStore(t *testing.T) (*Store, *fake.Clientset, func()) {
	t.Helper()
	c := fake.NewClientset()
	ctx, cancel := context.WithCancel(context.Background())
	s, err := New(ctx, Options{Client: c, Namespace: testNS, Name: testName})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cleanup := func() {
		_ = s.Close()
		cancel()
	}
	return s, c, cleanup
}

func TestEnsureCreatesEmptyConfigMap(t *testing.T) {
	_, c, cleanup := newStore(t)
	defer cleanup()
	cm, err := c.CoreV1().ConfigMaps(testNS).Get(context.Background(), testName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cm.Data[stateKey]; !ok {
		t.Fatal("expected state.json key")
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	s, _, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()
	payload := json.RawMessage(`{"name":"g1","rules":[]}`)
	if _, err := s.Put(ctx, state.SectionGroups, "g1", payload, ""); err != nil {
		t.Fatal(err)
	}
	// (The fake clientset returns an empty resourceVersion on Update,
	// so we don't assert on the returned revision here. Real
	// kube-apiserver behaviour is covered in the Kind-based E2E
	// suite.)
	waitInformer(t, s, "g1")
	e, err := s.Get(ctx, state.SectionGroups, "g1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(e.Payload) != string(payload) {
		t.Fatalf("payload mismatch: %s", e.Payload)
	}
}

func TestPutIfMatchWildcardOnExistingFails(t *testing.T) {
	s, _, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()
	_, err := s.Put(ctx, state.SectionGroups, "g", json.RawMessage(`{}`), "")
	if err != nil {
		t.Fatal(err)
	}
	waitInformer(t, s, "g")
	if _, err := s.Put(ctx, state.SectionGroups, "g", json.RawMessage(`{}`), "*"); !errors.Is(err, state.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestApiServerConflictBubblesUp(t *testing.T) {
	s, c, cleanup := newStore(t)
	defer cleanup()
	// Force the fake client to return a 409 on the next Update.
	c.PrependReactor("update", "configmaps", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(
			schema.GroupResource{Group: "", Resource: "configmaps"}, testName,
			errors.New("simulated conflict"))
	})
	if _, err := s.Put(context.Background(), state.SectionGroups, "g", json.RawMessage(`{}`), ""); !errors.Is(err, state.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestDeleteThenNotFound(t *testing.T) {
	s, _, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()
	_, _ = s.Put(ctx, state.SectionGroups, "x", json.RawMessage(`{}`), "")
	waitInformer(t, s, "x")
	if err := s.Delete(ctx, state.SectionGroups, "x", ""); err != nil {
		t.Fatal(err)
	}
	// Inferer may still see the value briefly.
	waitInformerGone(t, s, "x")
	if _, err := s.Get(ctx, state.SectionGroups, "x"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSnapshotReadsCache(t *testing.T) {
	s, _, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()
	// Put one entry, wait for the informer to reflect it, then put
	// a second entry and wait for THAT too before snapshotting.
	// Sequential Updates on the fake client are technically each
	// observed by the informer, but the second Update can race the
	// first delivery's processing if we don't gate between them.
	if _, err := s.Put(ctx, state.SectionGroups, "g", json.RawMessage(`{"name":"g"}`), ""); err != nil {
		t.Fatal(err)
	}
	waitInformer(t, s, "g")
	if _, err := s.Put(ctx, state.SectionFacts, "f", json.RawMessage(`{"name":"f"}`), ""); err != nil {
		t.Fatal(err)
	}
	// Snapshot should now contain both entries; wait for the second
	// to propagate as well.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		snap, err := s.Snapshot(ctx)
		if err == nil && snap.Groups["g"] != nil && snap.Facts["f"] != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("informer never reflected both entries")
}

func TestExistingConfigMapIsLoaded(t *testing.T) {
	c := fake.NewClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: testName, Namespace: testNS},
		Data: map[string]string{
			stateKey: `{"version":1,"groups":{"seed":{"name":"seed","rules":[]}}}`,
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := New(ctx, Options{Client: c, Namespace: testNS, Name: testName})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Get(ctx, state.SectionGroups, "seed"); err != nil {
		t.Fatalf("expected seed loaded, got %v", err)
	}
}

func TestWatchDeliversEvents(t *testing.T) {
	// The fake clientset's watch surface does not propagate
	// Updates into the SharedIndexInformer the same way kube-apiserver
	// does; we exercise onChange() directly to verify the fan-out
	// logic. A real cluster (covered by E2E with Kind) is what
	// validates the full informer wiring.
	s, _, cleanup := newStore(t)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := s.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		// Simulate the informer delivering an updated ConfigMap.
		s.onChange(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:            testName,
				Namespace:       testNS,
				ResourceVersion: "42",
			},
			Data: map[string]string{stateKey: `{"version":1}`},
		})
	}()
	select {
	case ev := <-ch:
		if ev.Revision != "42" {
			t.Fatalf("expected revision 42, got %q", ev.Revision)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watch did not deliver")
	}
}

// waitInformer blocks until the informer cache reflects the entry.
func waitInformer(t *testing.T, s *Store, key string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, err := s.Get(context.Background(), state.SectionGroups, key)
		if err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("informer never saw %q", key)
}

func waitInformerGone(t *testing.T, s *Store, key string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, err := s.Get(context.Background(), state.SectionGroups, key)
		if errors.Is(err, state.ErrNotFound) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("informer still sees %q", key)
}

func TestGetMissingNS(t *testing.T) {
	_, c, cleanup := newStore(t)
	defer cleanup()
	// Sanity: the underlying ConfigMap was created in testNS, not in
	// some other namespace.
	if _, err := c.CoreV1().ConfigMaps("other-ns").Get(context.Background(), testName, metav1.GetOptions{}); err == nil {
		t.Fatal("expected the CM to be in testNS only")
	}
}

func TestGetEachSection(t *testing.T) {
	// One subtest per section: the fake clientset + informer combo
	// gets unreliable when writes pile up sequentially against the
	// same ConfigMap without giving the cache time to catch up.
	cases := []struct {
		section, key string
		seed         string
	}{
		{state.SectionGroups, "g", `{"name":"g"}`},
		{state.SectionFacts, "f", `{"name":"f"}`},
		{state.SectionDefaults, "", `{"action":"deny"}`},
		{state.SectionLogging, "", `{"level":"debug"}`},
	}
	for _, c := range cases {
		c := c
		t.Run(c.section, func(t *testing.T) {
			s, _, cleanup := newStore(t)
			defer cleanup()
			ctx := context.Background()
			if _, err := s.Put(ctx, c.section, c.key, json.RawMessage(c.seed), ""); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := s.Get(ctx, c.section, c.key); err == nil {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			t.Fatalf("informer never reflected %s/%s", c.section, c.key)
		})
	}
}

func TestGetUnknownSection(t *testing.T) {
	s, _, cleanup := newStore(t)
	defer cleanup()
	_, err := s.Get(context.Background(), "nope", "key")
	if err == nil {
		t.Fatal("expected error for unknown section")
	}
}

func TestPutUnknownSection(t *testing.T) {
	s, _, cleanup := newStore(t)
	defer cleanup()
	_, err := s.Put(context.Background(), "nope", "k", json.RawMessage(`{}`), "")
	if err == nil {
		t.Fatal("expected error for unknown section")
	}
}

func TestDeleteEachSection(t *testing.T) {
	// Exercise the delete path of every section in isolation so the
	// fake client's informer can resynchronise between writes.
	cases := []struct {
		section, key string
		seed         string
	}{
		{state.SectionGroups, "x", `{"name":"x"}`},
		{state.SectionFacts, "y", `{"name":"y"}`},
		{state.SectionDefaults, "", `{"action":"deny"}`},
		{state.SectionLogging, "", `{"level":"debug"}`},
	}
	for _, c := range cases {
		c := c
		t.Run(c.section, func(t *testing.T) {
			s, _, cleanup := newStore(t)
			defer cleanup()
			ctx := context.Background()
			if _, err := s.Put(ctx, c.section, c.key, json.RawMessage(c.seed), ""); err != nil {
				t.Fatal(err)
			}
			// Wait for the entry to be visible in the cache.
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := s.Get(ctx, c.section, c.key); err == nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err := s.Delete(ctx, c.section, c.key, ""); err != nil {
				t.Fatalf("Delete: %v", err)
			}
		})
	}
}

func TestDeleteMissingReturnsNotFound(t *testing.T) {
	s, _, cleanup := newStore(t)
	defer cleanup()
	if err := s.Delete(context.Background(), state.SectionGroups, "missing", ""); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDeleteUnknownSection(t *testing.T) {
	s, _, cleanup := newStore(t)
	defer cleanup()
	err := s.Delete(context.Background(), "nope", "k", "")
	if err == nil {
		t.Fatal("expected error for unknown section")
	}
}

func TestPutIfMatchExactRevisionConflict(t *testing.T) {
	s, _, cleanup := newStore(t)
	defer cleanup()
	ctx := context.Background()
	_, _ = s.Put(ctx, state.SectionGroups, "g", json.RawMessage(`{"name":"g"}`), "")
	waitInformer(t, s, "g")
	if _, err := s.Put(ctx, state.SectionGroups, "g", json.RawMessage(`{"name":"g"}`), "definitely-stale"); !errors.Is(err, state.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestDecodeCorruptStateJSON(t *testing.T) {
	// Pre-create a CM with invalid JSON in state.json, then ensure
	// Snapshot surfaces the parse error.
	c := fake.NewClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: testName, Namespace: testNS},
		Data:       map[string]string{stateKey: `{not-json`},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := New(ctx, Options{Client: c, Namespace: testNS, Name: testName})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Snapshot(ctx); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestEnsureConfigMapAlreadyExists(t *testing.T) {
	// Pre-create the CM and ensure New() does not error.
	c := fake.NewClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: testName, Namespace: testNS},
		Data:       map[string]string{stateKey: `{"version":1}`},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := New(ctx, Options{Client: c, Namespace: testNS, Name: testName})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer s.Close()
}
