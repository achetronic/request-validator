package cluster

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

func TestStandaloneIsAlwaysLeader(t *testing.T) {
	c, err := Bootstrap(context.Background(), Options{PodName: "self", AdminURL: "http://127.0.0.1:8081"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	if !c.IsLeader() {
		t.Fatal("standalone should always be leader")
	}
	if !c.Standalone() {
		t.Fatal("standalone should report Standalone()==true")
	}
	l := c.Leader()
	if l.PodName != "self" || l.AdminURL != "http://127.0.0.1:8081" {
		t.Fatalf("unexpected leader %+v", l)
	}
}

func TestKubernetesLeaderElectionAcquires(t *testing.T) {
	client := fake.NewClientset()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c, err := Bootstrap(ctx, Options{
		Client:        client,
		Namespace:     "default",
		LeaseName:     "rv-leader",
		PodName:       "pod-A",
		AdminURL:      "http://10.0.0.1:8081",
		LeaseDuration: 2 * time.Second,
		RenewDeadline: time.Second,
		RetryPeriod:   200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.IsLeader() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("pod-A never became leader; current=%+v", c.Leader())
}

func TestIdentityEncodeDecode(t *testing.T) {
	enc := encodeIdentity("pod-7", "http://1.2.3.4:8081")
	pod, admin := decodeIdentity(enc)
	if pod != "pod-7" || admin != "http://1.2.3.4:8081" {
		t.Fatalf("decode mismatch: %q %q", pod, admin)
	}
	// Malformed identity (no separator) becomes pod-only.
	pod, admin = decodeIdentity("bare")
	if pod != "bare" || admin != "" {
		t.Fatalf("decode of bare identity: %q %q", pod, admin)
	}
}
