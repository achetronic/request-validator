package quarantine

import (
	"testing"
	"time"
)

func TestPushAndList(t *testing.T) {
	b := New()
	b.Push("groups", "g1", "compile failed")
	b.Push("facts", "f1", "missing url")
	list := b.List()
	if len(list) != 2 {
		t.Fatalf("expected 2, got %d", len(list))
	}
	if list[0].Section != "facts" || list[1].Section != "groups" {
		t.Fatalf("expected sorted by section, got %+v", list)
	}
}

func TestPushSameKeyIncrementsRetry(t *testing.T) {
	b := New()
	b.Push("groups", "g1", "first")
	b.Push("groups", "g1", "second")
	list := b.List()
	if len(list) != 1 {
		t.Fatalf("expected 1, got %d", len(list))
	}
	if list[0].RetryCount != 1 {
		t.Fatalf("expected retryCount=1, got %d", list[0].RetryCount)
	}
	if list[0].Reason != "second" {
		t.Fatalf("expected updated reason, got %q", list[0].Reason)
	}
}

func TestRemove(t *testing.T) {
	b := New()
	b.Push("groups", "g1", "x")
	if !b.Remove("groups", "g1") {
		t.Fatal("expected remove to report true")
	}
	if b.Len() != 0 {
		t.Fatal("expected empty after remove")
	}
}

func TestDrainKeepsAndRemoves(t *testing.T) {
	b := New()
	b.Push("groups", "g1", "x")
	b.Push("groups", "g2", "y")
	removed := b.Drain(func(e Entry) bool { return e.Key == "g2" })
	if len(removed) != 1 || removed[0].Key != "g1" {
		t.Fatalf("expected g1 removed, got %+v", removed)
	}
	if b.Len() != 1 || !b.Has("groups", "g2") {
		t.Fatal("expected g2 retained")
	}
}

func TestHas(t *testing.T) {
	b := New()
	b.Push("defaults", "", "bad")
	if !b.Has("defaults", "") {
		t.Fatal("expected singleton stored under empty key")
	}
	if b.Has("groups", "") {
		t.Fatal("must not match other sections")
	}
}

func TestSetClockUsedForSince(t *testing.T) {
	b := New()
	called := 0
	b.SetClock(func() time.Time {
		called++
		return time.Unix(int64(42+called), 0)
	})
	b.Push("groups", "k", "first")
	list := b.List()
	if list[0].Since.Unix() != 43 {
		t.Fatalf("expected since=43, got %d", list[0].Since.Unix())
	}
	if list[0].LastRetry.Unix() != 43 {
		t.Fatalf("expected lastRetry=43, got %d", list[0].LastRetry.Unix())
	}
}

func TestPushPreservesSinceOnRetry(t *testing.T) {
	b := New()
	tick := 0
	b.SetClock(func() time.Time {
		tick++
		return time.Unix(int64(tick), 0)
	})
	b.Push("groups", "k", "first") // since=1
	b.Push("groups", "k", "later") // lastRetry=2
	list := b.List()
	if list[0].Since.Unix() != 1 {
		t.Fatalf("since should be preserved across retries, got %d", list[0].Since.Unix())
	}
	if list[0].LastRetry.Unix() != 2 {
		t.Fatalf("lastRetry should advance, got %d", list[0].LastRetry.Unix())
	}
}
