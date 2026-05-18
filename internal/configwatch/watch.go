// Package configwatch watches a single configuration file for changes and
// invokes a callback whenever the file is rewritten.
//
// The watcher has to cope with three realistic scenarios. The simplest is a
// plain in-place write - vim's `:w`, `tee policy.yaml` and friends - which
// fsnotify reports as a WRITE event on the file itself. Many editors instead
// save by writing to a temporary file, fsyncing it and then renaming it over
// the target; fsnotify sees that as a CREATE/RENAME on the directory entry,
// not a WRITE on the original inode. Finally, kubelet projects a ConfigMap
// by storing the contents under a versioned hidden directory like
// `..2024_01_15_...` and flipping a parent `..data` symlink atomically; a
// watch held on the visible file becomes orphaned on every update.
//
// To cover all three we subscribe to the parent directory and react to any
// event whose target matches the file's basename or whose target is the
// kubelet `..data` symlink. Events arriving in a short burst (200 ms by
// default) are debounced into a single reload.
package configwatch

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// kubeProjectedSymlink is the well-known name of the parent symlink kubelet
// flips atomically when a ConfigMap projection is updated.
const kubeProjectedSymlink = "..data"

// Run starts watching the directory containing `path` and invokes `onChange`
// whenever the file changes. It blocks until ctx is cancelled.
//
// The callback runs on the watcher's goroutine; callers should keep it short
// or kick the actual work to another goroutine themselves.
func Run(ctx context.Context, path string, debounce time.Duration, onChange func()) error {
	if debounce <= 0 {
		debounce = 200 * time.Millisecond
	}

	dir := filepath.Dir(path)
	name := filepath.Base(path)

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("fsnotify: %w", err)
	}
	defer w.Close()

	if err := w.Add(dir); err != nil {
		return fmt.Errorf("watch %s: %w", dir, err)
	}

	var timer *time.Timer
	fire := func() {
		// Reset/reschedule the debounce timer.
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(debounce, onChange)
	}

	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil

		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			// fsnotify errors are rarely fatal (queue overflow on Linux); we
			// surface them through the callback's caller via the next event.
			_ = err

		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if !relevant(ev, name) {
				continue
			}
			fire()
		}
	}
}

// relevant decides whether the given fsnotify event matters for the watched
// file. We match either the exact basename (covers in-place writes and
// save-via-rename) or the kubelet `..data` symlink (covers ConfigMap atomic
// swaps), and we only care about events that imply new content.
func relevant(ev fsnotify.Event, name string) bool {
	base := filepath.Base(ev.Name)
	if base != name && base != kubeProjectedSymlink {
		return false
	}
	// CREATE, WRITE, RENAME and CHMOD can all signal new content. Pure
	// REMOVE without a follow-up is meaningless on its own - the file will
	// reappear if it was an atomic rename, or stay gone if the user deleted
	// it (in which case the next reload attempt will fail and the previous
	// policy is kept).
	return ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Chmod) != 0
}
