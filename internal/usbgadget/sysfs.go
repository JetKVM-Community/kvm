package usbgadget

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jetkvm/kvm/internal/sync"
)

// Every path managed by the gadget changeset lives under sysfs: the configfs
// tree at /sys/kernel/config and the dwc3 bind/unbind files. All file
// operations go through an os.Root scoped to /sys so that a symlink inside
// configfs can never redirect an operation to a path outside of it.
const sysfsRootPath = "/sys"

var (
	sysfsRoot     *os.Root
	sysfsRootLock sync.Mutex
)

func getSysfsRoot() (*os.Root, error) {
	sysfsRootLock.Lock()
	defer sysfsRootLock.Unlock()

	if sysfsRoot == nil {
		root, err := os.OpenRoot(sysfsRootPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %w", sysfsRootPath, err)
		}
		sysfsRoot = root
	}

	return sysfsRoot, nil
}

// sysfsResolve translates an absolute path under /sys into the sysfs root and
// a path relative to it.
func sysfsResolve(path string) (*os.Root, string, error) {
	root, err := getSysfsRoot()
	if err != nil {
		return nil, "", err
	}

	rel, err := filepath.Rel(sysfsRootPath, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, "", fmt.Errorf("path %s is outside of %s", path, sysfsRootPath)
	}

	return root, rel, nil
}

func sysfsLstat(path string) (os.FileInfo, error) {
	root, rel, err := sysfsResolve(path)
	if err != nil {
		return nil, err
	}
	return root.Lstat(rel)
}

func sysfsReadFile(path string) ([]byte, error) {
	root, rel, err := sysfsResolve(path)
	if err != nil {
		return nil, err
	}
	return root.ReadFile(rel)
}

func sysfsWriteFile(path string, data []byte, perm os.FileMode) error {
	root, rel, err := sysfsResolve(path)
	if err != nil {
		return err
	}
	return root.WriteFile(rel, data, perm)
}

func sysfsReadlink(path string) (string, error) {
	root, rel, err := sysfsResolve(path)
	if err != nil {
		return "", err
	}
	return root.Readlink(rel)
}

// sysfsReadDir returns the directory entries sorted by filename, matching
// os.ReadDir.
func sysfsReadDir(path string) ([]os.DirEntry, error) {
	root, rel, err := sysfsResolve(path)
	if err != nil {
		return nil, err
	}

	dir, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})
	return entries, nil
}

func sysfsSymlink(target string, path string) error {
	root, rel, err := sysfsResolve(path)
	if err != nil {
		return err
	}
	// the target is stored verbatim, so it may keep pointing at the
	// absolute configfs function path the kernel expects
	return root.Symlink(target, rel)
}

func sysfsRemove(path string) error {
	root, rel, err := sysfsResolve(path)
	if err != nil {
		return err
	}
	return root.Remove(rel)
}

func sysfsRemoveAll(path string) error {
	root, rel, err := sysfsResolve(path)
	if err != nil {
		return err
	}
	return root.RemoveAll(rel)
}

func sysfsMkdirAll(path string, perm os.FileMode) error {
	root, rel, err := sysfsResolve(path)
	if err != nil {
		return err
	}
	return root.MkdirAll(rel, perm)
}

func sysfsChtimes(path string, atime time.Time, mtime time.Time) error {
	root, rel, err := sysfsResolve(path)
	if err != nil {
		return err
	}
	return root.Chtimes(rel, atime, mtime)
}
