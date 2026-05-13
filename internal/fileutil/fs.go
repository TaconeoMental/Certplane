package fileutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("stat %q: %w", path, err)
}

// Safely replaces a file avoiding partial writes.
//
// The data is written to a temporary file in the same directory and then renamed
// to the target path. Becasus rename is atomic con POSIX, a reader will either
// see the previous file or the complete new file.
//
// This is used for certs and keys to avoid corrupt or truncated PEM files if the
// agent crashesor a service reloads while files are being updated.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating directory %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".certplane-*")
	if err != nil {
		return fmt.Errorf("creating temp file in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temp file %q: %w", tmpName, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file %q: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file %q: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file %q: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("renaming %q to %q: %w", tmpName, path, err)
	}
	removeTemp = false

	if err := syncDir(dir); err != nil {
		return fmt.Errorf("syncing directory after rename: %w", err)
	}

	return nil
}

func syncDir(dir string) error {
	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("opening directory %q: %w", dir, err)
	}
	defer dirHandle.Close()

	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("syncing directory %q: %w", dir, err)
	}

	return nil
}
