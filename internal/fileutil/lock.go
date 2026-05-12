package fileutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Lock struct {
	path string
	file *os.File
}

func AcquireLock(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("creating lock directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("lock already exists at %s", path)
		}
		return nil, fmt.Errorf("creating lock %q: %w", path, err)
	}
	_, _ = fmt.Fprintf(file, "%d\n", os.Getpid())
	return &Lock{path: path, file: file}, nil
}

func (l *Lock) Release() error {
	if l == nil {
		return nil
	}
	var err error
	if l.file != nil {
		err = l.file.Close()
	}
	if rmErr := os.Remove(l.path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) && err == nil {
		err = rmErr
	}
	return err
}

