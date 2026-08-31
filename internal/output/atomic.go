package output

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrTargetExists = errors.New("output file already exists")

func WriteAtomic(path string, content []byte, force bool) error {
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".sing-box-redact-*.tmp")
	if err != nil {
		return fmt.Errorf("create output temp file: %w", err)
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	if err = temp.Chmod(0o600); err != nil {
		return fmt.Errorf("secure output temp file: %w", err)
	}
	if _, err = temp.Write(content); err != nil {
		return fmt.Errorf("write output temp file: %w", err)
	}
	if err = temp.Sync(); err != nil {
		return fmt.Errorf("sync output temp file: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("close output temp file: %w", err)
	}
	if force {
		if err = replaceFile(tempPath, path); err != nil {
			return fmt.Errorf("replace output file: %w", err)
		}
		committed = true
		return nil
	}
	if err = os.Link(tempPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrTargetExists
		}
		return fmt.Errorf("commit output file without overwrite: %w", err)
	}
	committed = true
	if err = os.Remove(tempPath); err != nil {
		return fmt.Errorf("remove output temp link: %w", err)
	}
	return nil
}
