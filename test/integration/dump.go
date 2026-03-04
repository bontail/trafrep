package integration

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/testcontainers/testcontainers-go"
)

func RemoveRestrictLines(path string) error {
	input, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var out []string
	scanner := bufio.NewScanner(bytes.NewReader(input))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, `\restrict `) || strings.HasPrefix(line, `\unrestrict`) {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(strings.Join(out, "\n")), 0644)
}

func CopyDumpFromContainer(
	ctx context.Context,
	container testcontainers.Container,
	containerPath string,
	hostPath string,
) error {

	reader, err := container.CopyFileFromContainer(ctx, containerPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	if err := os.MkdirAll(filepath.Dir(hostPath), 0755); err != nil {
		return err
	}
	out, err := os.Create(hostPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, reader)
	return err
}
