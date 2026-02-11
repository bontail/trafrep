package integration_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"trafRep/test/integration"
)

const ContainerDumpPath = "/tmp/backup.sql"
const HostDumpPathPrefix = "/tmp/trafrep/"

type ReplayTestCase struct {
	PcapFile     string
	ExpectedDump string
}

func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	cmd := exec.Command("docker", "version")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func RunReplay(t *testing.T, tc ReplayTestCase) {
	ctx := context.Background()

	if !dockerAvailable() {
		t.Skip("docker not available, skipping integration test")
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "postgres:15-alpine",
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_HOST_AUTH_METHOD": "trust",
				"POSTGRES_PASSWORD":         "postgres",
				"POSTGRES_USER":             "postgres",
			},
			WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(3000 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("failed to start container: %v", err)
	}
	defer container.Terminate(ctx)

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("failed to get mapped port: %v", err)
	}

	dsn := fmt.Sprintf("postgres://postgres:postgres@%s:%s/postgres?sslmode=disable", host, port.Port())
	pgxConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("failed to connect with pgx: %v", err)
	}
	defer pgxConn.Close(ctx)
	for i := 0; i < 10; i++ {
		err = pgxConn.Ping(ctx)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		t.Fatalf("db not ready: %v", err)
	}

	pcapPath := filepath.Join("./../../testdata/pcaps", tc.PcapFile)
	cmd := exec.Command("go", "run", "./../../main.go", "replay", "--pcap", pcapPath, "--target-host", host, "--target-port", port.Port(), "--print-query")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("replay failed: %v\nOutput: %s", err, string(output))
	}

	exitCode, _, stderr := container.Exec(ctx, []string{
		"pg_dump",
		"-U", "postgres",
		"-d", "postgres",
		"-f", ContainerDumpPath,
		"--data-only",
		"--inserts",
		"--column-inserts",
		"--no-owner",
		"--no-privileges",
		"--no-comments",
		"--disable-triggers",
		"--no-publications",
		"--no-subscriptions",
	})
	if exitCode != 0 {
		t.Fatalf("pg_dump exit=%d stderr=%s", exitCode, stderr)
	}

	if err = integration.CopyDumpFromContainer(ctx, container, ContainerDumpPath, HostDumpPathPrefix+container.GetContainerID()); err != nil {
		log.Fatalf("copy dump failed: %v", err)
	}

	if err = integration.RemoveRestrictLines(HostDumpPathPrefix + container.GetContainerID()); err != nil {
		log.Fatalf("remove restrict lines failed: %v", err)
	}

	expectedPath := filepath.Join("./../../testdata/dumps", tc.ExpectedDump)

	cmd = exec.Command("diff", "-u", expectedPath, HostDumpPathPrefix+container.GetContainerID())
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("diff failed: %v\nOutput: %s", err, string(output))
	}
}

func TestReplay(t *testing.T) {
	entries, err := os.ReadDir("./../../testdata/pcaps")
	if err != nil {
		log.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		testName := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		t.Run(testName, func(t *testing.T) {
			tc := ReplayTestCase{
				PcapFile:     testName + ".pcap",
				ExpectedDump: testName + ".sql",
			}
			RunReplay(t, tc)
		})
	}
}
