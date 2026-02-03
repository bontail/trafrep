package integration

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type ReplayTestCase struct {
	PcapFile        string
	PreparedQueries []string
	CheckFunc       func(ctx context.Context, conn *pgx.Conn) error
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

	for _, q := range tc.PreparedQueries {
		_, err := pgxConn.Exec(ctx, q)
		if err != nil {
			t.Fatalf("prepared query failed: %v\nQuery: %s", err, q)
		}
	}

	pcapPath := filepath.Join("./../../../../testdata", tc.PcapFile)
	cmd := exec.Command("go", "run", "./../../../../main.go", "replay", "--pcap", pcapPath, "--target-host", host, "--target-port", port.Port(), "--print-query")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("replay failed: %v\nOutput: %s", err, string(output))
	}

	if err = tc.CheckFunc(ctx, pgxConn); err != nil {
		t.Errorf("check failed %s for test case: %s", err, tc.PcapFile)
	}
}
