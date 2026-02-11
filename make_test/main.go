package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"trafRep/test/integration"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	name              = "distinct_and_order_by"
	containerDumpPath = "/tmp/backup.sql"
	hostDumpPath      = "./testdata/dumps/" + name + ".sql"

	containerPcapPath = "/tmp/pg_traffic.pcap"
	hostPcapPath      = "./testdata/pcaps/" + name + ".pcap"
)

func runSQL(db *sql.DB) {
	db.Exec("CREATE TABLE events (id SERIAL PRIMARY KEY, event_type VARCHAR(50), created_at TIMESTAMP)")
	db.Exec("INSERT INTO events (event_type, created_at) VALUES ('login', '2024-01-01 09:00:00.000000'), ('logout', '2024-01-01 09:30:00.000000'), ('login', '2024-01-01 10:00:00.000000'), ('error', '2024-01-01 10:15:00.000000')")

	rows, _ := db.Query("SELECT DISTINCT event_type FROM events ORDER BY event_type")
	defer rows.Close()
	for rows.Next() {
	}

	rows2, _ := db.Query("SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY COUNT(*) DESC")
	defer rows2.Close()
	for rows2.Next() {
	}
}

func main() {
	ctx := context.Background()

	container, cfg := startPostgresContainer(ctx)
	defer func() {
		_ = container.Terminate(ctx)
	}()

	installTcpdump(ctx, container)
	startTcpdump(ctx, container)

	db := connectDB(cfg)
	fmt.Println("Выполнение SQL запросов...")
	runSQL(db)
	fmt.Println("Запросы выполнены")
	db.Close()

	stopTcpdump(ctx, container)

	if err := runPgDumpInContainer(ctx, container); err != nil {
		log.Fatalf("pg_dump failed: %v", err)
	}

	if err := copyFileFromContainer(ctx, container, containerDumpPath, hostDumpPath); err != nil {
		log.Fatalf("copy dump failed: %v", err)
	}

	if err := copyFileFromContainer(ctx, container, containerPcapPath, hostPcapPath); err != nil {
		log.Fatalf("copy pcap failed: %v", err)
	}

	if err := integration.RemoveRestrictLines(hostDumpPath); err != nil {
		log.Fatalf("remove restrict lines failed: %v", err)
	}

	fmt.Println("Готово ✅ Дамп и PCAP сохранены")
}

type DBConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Database string
}

func startPostgresContainer(ctx context.Context) (testcontainers.Container, DBConfig) {
	container, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "postgres:15-alpine",
				ExposedPorts: []string{"5432/tcp"},
				Env: map[string]string{
					"POSTGRES_USER":             "postgres",
					"POSTGRES_PASSWORD":         "postgres",
					"POSTGRES_DB":               "postgres",
					"POSTGRES_HOST_AUTH_METHOD": "trust",
				},
				WaitingFor: wait.
					ForListeningPort("5432/tcp").
					WithStartupTimeout(30 * time.Second),
			},
			Started: true,
		},
	)
	if err != nil {
		log.Fatalf("container start failed: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		log.Fatalf("container host failed: %v", err)
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		log.Fatalf("container port failed: %v", err)
	}

	cfg := DBConfig{
		Host:     host,
		Port:     port.Port(),
		User:     "postgres",
		Password: "postgres",
		Database: "postgres",
	}

	fmt.Printf("PostgreSQL запущен: %s:%s\n", cfg.Host, cfg.Port)

	return container, cfg
}

func installTcpdump(ctx context.Context, container testcontainers.Container) {
	cmd := []string{"apk", "add", "--no-cache", "tcpdump"}
	exit, _, stderr := container.Exec(ctx, cmd)
	if exit != 0 {
		log.Fatalf("install tcpdump failed: %s", stderr)
	}
}

func startTcpdump(ctx context.Context, container testcontainers.Container) {
	cmd := []string{
		"sh", "-c",
		fmt.Sprintf(
			"tcpdump -i eth0 port 5432 -w %s & echo $! > /tmp/tcpdump.pid",
			containerPcapPath,
		),
	}

	exit, _, stderr := container.Exec(ctx, cmd)
	if exit != 0 {
		log.Fatalf("start tcpdump failed: %s", stderr)
	}

	fmt.Println("tcpdump запущен")
}

func stopTcpdump(ctx context.Context, container testcontainers.Container) {
	cmd := []string{
		"sh", "-c",
		"kill $(cat /tmp/tcpdump.pid)",
	}

	exit, _, stderr := container.Exec(ctx, cmd)
	if exit != 0 {
		log.Fatalf("stop tcpdump failed: %s", stderr)
	}

	fmt.Println("tcpdump остановлен")
}

func connectDB(cfg DBConfig) *sql.DB {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.Host,
		cfg.Port,
		cfg.User,
		cfg.Password,
		cfg.Database,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("sql.Open failed: %v", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.Ping(); err != nil {
		log.Fatalf("db ping failed: %v", err)
	}

	fmt.Println("Подключение к БД успешно")

	return db
}

func runPgDumpInContainer(ctx context.Context, container testcontainers.Container) error {
	cmd := []string{
		"pg_dump",
		"-U", "postgres",
		"-d", "postgres",
		"-f", containerDumpPath,
		"--data-only",
		"--inserts",
		"--column-inserts",
		"--no-owner",
		"--no-privileges",
		"--no-comments",
		"--disable-triggers",
		"--no-publications",
		"--no-subscriptions",
	}

	exitCode, _, stderr := container.Exec(ctx, cmd)
	if exitCode != 0 {
		return fmt.Errorf("pg_dump exit=%d stderr=%s", exitCode, stderr)
	}

	return nil
}

func copyFileFromContainer(
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

	out, err := os.Create(hostPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, reader)
	return err
}
