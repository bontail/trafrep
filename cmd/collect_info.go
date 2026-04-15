package cmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
)

type collectInfoQueryDef struct {
	key string
	sql string
}

var collectInfoQueries = []collectInfoQueryDef{
	{
		key: "db_stats",
		sql: `
        SELECT
            datname,
            numbackends,
            xact_commit,
            xact_rollback,
            blks_read,
            blks_hit,
            CASE WHEN blks_hit + blks_read > 0
                 THEN round(blks_hit::numeric / (blks_hit + blks_read) * 100, 4)
                 ELSE NULL END AS cache_hit_ratio,
            tup_returned,
            tup_fetched,
            tup_inserted,
            tup_updated,
            tup_deleted,
            conflicts,
            temp_files,
            temp_bytes,
            deadlocks,
            checksum_failures,
            blk_read_time,
            blk_write_time,
            session_time,
            active_time,
            idle_in_transaction_time,
            sessions,
            sessions_abandoned,
            sessions_fatal,
            sessions_killed,
            stats_reset
        FROM pg_stat_database
        WHERE datname = current_database()
    `,
	},
	{
		key: "table_stats",
		sql: `
        SELECT
            schemaname,
            relname,
            seq_scan,
            seq_tup_read,
            idx_scan,
            idx_tup_fetch,
            n_tup_ins,
            n_tup_upd,
            n_tup_del,
            n_tup_hot_upd,
            n_live_tup,
            n_dead_tup,
            n_mod_since_analyze,
            n_ins_since_vacuum,
            last_vacuum,
            last_autovacuum,
            last_analyze,
            last_autoanalyze,
            vacuum_count,
            autovacuum_count,
            analyze_count,
            autoanalyze_count
        FROM pg_stat_user_tables
        ORDER BY schemaname, relname
    `,
	},
	{
		key: "table_io_stats",
		sql: `
        SELECT
            schemaname,
            relname,
            heap_blks_read,
            heap_blks_hit,
            idx_blks_read,
            idx_blks_hit,
            toast_blks_read,
            toast_blks_hit,
            tidx_blks_read,
            tidx_blks_hit
        FROM pg_statio_user_tables
        ORDER BY schemaname, relname
    `,
	},
	{
		key: "index_stats",
		sql: `
        SELECT
            schemaname,
            relname,
            indexrelname,
            idx_scan,
            idx_tup_read,
            idx_tup_fetch
        FROM pg_stat_user_indexes
        ORDER BY schemaname, relname, indexrelname
    `,
	},
	{
		key: "index_io_stats",
		sql: `
        SELECT
            schemaname,
            relname,
            indexrelname,
            idx_blks_read,
            idx_blks_hit
        FROM pg_statio_user_indexes
        ORDER BY schemaname, relname, indexrelname
    `,
	},
	{
		key: "bgwriter_stats",
		sql: `
        SELECT
            checkpoints_timed,
            checkpoints_req,
            checkpoint_write_time,
            checkpoint_sync_time,
            buffers_checkpoint,
            buffers_clean,
            maxwritten_clean,
            buffers_backend,
            buffers_backend_fsync,
            buffers_alloc,
            stats_reset
        FROM pg_stat_bgwriter
    `,
	},
	{
		key: "connections",
		sql: `
        SELECT
            state,
            count(*) AS cnt
        FROM pg_stat_activity
        WHERE datname = current_database()
        GROUP BY state
        ORDER BY state
    `,
	},
	{
		key: "table_sizes",
		sql: `
        SELECT
            schemaname,
            relname,
            pg_total_relation_size(schemaname || '.' || relname) AS total_bytes,
            pg_relation_size(schemaname || '.' || relname)        AS table_bytes,
            pg_indexes_size(schemaname || '.' || relname)         AS indexes_bytes
        FROM pg_stat_user_tables
        ORDER BY total_bytes DESC
    `,
	},
	{
		key: "locks",
		sql: `
        SELECT
            mode,
            locktype,
            granted,
            count(*) AS cnt
        FROM pg_locks
        GROUP BY mode, locktype, granted
        ORDER BY cnt DESC
    `,
	},
	{
		key: "pg_version",
		sql: `
        SELECT version()
    `,
	},
	{
		key: "sys_table_stats",
		sql: `
        SELECT
            schemaname,
            relname,
            seq_scan,
            seq_tup_read,
            idx_scan,
            idx_tup_fetch,
            n_tup_ins,
            n_tup_upd,
            n_tup_del,
            n_live_tup,
            n_dead_tup
        FROM pg_stat_sys_tables
        WHERE n_tup_ins + n_tup_upd + n_tup_del > 0
        ORDER BY n_tup_ins + n_tup_upd + n_tup_del DESC
    `,
	},
}

const collectInfoStatStatementsQuery = `
    SELECT
        userid::regrole::text  AS username,
        (SELECT datname FROM pg_database WHERE oid = dbid) AS dbname,
        query,
        plans,
        total_plan_time,
        mean_plan_time,
        calls,
        total_exec_time,
        mean_exec_time,
        min_exec_time,
        max_exec_time,
        stddev_exec_time,
        rows,
        shared_blks_hit,
        shared_blks_read,
        shared_blks_dirtied,
        shared_blks_written,
        local_blks_hit,
        local_blks_read,
        local_blks_dirtied,
        local_blks_written,
        temp_blks_read,
        temp_blks_written,
        blk_read_time,
        blk_write_time,
        wal_records,
        wal_fpi,
        wal_bytes
    FROM pg_stat_statements
    WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
    ORDER BY total_exec_time DESC
`

const collectInfoWalQuery = `
    SELECT
        wal_records,
        wal_fpi,
        wal_bytes,
        wal_buffers_full,
        wal_write,
        wal_sync,
        wal_write_time,
        wal_sync_time,
        stats_reset
    FROM pg_stat_wal
`

type collectInfoConfig struct {
	host     string
	port     int
	dbname   string
	user     string
	password string
	label    string
	outDir   string
}

var collectInfoCfg collectInfoConfig

func collectInfoEnvOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func collectInfoDSN(cfg collectInfoConfig, dbname string) string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=disable",
		cfg.host,
		cfg.port,
		dbname,
		cfg.user,
		cfg.password,
	)
}

func collectInfoNormalizeValue(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case time.Time:
		return t.Format("2006-01-02T15:04:05.999999999-07:00")
	case []byte:
		return string(t)
	default:
		return t
	}
}

func collectInfoFetchQuery(ctx context.Context, db *sql.DB, query string) ([]map[string]any, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	result := make([]map[string]any, 0)
	for rows.Next() {
		values := make([]any, len(cols))
		valuePtrs := make([]any, len(cols))
		for i := range values {
			valuePtrs[i] = &values[i]
		}
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		clean := make(map[string]any, len(cols))
		for i, col := range cols {
			clean[col] = collectInfoNormalizeValue(values[i])
		}
		result = append(result, clean)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func collectInfoVersionNum(ctx context.Context, db *sql.DB) (int, error) {
	var raw string
	if err := db.QueryRowContext(ctx, "SHOW server_version_num").Scan(&raw); err != nil {
		return 0, err
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("parse server_version_num %q: %w", raw, err)
	}
	return v, nil
}

func collectInfoExtensionExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var one int
	err := db.QueryRowContext(ctx, "SELECT 1 FROM pg_extension WHERE extname = $1", name).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func collectInfoWriteSnapshotFile(outDir, label string, payload map[string]any) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}

	ts := time.Now().Format("20060102_150405")
	path := filepath.Join(outDir, fmt.Sprintf("%s_%s.json", label, ts))

	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return "", err
	}

	return path, nil
}

func collectInfoCollect(ctx context.Context, db *sql.DB, cfg collectInfoConfig) (string, error) {
	version, err := collectInfoVersionNum(ctx, db)
	if err != nil {
		return "", err
	}
	fmt.Printf("  PostgreSQL server_version_num = %d\n", version)

	data := map[string]any{
		"label":          cfg.label,
		"collected_at":   time.Now().UTC().Format("2006-01-02T15:04:05.999999999-07:00"),
		"pg_version_num": version,
	}

	for _, q := range collectInfoQueries {
		fmt.Printf("  - %s\n", q.key)
		rows, qErr := collectInfoFetchQuery(ctx, db, q.sql)
		if qErr != nil {
			fmt.Printf("    ! skipped: %v\n", qErr)
			data[q.key] = nil
			continue
		}
		data[q.key] = rows
	}

	hasStatStatements, err := collectInfoExtensionExists(ctx, db, "pg_stat_statements")
	if err != nil {
		return "", err
	}
	if hasStatStatements {
		fmt.Println("  - stat_statements (pg_stat_statements)")
		rows, qErr := collectInfoFetchQuery(ctx, db, collectInfoStatStatementsQuery)
		if qErr != nil {
			fmt.Printf("    ! skipped: %v\n", qErr)
			data["stat_statements"] = nil
		} else {
			data["stat_statements"] = rows
		}
	} else {
		fmt.Println("  ! pg_stat_statements is not installed, skipping")
		data["stat_statements"] = nil
	}

	if version >= 140000 {
		fmt.Println("  - wal_stats (pg_stat_wal, PG14+)")
		rows, qErr := collectInfoFetchQuery(ctx, db, collectInfoWalQuery)
		if qErr != nil {
			fmt.Printf("    ! skipped: %v\n", qErr)
			data["wal_stats"] = nil
		} else {
			data["wal_stats"] = rows
		}
	} else {
		fmt.Println("  ! pg_stat_wal requires PG14+, skipping")
		data["wal_stats"] = nil
	}

	filename, err := collectInfoWriteSnapshotFile(cfg.outDir, cfg.label, data)
	if err != nil {
		return "", err
	}

	fmt.Printf("\n  saved -> %s\n", filename)
	return filename, nil
}

// CollectInfoCmd collects PostgreSQL statistics into a JSON snapshot.
var CollectInfoCmd = &cobra.Command{
	Use:   "collect_info",
	Short: "Collect PostgreSQL benchmark statistics into JSON",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := collectInfoCfg
		fmt.Printf("Connecting: %s:%d/%s (user=%s)\n", cfg.host, cfg.port, cfg.dbname, cfg.user)

		ctx := context.Background()
		db, err := sql.Open("postgres", collectInfoDSN(cfg, cfg.dbname))
		if err != nil {
			return fmt.Errorf("connection error: %w", err)
		}
		defer func() { _ = db.Close() }()

		if err := db.PingContext(ctx); err != nil {
			return fmt.Errorf("connection error: %w", err)
		}

		fmt.Printf("\n[COLLECT] Collecting stats (label=%s)...\n\n", cfg.label)
		if _, err := collectInfoCollect(ctx, db, cfg); err != nil {
			return fmt.Errorf("collect error: %w", err)
		}
		return nil
	},
}

func init() {
	defaultPort := 5432
	if raw := collectInfoEnvOrDefault("PG_PORT", "5432"); raw != "" {
		if p, err := strconv.Atoi(raw); err == nil {
			defaultPort = p
		}
	}

	CollectInfoCmd.Flags().StringVar(&collectInfoCfg.host, "host", collectInfoEnvOrDefault("PG_HOST", "127.0.0.1"), "PostgreSQL host")
	CollectInfoCmd.Flags().IntVar(&collectInfoCfg.port, "port", defaultPort, "PostgreSQL port")
	CollectInfoCmd.Flags().StringVar(&collectInfoCfg.dbname, "dbname", collectInfoEnvOrDefault("PG_DBNAME", "postgres"), "Database name")
	CollectInfoCmd.Flags().StringVar(&collectInfoCfg.user, "user", collectInfoEnvOrDefault("PG_USER", "postgres"), "Database user")
	CollectInfoCmd.Flags().StringVar(&collectInfoCfg.password, "password", collectInfoEnvOrDefault("PG_PASSWORD", "postgres"), "Database password")
	CollectInfoCmd.Flags().StringVar(&collectInfoCfg.label, "label", "run", "Run label (baseline / replay / ...)")
	CollectInfoCmd.Flags().StringVar(&collectInfoCfg.outDir, "out", ".", "Output directory")
}
