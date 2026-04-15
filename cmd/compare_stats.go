package cmd

import (
	"encoding/json"
	"fmt"
	"html"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type compareStatsMetric struct {
	Label         string
	Field         string
	LowerIsBetter bool
}

type compareStatsDeltaCell struct {
	A             any
	B             any
	Diff          *float64
	Pct           *string
	LowerIsBetter bool
}

type compareStatsScalarRow struct {
	Metric string
	Cell   compareStatsDeltaCell
}

type compareStatsTableRow struct {
	Key     []string
	Cells   []compareStatsDeltaCell
	Changed bool
}

type compareStatsStmtRow struct {
	Query   string
	Cells   []compareStatsDeltaCell
	Changed bool
}

var compareStatsOutput string

var CompareStatsCmd = &cobra.Command{
	Use:   "compare_stats <file_a.json> <file_b.json>",
	Short: "Сравнивает JSON snapshots collect_info и генерирует HTML-отчет",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		fileA := args[0]
		fileB := args[1]

		a, err := loadCompareStatsJSON(fileA)
		if err != nil {
			return fmt.Errorf("read %s: %w", fileA, err)
		}
		b, err := loadCompareStatsJSON(fileB)
		if err != nil {
			return fmt.Errorf("read %s: %w", fileB, err)
		}

		labelA := pickString(a["label"], filepath.Base(fileA))
		labelB := pickString(b["label"], filepath.Base(fileB))
		htmlReport := renderCompareStatsHTML(a, b, labelA, labelB)

		if err := os.WriteFile(compareStatsOutput, []byte(htmlReport), 0644); err != nil {
			return fmt.Errorf("write %s: %w", compareStatsOutput, err)
		}

		fmt.Printf("report saved -> %s\n", compareStatsOutput)
		return nil
	},
}

func init() {
	CompareStatsCmd.Flags().StringVar(&compareStatsOutput, "out", "pg_compare.html", "Путь к HTML-отчету")
	CompareStatsCmd.Flags().StringVar(&compareStatsOutput, "output", "pg_compare.html", "Путь к HTML-отчету (alias)")
}

func loadCompareStatsJSON(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func renderCompareStatsHTML(a, b map[string]any, labelA, labelB string) string {
	dbRows := scalarSection(a, b, "db_stats", []compareStatsMetric{
		{Label: "xact_commit", Field: "xact_commit", LowerIsBetter: false},
		{Label: "xact_rollback", Field: "xact_rollback", LowerIsBetter: true},
		{Label: "blks_read", Field: "blks_read", LowerIsBetter: true},
		{Label: "blks_hit", Field: "blks_hit", LowerIsBetter: false},
		{Label: "cache_hit_ratio (%)", Field: "cache_hit_ratio", LowerIsBetter: false},
		{Label: "tup_returned", Field: "tup_returned", LowerIsBetter: true},
		{Label: "tup_fetched", Field: "tup_fetched", LowerIsBetter: true},
		{Label: "tup_inserted", Field: "tup_inserted", LowerIsBetter: false},
		{Label: "tup_updated", Field: "tup_updated", LowerIsBetter: false},
		{Label: "tup_deleted", Field: "tup_deleted", LowerIsBetter: false},
		{Label: "conflicts", Field: "conflicts", LowerIsBetter: true},
		{Label: "deadlocks", Field: "deadlocks", LowerIsBetter: true},
		{Label: "temp_files", Field: "temp_files", LowerIsBetter: true},
		{Label: "temp_bytes", Field: "temp_bytes", LowerIsBetter: true},
		{Label: "blk_read_time (ms)", Field: "blk_read_time", LowerIsBetter: true},
		{Label: "blk_write_time (ms)", Field: "blk_write_time", LowerIsBetter: true},
		{Label: "sessions", Field: "sessions", LowerIsBetter: false},
		{Label: "sessions_abandoned", Field: "sessions_abandoned", LowerIsBetter: true},
		{Label: "sessions_fatal", Field: "sessions_fatal", LowerIsBetter: true},
	})

	bgwRows := scalarSection(a, b, "bgwriter_stats", []compareStatsMetric{
		{Label: "checkpoints_timed", Field: "checkpoints_timed", LowerIsBetter: false},
		{Label: "checkpoints_req", Field: "checkpoints_req", LowerIsBetter: true},
		{Label: "checkpoint_write_time", Field: "checkpoint_write_time", LowerIsBetter: true},
		{Label: "checkpoint_sync_time", Field: "checkpoint_sync_time", LowerIsBetter: true},
		{Label: "buffers_checkpoint", Field: "buffers_checkpoint", LowerIsBetter: false},
		{Label: "buffers_clean", Field: "buffers_clean", LowerIsBetter: false},
		{Label: "maxwritten_clean", Field: "maxwritten_clean", LowerIsBetter: true},
		{Label: "buffers_backend", Field: "buffers_backend", LowerIsBetter: true},
		{Label: "buffers_backend_fsync", Field: "buffers_backend_fsync", LowerIsBetter: true},
		{Label: "buffers_alloc", Field: "buffers_alloc", LowerIsBetter: false},
	})

	walRows := scalarSection(a, b, "wal_stats", []compareStatsMetric{
		{Label: "wal_records", Field: "wal_records", LowerIsBetter: false},
		{Label: "wal_fpi", Field: "wal_fpi", LowerIsBetter: true},
		{Label: "wal_bytes", Field: "wal_bytes", LowerIsBetter: false},
		{Label: "wal_buffers_full", Field: "wal_buffers_full", LowerIsBetter: true},
		{Label: "wal_write_time", Field: "wal_write_time", LowerIsBetter: true},
		{Label: "wal_sync_time", Field: "wal_sync_time", LowerIsBetter: true},
	})

	tblRows := tableSection(a, b, "table_stats", []string{"schemaname", "relname"}, []compareStatsMetric{
		{Label: "seq_scan", Field: "seq_scan", LowerIsBetter: true},
		{Label: "idx_scan", Field: "idx_scan", LowerIsBetter: false},
		{Label: "ins", Field: "n_tup_ins", LowerIsBetter: false},
		{Label: "upd", Field: "n_tup_upd", LowerIsBetter: false},
		{Label: "del", Field: "n_tup_del", LowerIsBetter: false},
		{Label: "dead", Field: "n_dead_tup", LowerIsBetter: true},
	})

	tioRows := tableSection(a, b, "table_io_stats", []string{"schemaname", "relname"}, []compareStatsMetric{
		{Label: "heap_read", Field: "heap_blks_read", LowerIsBetter: true},
		{Label: "heap_hit", Field: "heap_blks_hit", LowerIsBetter: false},
		{Label: "idx_read", Field: "idx_blks_read", LowerIsBetter: true},
		{Label: "idx_hit", Field: "idx_blks_hit", LowerIsBetter: false},
	})

	idxRows := tableSection(a, b, "index_stats", []string{"schemaname", "relname", "indexrelname"}, []compareStatsMetric{
		{Label: "idx_scan", Field: "idx_scan", LowerIsBetter: false},
		{Label: "tup_read", Field: "idx_tup_read", LowerIsBetter: false},
		{Label: "tup_fetch", Field: "idx_tup_fetch", LowerIsBetter: false},
	})

	sizeRows := tableSection(a, b, "table_sizes", []string{"schemaname", "relname"}, []compareStatsMetric{
		{Label: "total", Field: "total_bytes", LowerIsBetter: false},
		{Label: "table", Field: "table_bytes", LowerIsBetter: false},
		{Label: "indexes", Field: "indexes_bytes", LowerIsBetter: false},
	})

	sysRows := tableSection(a, b, "sys_table_stats", []string{"schemaname", "relname"}, []compareStatsMetric{
		{Label: "seq_scan", Field: "seq_scan", LowerIsBetter: true},
		{Label: "idx_scan", Field: "idx_scan", LowerIsBetter: false},
		{Label: "ins", Field: "n_tup_ins", LowerIsBetter: false},
		{Label: "upd", Field: "n_tup_upd", LowerIsBetter: false},
		{Label: "del", Field: "n_tup_del", LowerIsBetter: false},
		{Label: "dead", Field: "n_dead_tup", LowerIsBetter: true},
	})

	stmtRows := statStatementsSection(a, b)

	generated := time.Now().Format("2006-01-02 15:04:05")
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"utf-8\">")
	sb.WriteString("<title>PG Compare: " + html.EscapeString(labelA) + " vs " + html.EscapeString(labelB) + "</title>")
	sb.WriteString("<style>" + compareStatsStyle + "</style></head><body>")
	sb.WriteString("<h1>PostgreSQL Stats Comparison</h1>")
	sb.WriteString("<p class=\"sub\">Generated " + html.EscapeString(generated) + "</p>")
	sb.WriteString("<div class=\"meta\">")
	sb.WriteString("<div class=\"card\"><span class=\"badge ba\">A - " + html.EscapeString(labelA) + "</span>")
	sb.WriteString("<p><strong>Collected:</strong> " + html.EscapeString(pickString(a["collected_at"], "-")) + "<br><strong>PG:</strong> " + html.EscapeString(pickString(a["pg_version_num"], "-")) + "</p></div>")
	sb.WriteString("<div class=\"card\"><span class=\"badge bb\">B - " + html.EscapeString(labelB) + "</span>")
	sb.WriteString("<p><strong>Collected:</strong> " + html.EscapeString(pickString(b["collected_at"], "-")) + "<br><strong>PG:</strong> " + html.EscapeString(pickString(b["pg_version_num"], "-")) + "</p></div>")
	sb.WriteString("</div>")

	sb.WriteString(renderSummaryCards(a, b))
	sb.WriteString("<h2>Общая статистика БД</h2>")
	sb.WriteString(renderScalarTable(dbRows))
	sb.WriteString("<h2>BGWriter</h2>")
	sb.WriteString(renderScalarTable(bgwRows))
	sb.WriteString("<h2>WAL</h2>")
	sb.WriteString(renderScalarTable(walRows))
	sb.WriteString("<h2>Таблицы</h2>")
	sb.WriteString(renderTable(tblRows, []string{"schema", "table"}, []compareStatsMetric{{Label: "seq_scan", Field: "seq_scan", LowerIsBetter: true}, {Label: "idx_scan", Field: "idx_scan", LowerIsBetter: false}, {Label: "ins", Field: "n_tup_ins", LowerIsBetter: false}, {Label: "upd", Field: "n_tup_upd", LowerIsBetter: false}, {Label: "del", Field: "n_tup_del", LowerIsBetter: false}, {Label: "dead", Field: "n_dead_tup", LowerIsBetter: true}}))
	sb.WriteString("<h2>I/O таблиц</h2>")
	sb.WriteString(renderTable(tioRows, []string{"schema", "table"}, []compareStatsMetric{{Label: "heap_read", Field: "heap_blks_read", LowerIsBetter: true}, {Label: "heap_hit", Field: "heap_blks_hit", LowerIsBetter: false}, {Label: "idx_read", Field: "idx_blks_read", LowerIsBetter: true}, {Label: "idx_hit", Field: "idx_blks_hit", LowerIsBetter: false}}))
	sb.WriteString("<h2>Индексы</h2>")
	sb.WriteString(renderTable(idxRows, []string{"schema", "table", "index"}, []compareStatsMetric{{Label: "idx_scan", Field: "idx_scan", LowerIsBetter: false}, {Label: "tup_read", Field: "idx_tup_read", LowerIsBetter: false}, {Label: "tup_fetch", Field: "idx_tup_fetch", LowerIsBetter: false}}))
	sb.WriteString("<h2>Размеры</h2>")
	sb.WriteString(renderTable(sizeRows, []string{"schema", "table"}, []compareStatsMetric{{Label: "total", Field: "total_bytes", LowerIsBetter: false}, {Label: "table", Field: "table_bytes", LowerIsBetter: false}, {Label: "indexes", Field: "indexes_bytes", LowerIsBetter: false}}))
	sb.WriteString("<h2>Системные таблицы каталога</h2>")
	sb.WriteString(renderTable(sysRows, []string{"schema", "table"}, []compareStatsMetric{{Label: "seq_scan", Field: "seq_scan", LowerIsBetter: true}, {Label: "idx_scan", Field: "idx_scan", LowerIsBetter: false}, {Label: "ins", Field: "n_tup_ins", LowerIsBetter: false}, {Label: "upd", Field: "n_tup_upd", LowerIsBetter: false}, {Label: "del", Field: "n_tup_del", LowerIsBetter: false}, {Label: "dead", Field: "n_dead_tup", LowerIsBetter: true}}))
	sb.WriteString("<h2>pg_stat_statements</h2>")
	sb.WriteString(renderStatementsTable(stmtRows))
	sb.WriteString("<script>" + compareStatsStatementsPagerScript + "</script>")
	sb.WriteString("</body></html>")
	return sb.String()
}

func renderSummaryCards(a, b map[string]any) string {
	ra := firstRecord(a, "db_stats")
	rb := firstRecord(b, "db_stats")
	items := []struct {
		Label         string
		Field         string
		LowerIsBetter bool
		Unit          string
	}{
		{Label: "Cache Hit Ratio", Field: "cache_hit_ratio", LowerIsBetter: false, Unit: "%"},
		{Label: "xact_commit", Field: "xact_commit", LowerIsBetter: false, Unit: ""},
		{Label: "xact_rollback", Field: "xact_rollback", LowerIsBetter: true, Unit: ""},
		{Label: "deadlocks", Field: "deadlocks", LowerIsBetter: true, Unit: ""},
		{Label: "blk_read_time", Field: "blk_read_time", LowerIsBetter: true, Unit: " ms"},
		{Label: "temp_files", Field: "temp_files", LowerIsBetter: true, Unit: ""},
	}

	var cards strings.Builder
	for _, item := range items {
		va := ra[item.Field]
		vb := rb[item.Field]
		diff, pct := deltaPct(va, vb)
		cls := "gray"
		val := "-"
		if diff != nil && pct != nil {
			if *diff == 0 {
				val = "-> " + *pct
			} else {
				up := *diff > 0
				icon := "↑"
				if !up {
					icon = "↓"
				}
				if (item.LowerIsBetter && up) || (!item.LowerIsBetter && !up) {
					cls = "red"
				} else {
					cls = "green"
				}
				val = icon + " " + *pct
			}
		}
		cards.WriteString("<div class=\"scard\">")
		cards.WriteString("<div class=\"slabel\">" + html.EscapeString(item.Label) + "</div>")
		cards.WriteString("<div class=\"sval " + cls + "\">" + html.EscapeString(val) + "</div>")
		cards.WriteString("<div class=\"ssub\">A: " + html.EscapeString(formatNum(va)+item.Unit) + " &nbsp; B: " + html.EscapeString(formatNum(vb)+item.Unit) + "</div>")
		cards.WriteString("</div>")
	}
	return "<h2>Сводка</h2><div class=\"summary\">" + cards.String() + "</div>"
}

func renderScalarTable(rows []compareStatsScalarRow) string {
	var sb strings.Builder
	sb.WriteString("<div class=\"wrap\"><table><thead><tr><th>Метрика</th><th class=\"num\">A</th><th class=\"num\">B</th><th class=\"num\">Δ</th></tr></thead><tbody>")
	for _, r := range rows {
		sb.WriteString("<tr>")
		sb.WriteString("<td class=\"tm\">" + html.EscapeString(r.Metric) + "</td>")
		sb.WriteString("<td class=\"ta\">" + html.EscapeString(formatNum(r.Cell.A)) + "</td>")
		sb.WriteString("<td class=\"tb\">" + html.EscapeString(formatNum(r.Cell.B)) + "</td>")
		sb.WriteString("<td class=\"td " + deltaClass(r.Cell) + "\">" + html.EscapeString(valueOrDash(r.Cell.Pct)) + "</td>")
		sb.WriteString("</tr>")
	}
	sb.WriteString("</tbody></table></div>")
	return sb.String()
}

func renderTable(rows []compareStatsTableRow, keyCols []string, metrics []compareStatsMetric) string {
	var sb strings.Builder
	sb.WriteString("<div class=\"wrap\"><table><thead><tr>")
	for _, c := range keyCols {
		sb.WriteString("<th>" + html.EscapeString(c) + "</th>")
	}
	for _, m := range metrics {
		sb.WriteString("<th class=\"num\">A " + html.EscapeString(m.Label) + "</th>")
		sb.WriteString("<th class=\"num\">B " + html.EscapeString(m.Label) + "</th>")
		sb.WriteString("<th class=\"num\">Δ</th>")
	}
	sb.WriteString("</tr></thead><tbody>")
	for _, r := range rows {
		sb.WriteString("<tr>")
		for _, k := range r.Key {
			sb.WriteString("<td class=\"tm\">" + html.EscapeString(k) + "</td>")
		}
		for _, c := range r.Cells {
			sb.WriteString("<td class=\"ta\">" + html.EscapeString(formatNum(c.A)) + "</td>")
			sb.WriteString("<td class=\"tb\">" + html.EscapeString(formatNum(c.B)) + "</td>")
			sb.WriteString("<td class=\"td " + deltaClass(c) + "\">" + html.EscapeString(valueOrDash(c.Pct)) + "</td>")
		}
		sb.WriteString("</tr>")
	}
	sb.WriteString("</tbody></table></div>")
	return sb.String()
}

func renderStatementsTable(rows []compareStatsStmtRow) string {
	metrics := []compareStatsMetric{
		{Label: "calls", Field: "calls", LowerIsBetter: false},
		{Label: "mean ms", Field: "mean_exec_time", LowerIsBetter: true},
		{Label: "total ms", Field: "total_exec_time", LowerIsBetter: true},
		{Label: "rows", Field: "rows", LowerIsBetter: false},
		{Label: "blks_hit", Field: "shared_blks_hit", LowerIsBetter: false},
		{Label: "blks_read", Field: "shared_blks_read", LowerIsBetter: true},
	}
	const pageSize = 50

	var sb strings.Builder
	sb.WriteString("<div class=\"wrap\"><table id=\"stmt-table\"><thead><tr><th>Query</th>")
	for _, m := range metrics {
		sb.WriteString("<th class=\"num\">A " + html.EscapeString(m.Label) + "</th>")
		sb.WriteString("<th class=\"num\">B " + html.EscapeString(m.Label) + "</th>")
		sb.WriteString("<th class=\"num\">Δ</th>")
	}
	sb.WriteString("</tr></thead><tbody>")
	for _, r := range rows {
		fullQuery := html.EscapeString(r.Query)
		previewQuery := html.EscapeString(queryPreview(r.Query, 160))

		sb.WriteString("<tr class=\"stmt-row\"><td class=\"qcell\">")
		if previewQuery == fullQuery {
			sb.WriteString("<div class=\"qtext\">" + fullQuery + "</div>")
		} else {
			sb.WriteString("<details class=\"qexp\"><summary class=\"qsum qtext\">" + previewQuery + "</summary><div class=\"qfull qtext\">" + fullQuery + "</div></details>")
		}
		sb.WriteString("</td>")
		for _, c := range r.Cells {
			sb.WriteString("<td class=\"ta\">" + html.EscapeString(formatNum(c.A)) + "</td>")
			sb.WriteString("<td class=\"tb\">" + html.EscapeString(formatNum(c.B)) + "</td>")
			sb.WriteString("<td class=\"td " + deltaClass(c) + "\">" + html.EscapeString(valueOrDash(c.Pct)) + "</td>")
		}
		sb.WriteString("</tr>")
	}
	sb.WriteString("</tbody></table></div>")
	sb.WriteString("<div id=\"stmt-pager\" class=\"pager\" data-page-size=\"" + strconv.Itoa(pageSize) + "\">")
	sb.WriteString("<button type=\"button\" id=\"stmt-prev\" class=\"pager-btn\">Prev</button>")
	sb.WriteString("<span id=\"stmt-page-info\" class=\"pager-info\"></span>")
	sb.WriteString("<button type=\"button\" id=\"stmt-next\" class=\"pager-btn\">Next</button>")
	sb.WriteString("</div>")
	return sb.String()
}

func scalarSection(a, b map[string]any, key string, metrics []compareStatsMetric) []compareStatsScalarRow {
	ra := firstRecord(a, key)
	rb := firstRecord(b, key)
	rows := make([]compareStatsScalarRow, 0, len(metrics))
	for _, m := range metrics {
		d, p := deltaPct(ra[m.Field], rb[m.Field])
		rows = append(rows, compareStatsScalarRow{
			Metric: m.Label,
			Cell: compareStatsDeltaCell{
				A:             ra[m.Field],
				B:             rb[m.Field],
				Diff:          d,
				Pct:           p,
				LowerIsBetter: m.LowerIsBetter,
			},
		})
	}
	return rows
}

func tableSection(a, b map[string]any, key string, keyCols []string, metrics []compareStatsMetric) []compareStatsTableRow {
	rowsA := recordsSection(a, key)
	rowsB := recordsSection(b, key)

	mapA := make(map[string]map[string]any, len(rowsA))
	mapB := make(map[string]map[string]any, len(rowsB))
	allKeys := make(map[string][]string)

	for _, row := range rowsA {
		k := rowKey(row, keyCols)
		mapA[k] = row
		allKeys[k] = rowKeyParts(row, keyCols)
	}
	for _, row := range rowsB {
		k := rowKey(row, keyCols)
		mapB[k] = row
		if _, ok := allKeys[k]; !ok {
			allKeys[k] = rowKeyParts(row, keyCols)
		}
	}

	sortedKeys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	rows := make([]compareStatsTableRow, 0, len(sortedKeys))
	for _, k := range sortedKeys {
		ra := mapA[k]
		rb := mapB[k]
		cells := make([]compareStatsDeltaCell, 0, len(metrics))
		changed := false
		for _, m := range metrics {
			var va, vb any
			if ra != nil {
				va = ra[m.Field]
			}
			if rb != nil {
				vb = rb[m.Field]
			}
			d, p := deltaPct(va, vb)
			if d != nil && *d != 0 {
				changed = true
			}
			cells = append(cells, compareStatsDeltaCell{
				A:             va,
				B:             vb,
				Diff:          d,
				Pct:           p,
				LowerIsBetter: m.LowerIsBetter,
			})
		}
		rows = append(rows, compareStatsTableRow{Key: allKeys[k], Cells: cells, Changed: changed})
	}
	return rows
}

func statStatementsSection(a, b map[string]any) []compareStatsStmtRow {
	fields := []compareStatsMetric{
		{Field: "calls", LowerIsBetter: false},
		{Field: "mean_exec_time", LowerIsBetter: true},
		{Field: "total_exec_time", LowerIsBetter: true},
		{Field: "rows", LowerIsBetter: false},
		{Field: "shared_blks_hit", LowerIsBetter: false},
		{Field: "shared_blks_read", LowerIsBetter: true},
	}

	sa := aggStatStatements(recordsSection(a, "stat_statements"))
	sb := aggStatStatements(recordsSection(b, "stat_statements"))

	allQueries := make([]string, 0, len(sa)+len(sb))
	seen := make(map[string]struct{}, len(sa)+len(sb))
	for q := range sa {
		seen[q] = struct{}{}
		allQueries = append(allQueries, q)
	}
	for q := range sb {
		if _, ok := seen[q]; !ok {
			allQueries = append(allQueries, q)
		}
	}

	sort.SliceStable(allQueries, func(i, j int) bool {
		li := 0.0
		if v, ok := toFloat(sb[allQueries[i]]["total_exec_time"]); ok {
			li = v
		} else if v, ok := toFloat(sa[allQueries[i]]["total_exec_time"]); ok {
			li = v
		}

		lj := 0.0
		if v, ok := toFloat(sb[allQueries[j]]["total_exec_time"]); ok {
			lj = v
		} else if v, ok := toFloat(sa[allQueries[j]]["total_exec_time"]); ok {
			lj = v
		}
		return li > lj
	})

	rows := make([]compareStatsStmtRow, 0, len(allQueries))
	for _, q := range allQueries {
		ra := sa[q]
		rb := sb[q]
		if ra == nil {
			ra = map[string]any{}
		}
		if rb == nil {
			rb = map[string]any{}
		}

		cells := make([]compareStatsDeltaCell, 0, len(fields))
		changed := false
		for _, f := range fields {
			d, p := deltaPct(ra[f.Field], rb[f.Field])
			if d != nil && *d != 0 {
				changed = true
			}
			cells = append(cells, compareStatsDeltaCell{
				A:             ra[f.Field],
				B:             rb[f.Field],
				Diff:          d,
				Pct:           p,
				LowerIsBetter: f.LowerIsBetter,
			})
		}

		query := q
		if len(query) > 400 {
			query = query[:400]
		}
		rows = append(rows, compareStatsStmtRow{Query: query, Cells: cells, Changed: changed})
	}
	return rows
}

func aggStatStatements(rows []map[string]any) map[string]map[string]any {
	out := make(map[string]map[string]any, len(rows))
	for _, r := range rows {
		q := pickString(r["query"], "")
		if q == "" {
			continue
		}
		if _, ok := out[q]; !ok {
			clone := make(map[string]any, len(r))
			for k, v := range r {
				clone[k] = v
			}
			out[q] = clone
			continue
		}
		for _, field := range []string{"calls", "total_exec_time", "rows", "shared_blks_hit", "shared_blks_read"} {
			acc, _ := toFloat(out[q][field])
			cur, ok := toFloat(r[field])
			if ok {
				out[q][field] = acc + cur
			}
		}
	}
	return out
}

func recordsSection(m map[string]any, key string) []map[string]any {
	raw, ok := m[key]
	if !ok || raw == nil {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		r, ok := item.(map[string]any)
		if ok {
			out = append(out, r)
		}
	}
	return out
}

func firstRecord(m map[string]any, key string) map[string]any {
	rows := recordsSection(m, key)
	if len(rows) == 0 {
		return map[string]any{}
	}
	return rows[0]
}

func rowKey(row map[string]any, cols []string) string {
	return strings.Join(rowKeyParts(row, cols), "\x1f")
}

func rowKeyParts(row map[string]any, cols []string) []string {
	parts := make([]string, 0, len(cols))
	for _, c := range cols {
		parts = append(parts, pickString(row[c], ""))
	}
	return parts
}

func deltaPct(a, b any) (*float64, *string) {
	fa, oka := toFloat(a)
	fb, okb := toFloat(b)
	if !oka || !okb {
		return nil, nil
	}
	diff := fb - fa
	pct := ""
	if fa != 0 {
		pct = fmt.Sprintf("%+.1f%%", diff/fa*100)
	} else if diff > 0 {
		pct = "∞"
	} else {
		pct = "-"
	}
	return &diff, &pct
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case nil:
		return 0, false
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case int32:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func formatNum(v any) string {
	if v == nil {
		return "-"
	}
	f, ok := toFloat(v)
	if !ok {
		return pickString(v, "-")
	}
	if math.Mod(f, 1) == 0 {
		return formatIntLike(int64(f))
	}
	s := fmt.Sprintf("%.3f", f)
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	return s
}

func formatIntLike(n int64) string {
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}
	neg := ""
	if strings.HasPrefix(s, "-") {
		neg = "-"
		s = s[1:]
	}
	var out []string
	for len(s) > 3 {
		out = append([]string{s[len(s)-3:]}, out...)
		s = s[:len(s)-3]
	}
	out = append([]string{s}, out...)
	return neg + strings.Join(out, " ")
}

func pickString(v any, fallback string) string {
	if v == nil {
		return fallback
	}
	switch t := v.(type) {
	case string:
		if strings.TrimSpace(t) == "" {
			return fallback
		}
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}

func queryPreview(query string, maxRunes int) string {
	if maxRunes < 1 {
		maxRunes = 160
	}
	trimmed := strings.TrimSpace(query)
	runes := []rune(trimmed)
	if len(runes) <= maxRunes {
		return trimmed
	}
	return string(runes[:maxRunes]) + " ..."
}

func valueOrDash(v *string) string {
	if v == nil {
		return "-"
	}
	return *v
}

func deltaClass(cell compareStatsDeltaCell) string {
	if cell.Diff == nil || *cell.Diff == 0 {
		return "dz"
	}
	if (cell.LowerIsBetter && *cell.Diff > 0) || (!cell.LowerIsBetter && *cell.Diff < 0) {
		return "dp"
	}
	return "dn"
}

const compareStatsStatementsPagerScript = `
(function () {
	var table = document.getElementById('stmt-table');
	if (!table) {
		return;
	}

	var pager = document.getElementById('stmt-pager');
	var prev = document.getElementById('stmt-prev');
	var next = document.getElementById('stmt-next');
	var info = document.getElementById('stmt-page-info');
	var rows = Array.prototype.slice.call(table.querySelectorAll('tbody tr'));

	if (!pager || !prev || !next || !info) {
		return;
	}

	var pageSize = parseInt(pager.getAttribute('data-page-size') || '50', 10);
	if (!pageSize || pageSize < 1) {
		pageSize = 50;
	}

	var page = 1;
	var pages = Math.max(1, Math.ceil(rows.length / pageSize));

	function render() {
		var start = (page - 1) * pageSize;
		var end = start + pageSize;
		for (var i = 0; i < rows.length; i++) {
			rows[i].style.display = i >= start && i < end ? '' : 'none';
		}

		if (rows.length === 0) {
			info.textContent = 'Страница 0 / 0';
		} else {
			info.textContent = 'Страница ' + page + ' / ' + pages + ' (' + rows.length + ' запросов)';
		}
		prev.disabled = page <= 1;
		next.disabled = page >= pages;
	}

	prev.addEventListener('click', function () {
		if (page > 1) {
			page--;
			render();
		}
	});

	next.addEventListener('click', function () {
		if (page < pages) {
			page++;
			render();
		}
	});

	render();
})();
`

const compareStatsStyle = `
* { box-sizing: border-box; margin: 0; padding: 0 }
body { font: 13px/1.5 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #dde3ee; padding: 20px }
h1 { font-size: 1.4rem; color: #f0f4ff; margin-bottom: 4px }
.sub { color: #6b7a99; font-size: .8rem; margin-bottom: 24px }
h2 { font-size: .95rem; color: #a5b4fc; margin: 28px 0 8px; border-left: 3px solid #6366f1; padding-left: 9px }
.meta { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 24px }
.card { background: #1a1d2e; border: 1px solid #2b2f4a; border-radius: 8px; padding: 12px 16px }
.badge { display:inline-block; padding:2px 10px; border-radius:99px; font-size:.72rem; font-weight:600; margin-bottom:6px }
.ba { background:#1e3a5f; color:#60a5fa }
.bb { background:#1a3a2a; color:#34d399 }
.card p { font-size:.8rem; color:#8898b8; line-height:1.7 }
.card strong { color:#dde3ee }
.summary { display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:10px; margin-bottom:8px }
.scard { background:#1a1d2e; border:1px solid #2b2f4a; border-radius:8px; padding:12px 14px }
.slabel { font-size:.72rem; color:#6b7a99; margin-bottom:4px }
.sval { font-size:1.2rem; font-weight:700 }
.ssub { font-size:.72rem; color:#8898b8; margin-top:3px }
.green { color:#34d399 }
.red { color:#f87171 }
.gray { color:#64748b }
.wrap { overflow-x:auto; border:1px solid #2b2f4a; border-radius:8px }
.pager { display:flex; align-items:center; justify-content:flex-end; gap:8px; margin-top:8px }
.pager-btn { background:#1a1d2e; color:#cbd5e1; border:1px solid #2b2f4a; border-radius:6px; padding:4px 10px; cursor:pointer }
.pager-btn:hover:not(:disabled) { background:#222641 }
.pager-btn:disabled { opacity:.45; cursor:not-allowed }
.pager-info { color:#94a3b8; font-size:.75rem; min-width:180px; text-align:center }
table { width:100%; border-collapse:collapse; font-size:.78rem }
thead th { background:#151827; color:#8898b8; padding:7px 10px; text-align:left; white-space:nowrap; border-bottom:1px solid #2b2f4a; position:sticky; top:0; z-index:1 }
tbody tr:hover { background:#1a1d2e }
td { padding:5px 10px; border-bottom:1px solid #181b29; vertical-align:top }
.tm { color:#b0bdd6; word-break:break-word; max-width:360px }
.ta { color:#60a5fa; text-align:right; white-space:nowrap }
.tb { color:#34d399; text-align:right; white-space:nowrap }
.td { text-align:right; font-weight:600; white-space:nowrap }
.num { text-align:right }
.dp { color:#f87171 }
.dn { color:#34d399 }
.dz { color:#475569 }
.qcell { min-width:320px; max-width:700px }
.qexp { display:block }
.qsum { cursor:pointer; list-style:none; white-space:nowrap; overflow:hidden; text-overflow:ellipsis }
.qsum::-webkit-details-marker { display:none }
.qsum::before { content:'[+] '; color:#60a5fa }
.qexp[open] .qsum::before { content:'[-] '; }
.qexp[open] .qsum { white-space:pre-wrap; overflow:visible }
.qfull { margin-top:6px; padding-top:6px; border-top:1px dashed #2b2f4a; white-space:pre-wrap; word-break:break-word }
.qtext { font-family: 'Fira Code', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:.72rem; color:#93c5fd; word-break:break-word }
`
