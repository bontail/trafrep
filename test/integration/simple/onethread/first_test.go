package onethread_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"

	"trafRep/test/integration"
)

type Row struct {
	ID    int
	Value int
}

var expectedObjects = []Row{
	{ID: 1, Value: 1},
	{ID: 2, Value: 1},
	{ID: 3, Value: 1},
}

func TestFirst(t *testing.T) {
	t.Run("First", func(t *testing.T) {
		integration.RunReplay(t, integration.ReplayTestCase{
			PcapFile: "first.pcap",
			PreparedQueries: []string{
				"CREATE TABLE some_table (id SERIAL PRIMARY KEY, value integer);",
			},
			CheckFunc: func(ctx context.Context, conn *pgx.Conn) error {
				rows, err := conn.Query(ctx, "SELECT id, value FROM some_table;")
				if err != nil {
					return fmt.Errorf("query failed: %v", err)
				}
				defer rows.Close()
				var objects []Row
				for rows.Next() {
					var id int
					var value int
					if err = rows.Scan(&id, &value); err != nil {
						return fmt.Errorf("scan failed: %v", err)
					}
					objects = append(objects, Row{id, value})
				}
				if err = rows.Err(); err != nil {
					return fmt.Errorf("rows iteration error: %v", err)
				}

				if !reflect.DeepEqual(objects, expectedObjects) {
					return fmt.Errorf("data mismatch: expected %+v, got %+v", expectedObjects, objects)
				}
				return nil
			},
		})
	})
}
