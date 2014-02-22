package acl

import (
	"database/sql"
	"strings"
)

var tpl_table = `CREATE TABLE "$TABLE"
(
	"actor_id" uuid NOT NULL,
	"action" character varying(255) NOT NULL,
	"target_id" uuid DEFAULT '00000000-0000-0000-0000-000000000000',
	"allowed" bool NOT NULL,
	PRIMARY KEY ("actor_id", "action", "target_id")
);
`

var tpl_insert_rule = `
CREATE RULE "$TABLE_INSERT" AS ON INSERT TO "$TABLE"
	WHERE EXISTS(SELECT 1 FROM "$TABLE"
		WHERE (actor_id, action, target_id) = (NEW.actor_id, NEW.action, NEW.target_id))
	DO INSTEAD UPDATE "$TABLE" SET allowed = NEW.allowed WHERE (actor_id, action, target_id) = (NEW.actor_id, NEW.action, NEW.target_id);`

// CreateTable creates the table and rules required to run the ACL,
// will only create new table and rule if they do not already exist
func CreateTable(db *sql.DB, name string) error {
	t, err := db.Begin()
	if err != nil {
		panic(err)
	}

	numRows := 0
	row := t.QueryRow("SELECT COUNT(1) FROM information_schema.tables WHERE table_name = $1", name)
	err = row.Scan(&numRows)
	if err != nil {
		t.Rollback()

		return err
	}

	if numRows == 0 {
		/* No row, insert new table */
		_, err = t.Exec(strings.Replace(tpl_table, "$TABLE", name, -1))
		if err != nil {
			t.Rollback()

			return err
		}
	}

	numRows = 0
	row = t.QueryRow("SELECT COUNT(1) FROM pg_rules WHERE rulename = $1", name+"_INSERT")
	err = row.Scan(&numRows)
	if err != nil {
		t.Rollback()

		return err
	}

	if numRows == 0 {
		/* No row, insert new rule */
		_, err = t.Exec(strings.Replace(tpl_insert_rule, "$TABLE", name, -1))
		if err != nil {
			t.Rollback()

			return err
		}
	}

	return t.Commit()
}
