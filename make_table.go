package acl

import (
	"database/sql"
	"strings"
)

type Link struct {
	Table string
	Key   string
}

// Cascades contains the tables and keys to cascade DELETES into the ACL-table
type Cascades struct {
	Actors  []Link
	Targets []Link
}

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

var tpl_actor_delete_trigger = `
CREATE RULE "$TABLE_ACTOR_$ACTOR_DELETED" AS ON DELETE TO "$ACTOR"
	DO ALSO DELETE FROM "$TABLE" WHERE actor_id = old."$KEY";
`

var tpl_target_delete_trigger = `
CREATE RULE "$TABLE_TARGET_$TARGET_DELETED" AS ON DELETE TO "$TARGET"
	DO ALSO DELETE FROM "$TABLE" WHERE target_id = old."$KEY";
`

// CreateTable creates the table and rules required to run the ACL,
// will only create new table and rule if they do not already exist
func CreateTable(db *sql.DB, name string, cascades Cascades) error {
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

	for _, link := range cascades.Actors {
		numRows = 0
		row = t.QueryRow("SELECT COUNT(1) FROM pg_rules WHERE tablename = $1 AND rulename = $2", link.Table, name+"_ACTOR_"+link.Table+"_DELETED")
		err = row.Scan(&numRows)
		if err != nil {
			t.Rollback()

			return err
		}

		if numRows == 0 {
			_, err = t.Exec(strings.Replace(strings.Replace(strings.Replace(tpl_actor_delete_trigger, "$TABLE", name, -1), "$ACTOR", link.Table, -1), "$KEY", link.Key, -1))
			if err != nil {
				t.Rollback()

				return err
			}
		}
	}

	for _, link := range cascades.Targets {
		numRows = 0
		row = t.QueryRow("SELECT COUNT(1) FROM pg_rules WHERE tablename = $1 AND rulename = $2", link.Table, name+"_TARGET_"+link.Table+"_DELETED")
		err = row.Scan(&numRows)
		if err != nil {
			t.Rollback()

			return err
		}

		if numRows == 0 {
			_, err = t.Exec(strings.Replace(strings.Replace(strings.Replace(tpl_target_delete_trigger, "$TABLE", name, -1), "$TARGET", link.Table, -1), "$KEY", link.Key, -1))
			if err != nil {
				t.Rollback()

				return err
			}
		}
	}

	return t.Commit()
}
