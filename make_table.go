package acl

import (
	"database/sql"
	"strings"

	"github.com/jmoiron/sqlx"
)

var tpl_table = `CREATE TABLE "$TABLE"
(
	"actor_id" uuid NOT NULL,
	"action" character varying(255) NOT NULL,
	"target_id" uuid DEFAULT '138fcc81-dcf5-4595-8d0d-9e104b491372',
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
func CreateTable(db *sqlx.DB, name string) error {
	t := db.MustBegin()

	rows, err := t.Query("SELECT table_name FROM information_schema.tables WHERE table_name = $1", name)
	if err != nil {
		t.Rollback()

		return err
	}

	row, err := hasRow(rows)
	if err != nil {
		t.Rollback()

		return err
	}

	if ! row {
		/* No row, insert new table */
		_, err = t.Exec(strings.Replace(tpl_table, "$TABLE", name, -1))
		if err != nil {
			t.Rollback()

			return err
		}
	}

	rows, err = t.Query("SELECT rulename FROM pg_rules WHERE rulename = $1", name + "_INSERT")
	if err != nil {
		t.Rollback()

		return err
	}

	row, err = hasRow(rows)
	if err != nil {
		t.Rollback()

		return err
	}

	if ! row {
		/* No row, insert new rule */
		_, err = t.Exec(strings.Replace(tpl_insert_rule, "$TABLE", name, -1))
		if err != nil {
			t.Rollback()

			return err
		}
	}

	return t.Commit()
}

// hasRow is a utility function which checks if rows has a row and then closes the iteration
func hasRow(rows *sql.Rows) (bool, error) {
	hasRow := rows.Next()

	return hasRow, rows.Close()
}

/* TODO: Needs a way to create cascades for when actors and targets are removed from the database */
