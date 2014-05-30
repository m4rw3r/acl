package acl

import (
	"database/sql"
	"strings"
	"fmt"
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

var tpl_tree_table = `CREATE TABLE "$TABLE"
(
	"id" uuid NOT NULL,
	"parent_id" uuid,
	PRIMARY KEY ("id", "parent_id")
);`

var tpl_tree_insert_trigger_function = `
CREATE OR REPLACE FUNCTION $TABLE_PreventCycles()
  RETURNS "trigger" AS $$
BEGIN
	IF EXISTS (WITH RECURSIVE q AS (
			SELECT q."parent_id", ARRAY[NEW."parent_id"] path
			FROM "$TABLE" q
			WHERE q."id" = NEW."parent_id"
		UNION
			SELECT t.parent_id, q.path || t.id
			FROM q
			JOIN "$TABLE" t ON t.id = q."parent_id" AND NOT (t.id = ANY(q.path))
		)
		SELECT q.parent_id FROM q
		WHERE NEW.id = q.parent_id) THEN
		RAISE EXCEPTION 'Cycles are not allowed in "$TABLE"';
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE 'plpgsql' VOLATILE;
`;

var tpl_tree_insert_trigger = `
CREATE TRIGGER $TABLE_PreventCyclesTrigger
	BEFORE INSERT OR UPDATE
	ON "$TABLE"
	FOR EACH ROW
	EXECUTE PROCEDURE $TABLE_PreventCycles();`

var tpl_actor_delete_trigger = `
CREATE RULE "{treeTable}_{relatedTable}_DELETED_REMOVE_PRIMARY" AS ON DELETE TO "{relatedTable}"
	DO ALSO DELETE FROM "{treeTable}" WHERE "id" = old."{relatedKey}" OR "parent_id" = old."{relatedKey}";`

var tpl_acl_table = `CREATE TABLE "$TABLE"
(
	"actor_id" uuid NOT NULL,
	"action" character varying(255) NOT NULL,
	"target_id" uuid DEFAULT '00000000-0000-0000-0000-000000000000',
	"allowed" bool NOT NULL,
	PRIMARY KEY ("actor_id", "action", "target_id")
);`

var tpl_insert_rule = `
CREATE RULE "$TABLE_INSERT" AS ON INSERT TO "$TABLE"
	WHERE EXISTS(SELECT 1 FROM "$TABLE"
		WHERE (actor_id, action, target_id) = (NEW.actor_id, NEW.action, NEW.target_id))
	DO INSTEAD UPDATE "$TABLE" SET allowed = NEW.allowed WHERE (actor_id, action, target_id) = (NEW.actor_id, NEW.action, NEW.target_id);`

var tpl_link_delete_trigger = `
CREATE RULE "{aclTable}_{linkType}_{relatedTable}_DELETED" AS ON DELETE TO "{relatedTable}"
	DO ALSO DELETE FROM "{aclTable}" WHERE "{localKey}" = old."{relatedKey}";`

// EnsureTableAndRulesAreCreated checks if the table and rules required to run the ACL exists,
// if they do not they will be created
func EnsureTablesAndRulesExist(db *sql.DB, treeTable string, table string, cascades Cascades) error {
	t, err := db.Begin()
	if err != nil {
		return err
	}

	exists, err := tableExists(t, treeTable)
	if err != nil {
		t.Rollback()

		return err
	}
	if ! exists {
		_, err = t.Exec(strings.Replace(tpl_tree_table, "$TABLE", treeTable, -1))
		if err != nil {
			t.Rollback()

			return err
		}
	}

	_, err = t.Exec(strings.Replace(tpl_tree_insert_trigger_function, "$TABLE", treeTable, -1))
	if err != nil {
		fmt.Printf("%v\n", err)
		t.Rollback()

		return err
	}

	_, err = t.Exec(fmt.Sprintf(`DROP TRIGGER IF EXISTS %s_PreventCyclesTrigger ON "%s";`, treeTable, treeTable))
	if err != nil {
		t.Rollback()

		return err
	}

	_, err = t.Exec(strings.Replace(tpl_tree_insert_trigger, "$TABLE", treeTable, -1))
	if err != nil {
		t.Rollback()

		return err
	}

	err = ensureTreeLinks(t, treeTable, cascades.Actors)
	if err != nil {
		t.Rollback()

		return err
	}

	exists, err = tableExists(t, table)
	if err != nil {
		t.Rollback()

		return err
	}
	if ! exists {
		/* No row, insert new table */
		_, err = t.Exec(strings.Replace(tpl_acl_table, "$TABLE", table, -1))
		if err != nil {
			t.Rollback()

			return err
		}
	}

	exists, err = ruleExists(t, table, table+"_INSERT")
	if err != nil {
		t.Rollback()

		return err
	}
	if ! exists {
		/* No row, insert new rule */
		_, err = t.Exec(strings.Replace(tpl_insert_rule, "$TABLE", table, -1))
		if err != nil {
			t.Rollback()

			return err
		}
	}

	err = ensureLinks(t, table, cascades.Actors, "ACTOR", "actor_id")
	if err != nil {
		t.Rollback()

		return err
	}

	err = ensureLinks(t, table, cascades.Targets, "TARGET", "target_id")
	if err != nil {
		t.Rollback()

		return err
	}

	return t.Commit()
}

// tableExists returns true if the supplied table name exists
func tableExists(t *sql.Tx, tableName string) (bool, error) {
	numRows := 0
	row := t.QueryRow("SELECT COUNT(1) FROM information_schema.tables WHERE table_name = $1", tableName)

	err := row.Scan(&numRows)
	if err != nil {
		return false, err
	}
	
	return numRows == 1, nil
}

// ruleExists returs true if the supplied rule exists on the given table
func ruleExists(t *sql.Tx, tableName string, ruleName string) (bool, error) {
	numRows := 0
	row := t.QueryRow("SELECT COUNT(1) FROM pg_rules WHERE tablename = $1 AND rulename = $2", tableName, ruleName)

	err := row.Scan(&numRows)
	if err != nil {
		return false, err
	}

	return numRows == 1, nil
}

func ensureTreeLinks(t *sql.Tx, treeTable string, links []Link) error {
	for _, link := range links {
		exists, err := ruleExists(t, link.Table, fmt.Sprintf("%s_%s_DELETED_REMOVE_PRIMARY", treeTable, link.Table))
		if err != nil {
			return err
		}

		if ! exists {
			replacer := strings.NewReplacer("{treeTable}", treeTable, "{relatedTable}", link.Table, "{relatedKey}", link.Key)

			_, err = t.Exec(replacer.Replace(tpl_actor_delete_trigger))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func ensureLinks(t *sql.Tx, tableName string, links []Link, linkType string, linkColumn string) error {
	for _, link := range links {
		exists, err := ruleExists(t, link.Table, fmt.Sprintf("%s_%s_%s_DELETED", tableName, linkType, link.Table))
		if err != nil {
			return err
		}

		if ! exists {
			replacer := strings.NewReplacer("{aclTable}", tableName, "{linkType}", linkType, "{relatedTable}", link.Table, "{localKey}", linkColumn, "{relatedKey}", link.Key)

			_, err = t.Exec(replacer.Replace(tpl_link_delete_trigger))
			if err != nil {
				return err
			}
		}
	}

	return nil
}
