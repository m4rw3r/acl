package acl

import (
	"database/sql"
)

const (
	EMPTY_RESOURCE = "00000000-0000-0000-0000-000000000000"
)

// Resource represents an object requesting to perform an action or an object acted upon
type Resource interface {
	GetId() string
}

// NilResource is an empty Resource, always returning empty string for id
type NilResource struct{}

// GetId is a dummy function which always returns empty string
func (n NilResource) GetId() string {
	return ""
}

// ActionAuthorizer is an interface which contains the methods to test authorization,
// useful for providing test-stubs instead of a full ACL-implementation
type ActionAuthorizer interface {
	AllowsAction(actor Resource, action string) (bool, error)
	AllowsActionOn(actor Resource, action string, target Resource) (bool, error)
}

// ACL is an object managing permissions for ACO which ARO act upon
type ACL struct {
	table      string
	treeTable  string
	db         *sql.DB
	bypassFunc func(actor Resource, action string, target Resource) bool
}

// NewACL creates a new ACL instance without any bypassFunc
func New(db *sql.DB, treeTable string, table string) *ACL {
	service := &ACL{db: db, treeTable: treeTable, table: table}

	return service
}

// NewACLWithBypass creates a new ACL instance with a bypassFunc
// The bypassFunc can short-circuit access control to allow actions which
// the ACL otherwise would have disallowed (eg. editing the user's own message)
func NewWithBypass(db *sql.DB, treeTable string, table string, bypassFunc func(actor Resource, action string, target Resource) bool) *ACL {
	service := &ACL{db: db, treeTable: treeTable, table: table, bypassFunc: bypassFunc}

	return service
}

// SetActionAllowed stores in the ACL if the Access Request Object is allowed to
// perform the given action or not
func (acl *ACL) SetActionAllowed(actor Resource, action string, allowed bool) error {
	_, err := acl.db.Exec("INSERT INTO \""+acl.table+"\" (actor_id, action, target_id, allowed) VALUES($1, $2, $3, $4)", actor.GetId(), action, EMPTY_RESOURCE, allowed)

	return err
}

// UnsetActionAllowed removes access setting for the user and action, if any
func (acl *ACL) UnsetActionAllowed(actor Resource, action string) error {
	_, err := acl.db.Exec("DELETE FROM \""+acl.table+"\" WHERE actor_id = $1 AND action = $2 AND target_id = $3", actor.GetId(), action, EMPTY_RESOURCE)

	return err
}

// SetActionAllowedOn stores in the ACL if the Access Request Object is allowed to
// perform the given action on a specific Access Control Object or not
func (acl *ACL) SetActionAllowedOn(actor Resource, action string, target Resource, allowed bool) error {
	_, err := acl.db.Exec("INSERT INTO \""+acl.table+"\" (actor_id, action, target_id, allowed) VALUES($1, $2, $3, $4)", actor.GetId(), action, target.GetId(), allowed)

	return err
}

// UnsetActionAllowed removes access setting for the ARO and action on the
// specific ACO, if any setting is present
func (acl *ACL) UnsetActionAllowedOn(actor Resource, action string, target Resource) error {
	_, err := acl.db.Exec("DELETE FROM \""+acl.table+"\" WHERE actor_id = $1 AND action = $2 AND target_id = $3", actor.GetId(), action, target.GetId())

	return err
}

// AllowsAction returns true if the given ARO is allowed to perform action
func (acl *ACL) AllowsAction(actor Resource, action string) (bool, error) {
	target := &NilResource{}

	if acl.bypassFunc != nil && acl.bypassFunc(actor, action, target) {
		return true, nil
	}

	row := acl.db.QueryRow(`WITH RECURSIVE q AS (
	SELECT "parent_id", ARRAY["id"] "path", 1 "level"
	FROM "`+acl.treeTable+`"
	WHERE "id" = $1
UNION ALL
	SELECT t."parent_id", q."path" || t."id", q."level" + 1
	FROM q
	JOIN "`+acl.treeTable+`" t ON t."id" = q."parent_id"
	WHERE NOT t."id" = ANY(q."path")
)
SELECT a."allowed"
FROM (
	SELECT $1 AS "id", 0 "level"
UNION ALL
	SELECT q."parent_id" AS "id", q."level"
	FROM q
) h
JOIN "`+acl.table+`" a ON a."actor_id" = h.id
WHERE a."action" = $2 AND a."target_id" = $3
ORDER BY h."level" ASC, a."allowed" ASC
LIMIT 1`, actor.GetId(), action, EMPTY_RESOURCE)

	allowed := false
	err := row.Scan(&allowed)

	/* No rows is not an error, just means no permissions set */
	if err != nil && err.Error() != "sql: no rows in result set" {
		return false, err
	}

	return allowed, nil
}

// AllowsActionOn returns true if the given ARO is allowed to perform action
// on the given ACO
func (acl *ACL) AllowsActionOn(actor Resource, action string, target Resource) (bool, error) {
	if acl.bypassFunc != nil && acl.bypassFunc(actor, action, target) {
		return true, nil
	}

	row := acl.db.QueryRow(`WITH RECURSIVE q AS (
	SELECT "parent_id", ARRAY["id"] "path", 1 "level"
	FROM "`+acl.treeTable+`"
	WHERE "id" = $1
UNION ALL
	SELECT t."parent_id", q."path" || t."id", q."level" + 1
	FROM q
	JOIN "`+acl.treeTable+`" t ON t."id" = q."parent_id"
	WHERE NOT t."id" = ANY(q."path")
)
SELECT a."allowed"
FROM (
	SELECT $1 AS "id", 0 "level"
UNION ALL
	SELECT q."parent_id" AS "id", q."level"
	FROM q
) h
JOIN "`+acl.table+`" a ON a."actor_id" = h.id
WHERE a."action" = $2 AND (a."target_id" = $3 OR target_id = $4)
ORDER BY h."level" ASC, a."target_id" DESC, a."allowed" ASC
LIMIT 1`, actor.GetId(), action, target.GetId(), EMPTY_RESOURCE)

	allowed := false
	err := row.Scan(&allowed)

	/* No rows is not an error, just means no permissions set */
	if err != nil && err.Error() != "sql: no rows in result set" {
		return false, err
	}

	return allowed, nil
}

func (acl *ACL) SetActorInherits(actor Resource, parentActor Resource) error {
	/* Conditional insert, in case we have an exact duplicate row */
	_, err := acl.db.Exec(`INSERT INTO "`+acl.treeTable+`" ("id", "parent_id") SELECT $1, $2 WHERE NOT EXISTS (SELECT 1 FROM "`+acl.treeTable+`" WHERE "id" = $3 AND "parent_id" = $4)`, actor.GetId(), parentActor.GetId(), actor.GetId(), parentActor.GetId())

	return err
}

func (acl *ACL) RemoveActorInherits(actor Resource, parentActor Resource) error {
	_, err := acl.db.Exec(`DELETE FROM "`+acl.treeTable+`" WHERE ("id", "parent_id") = ($1, $2)`, actor.GetId(), parentActor.GetId())

	return err
}

func (acl *ACL) GetActorInherits(actor Resource) ([]string, error) {
	rows, err := acl.db.Query(`SELECT "parent_id" FROM "`+acl.treeTable+`" WHERE "id" = $1 ORDER BY "id"`, actor.GetId())
	if err != nil {
		return []string{}, err
	}

	var ret []string

	for rows.Next() {
		str := ""

		rows.Scan(&str)

		ret = append(ret, str)
	}

	rows.Close()
	return ret, err
}

func (acl *ACL) GetActorChildren(actor Resource) ([]string, error) {
	rows, err := acl.db.Query(`SELECT "id" FROM "`+acl.treeTable+`" WHERE "parent_id" = $1 ORDER BY "id"`, actor.GetId())
	if err != nil {
		return []string{}, err
	}

	var ret []string

	for rows.Next() {
		str := ""

		rows.Scan(&str)

		ret = append(ret, str)
	}

	rows.Close()
	return ret, err
}
