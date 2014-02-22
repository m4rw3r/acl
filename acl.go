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

// ACL is an object managing permissions for ACO which ARO act upon
type ACL struct {
	table      string
	db         *sql.DB
	bypassFunc func(actor Resource, action string, target Resource) bool
}

// NewACL creates a new ACL instance without any bypassFunc
func NewACL(db *sql.DB, table string) *ACL {
	service := &ACL{db: db, table: table}

	return service
}

// NewACLWithBypass creates a new ACL instance with a bypassFunc
// The bypassFunc can short-circuit access control to allow actions which
// the ACL otherwise would have disallowed (eg. editing the user's own message)
func NewACLWithBypass(db *sql.DB, table string, bypassFunc func(actor Resource, action string, target Resource) bool) *ACL {
	service := &ACL{db: db, table: table, bypassFunc: bypassFunc}

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

	row := acl.db.QueryRow("SELECT allowed FROM \""+acl.table+"\" WHERE actor_id = $1 AND action = $2 AND target_id = $3 LIMIT 1", actor.GetId(), action, EMPTY_RESOURCE)

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

	row := acl.db.QueryRow("SELECT allowed FROM \""+acl.table+"\" WHERE actor_id = $1 AND action = $2 AND (target_id = $3 OR target_id = $4) ORDER BY target_id DESC LIMIT 1", actor.GetId(), action, target.GetId(), EMPTY_RESOURCE)

	allowed := false
	err := row.Scan(&allowed)

	/* No rows is not an error, just means no permissions set */
	if err != nil && err.Error() != "sql: no rows in result set" {
		return false, err
	}

	return allowed, nil
}
