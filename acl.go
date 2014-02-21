package acl

import (
	"github.com/jmoiron/sqlx"

	"lab.likipe.se/worktaim-api/user"
)

type ACOResource interface {
	GetId() string
}

type NilACOResource struct {}

func (n NilACOResource) GetId() string {
	return ""
}

type ACLService struct {
	table string
	DB *sqlx.DB
	bypassFunc func(user *user.User, action string, resource ACOResource) bool
}

func NewACL(db *sqlx.DB, table string) *ACLService {
	service := ACLService{DB: db, table: table}

	return &service
}

func NewACLWithBypass(db *sqlx.DB, table string, bypassFunc func(user *user.User, action string, resource ACOResource) bool) *ACLService {
	service := ACLService{DB: db, table: table, bypassFunc: bypassFunc}

	return &service
}

func (acl *ACLService) AllowsAction(user *user.User, action string) (bool, error) {
	resource := NilACOResource{}

	if acl.bypassFunc != nil && acl.bypassFunc(user, action, resource) {
		return true, nil
	}



	return true, nil
}

func (acl *ACLService) AllowsAccessToResource(user *user.User, action string, resource *ACOResource) (bool, error) {
	if acl.bypassFunc != nil && acl.bypassFunc(user, action, *resource) {
		return true, nil
	}

	return true, nil
}
