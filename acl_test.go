package acl

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"lab.likipe.se/worktaim-api/config"
	"lab.likipe.se/worktaim-api/postgresql"
	"lab.likipe.se/worktaim-api/util"
)

type idAble struct {
	id string
}

func (r idAble) GetId() string {
	return r.id
}

func TestAcl(t *testing.T) {
	config := config.LoadConfiguration("../config_test.json")

	db := postgresql.CreateConnection(config)

	err := CreateTable(db, "ACL_Test")
	util.PanicIf(err)

	testUserAllowed   := idAble{id: "3eb9e0dc-72fa-4e8f-a188-dcca409220f9"}
	testUserForbidden := idAble{id: "4a567886-2de1-4b0b-9508-5e3125da30f8"}

	testResourceA := idAble{id: "e74dc49c-e663-4144-9383-1a09c6c7ddfd"}
	// testResourceB := idAble{id: "98a66485-7c49-4f71-ad3c-6db457d54335"}

	acl := NewACL(db, "ACL_Test")
	aclWithBypassTrue := NewACLWithBypass(db, "ACL_Test", func(actor Resource, action string, target Resource) bool {
		return true
	})
	aclWithBypassFalse := NewACLWithBypass(db, "ACL_Test", func(actor Resource, action string, target Resource) bool {
		return false
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("With an empty database", t, func() {
		Convey("It should always deny access requests without a bypassFunc", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)

			allowed, err = acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)

			allowed, err = acl.AllowsAction(testUserForbidden, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)

			allowed, err = acl.AllowsActionOn(testUserForbidden, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)
		})

		Convey("It should always deny access requests with bypassFunc giving false", func() {

			allowed, err := aclWithBypassFalse.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)

			allowed, err = aclWithBypassFalse.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)
		})

		Convey("It should always allow access requests with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)

			allowed, err = aclWithBypassTrue.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When SetActionAllowed() is set to true", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", true);

		Convey("AllowsAction()   should return true", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})

		aclWithBypassFalse.SetActionAllowed(testUserAllowed, "test", true);

		Convey("AllowsAction()   should return true with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When SetActionAllowedOn() is set to true", t, func() {
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true);

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsAction()   should return false", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassFalse.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true);

		Convey("AllowsActionOn() should return true  with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsAction()   should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassTrue.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true);

		Convey("AllowsActionOn() should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsAction()   should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When SetActionAllowed() is set to false", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", true);

		Convey("AllowsAction()   should return false", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return false", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassFalse.SetActionAllowed(testUserAllowed, "test", false);

		Convey("AllowsAction()   should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassTrue.SetActionAllowed(testUserAllowed, "test", false);

		Convey("AllowsAction()   should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When SetActionAllowed() is set to true and SetActionAllowedOn() is set to false", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", true)
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, false)

		Convey("AllowsAction()   should return true", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return false", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassFalse.SetActionAllowed(testUserAllowed, "test", true);
		aclWithBypassFalse.SetActionAllowedOn(testUserAllowed, "test", testResourceA, false);

		Convey("AllowsAction()   should return true  with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassFalse.SetActionAllowed(testUserAllowed, "test", true);
		aclWithBypassFalse.SetActionAllowedOn(testUserAllowed, "test", testResourceA, false);

		Convey("AllowsAction()   should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When SetActionAllowed() is set to false and SetActionAllowedOn() is set to true", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", false)
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true)

		Convey("AllowsAction()   should return false", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})

		aclWithBypassFalse.SetActionAllowed(testUserAllowed, "test", false);
		aclWithBypassFalse.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true);

		Convey("AllowsAction()   should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true  with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})

		aclWithBypassFalse.SetActionAllowed(testUserAllowed, "test", false);
		aclWithBypassFalse.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true);

		Convey("AllowsAction()   should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(testUserAllowed, "test")
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsActionOn(testUserAllowed, "test", testResourceA)
			util.PanicIf(err)
			So(allowed, ShouldEqual, true)
		})
	})

	/* TODO: Tests for ARO hierarchy */
	/* TODO: Tests to make sure that SetActionAllowed(), SetActionAllowedOn(), UnsetActionAllowed() and UnsetActionAllowedOn() actually write their changes when used in combination */
	/* TODO: Tests for UnsetActionAllowed() and UnsetActionAllowedOn() */
}
