package acl

import (
	"database/sql"
	"testing"
	"os"
	"fmt"

	_ "github.com/lib/pq"
	. "github.com/smartystreets/goconvey/convey"
)

type idAble struct {
	id string
}

func (r idAble) GetId() string {
	return r.id
}

func TestAcl(t *testing.T) {
	requiressl := "disable"

	if os.Getenv("PGREQUIRESSL") == "1" {
		requiressl = "require"
	}

	db, err := sql.Open("postgres", fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", os.Getenv("PGUSER"), os.Getenv("PGPASSWORD"), os.Getenv("PGHOST"), os.Getenv("PGPORT"), os.Getenv("PGDATABASE"), requiressl))

	if err != nil {
		panic(err)
	}

	err = EnsureTablesAndRulesExist(db, "ACL_TestTree", "ACL_Test", Cascades{})
	if err != nil {
		panic(err)
	}

	testUserAllowed := idAble{id: "3eb9e0dc-72fa-4e8f-a188-dcca409220f9"}
	testUserForbidden := idAble{id: "4a567886-2de1-4b0b-9508-5e3125da30f8"}
	dummyUser := idAble{id: "7be24c16-6376-478d-91c9-f879116d1d49"}

	testResourceA := idAble{id: "e74dc49c-e663-4144-9383-1a09c6c7ddfd"}

	acl := New(db, "ACL_TestTree", "ACL_Test")
	aclWithBypassTrue := NewWithBypass(db, "ACL_TestTree", "ACL_Test", func(actor Resource, action string, target Resource) bool {
		return true
	})
	aclWithBypassFalse := NewWithBypass(db, "ACL_TestTree", "ACL_Test", func(actor Resource, action string, target Resource) bool {
		return false
	})

	db.Exec("TRUNCATE \"ACL_Test\";")
	db.Exec("TRUNCATE \"ACL_TestTree\";")

	Convey("With a missing table", t, func() {
		aclNoTable := New(db, "ACL_TestTree", "ACL_TestDoesNotExist")

		Convey("AllowsAction() should return false and error", func() {
			allowed, err := aclNoTable.AllowsAction(testUserAllowed, "test")

			So(allowed, ShouldEqual, false)
			So(err, ShouldNotBeNil)
		})

		Convey("AllowsActionOn() should return false and error", func() {
			allowed, err := aclNoTable.AllowsActionOn(testUserAllowed, "test", testResourceA)

			So(allowed, ShouldEqual, false)
			So(err, ShouldNotBeNil)
		})
	})

	Convey("With an empty database", t, func() {
		Convey("It should always deny access requests without a bypassFunc", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)

			allowed, err = acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)

			allowed, err = acl.AllowsAction(testUserForbidden, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)

			allowed, err = acl.AllowsActionOn(testUserForbidden, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("It should always deny access requests with bypassFunc giving false", func() {

			allowed, err := aclWithBypassFalse.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)

			allowed, err = aclWithBypassFalse.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("It should always allow access requests with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)

			allowed, err = aclWithBypassTrue.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	})

	Convey("When a bypassFunc is set", t, func() {
		Convey("The bypassFunc should receive the actor, action and NilResource on AllowsAction()", func() {
			testActor := Resource(&idAble{id: "a"})
			testAction := ""
			testTarget := Resource(&idAble{id: "b"})

			dummyActor := Resource(&idAble{id: "c"})

			aclWithFunc := NewWithBypass(db, "ACL_TestTree", "ACL_Test", func(actor Resource, action string, target Resource) bool {
				testActor = actor
				testAction = action
				testTarget = target

				return true
			})

			allowed, err := aclWithFunc.AllowsAction(dummyActor, "testString")

			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
			So(testActor, ShouldEqual, dummyActor)
			So(testAction, ShouldEqual, "testString")
			So(testTarget, ShouldHaveSameTypeAs, &NilResource{})
			So(testTarget.GetId(), ShouldEqual, "")
		})

		Convey("The bypassFunc should receive the actor, action and target on AllowsActionOn()", func() {
			testActor := Resource(&idAble{id: "a"})
			testAction := ""
			testTarget := Resource(&idAble{id: "b"})

			dummyActor := Resource(&idAble{id: "c"})
			dummyTarget := Resource(&idAble{id: "c"})

			aclWithFunc := NewWithBypass(db, "ACL_TestTree", "ACL_Test", func(actor Resource, action string, target Resource) bool {
				testActor = actor
				testAction = action
				testTarget = target

				return true
			})

			allowed, err := aclWithFunc.AllowsActionOn(dummyActor, "testString", dummyTarget)

			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
			So(testActor, ShouldEqual, dummyActor)
			So(testAction, ShouldEqual, "testString")
			So(testTarget, ShouldEqual, dummyTarget)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When SetActionAllowed() is set to true", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", true)

		Convey("AllowsAction()   should return true", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		aclWithBypassFalse.SetActionAllowed(testUserAllowed, "test", true)

		Convey("AllowsAction()   should return true with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When SetActionAllowedOn() is set to true", t, func() {
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true)

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsAction()   should return false", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassFalse.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true)

		Convey("AllowsActionOn() should return true  with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsAction()   should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassTrue.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true)

		Convey("AllowsActionOn() should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsAction()   should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When SetActionAllowed() is set to false", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", true)

		Convey("AllowsAction()   should return false", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return false", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassFalse.SetActionAllowed(testUserAllowed, "test", false)

		Convey("AllowsAction()   should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassTrue.SetActionAllowed(testUserAllowed, "test", false)

		Convey("AllowsAction()   should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When SetActionAllowed() is set to true and SetActionAllowedOn() is set to false", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", true)
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, false)

		Convey("AllowsAction()   should return true", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return false", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassFalse.SetActionAllowed(testUserAllowed, "test", true)
		aclWithBypassFalse.SetActionAllowedOn(testUserAllowed, "test", testResourceA, false)

		Convey("AllowsAction()   should return true  with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassFalse.SetActionAllowed(testUserAllowed, "test", true)
		aclWithBypassFalse.SetActionAllowedOn(testUserAllowed, "test", testResourceA, false)

		Convey("AllowsAction()   should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When SetActionAllowed() is set to false and SetActionAllowedOn() is set to true", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", false)
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true)

		Convey("AllowsAction()   should return false", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		aclWithBypassFalse.SetActionAllowed(testUserAllowed, "test", false)
		aclWithBypassFalse.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true)

		Convey("AllowsAction()   should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true  with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		aclWithBypassFalse.SetActionAllowed(testUserAllowed, "test", false)
		aclWithBypassFalse.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true)

		Convey("AllowsAction()   should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When AllowsAction(true) is called after AllowsAction(false)", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", false)
		acl.SetActionAllowed(testUserAllowed, "test", true)

		Convey("AllowsAction()   should return true", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When AllowsAction(false) is called after AllowsAction(true)", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", true)
		acl.SetActionAllowed(testUserAllowed, "test", false)

		Convey("AllowsAction()   should return true", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When AllowsActionOn(true) is called after AllowsActionOn(false)", t, func() {
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, false)
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true)

		Convey("AllowsAction()   should return false", func() {
			acl.UnsetActionAllowed(testUserAllowed, "test")

			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true", func() {

			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When AllowsActionOn(false) is called after AllowsActionOn(true)", t, func() {
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true)
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, false)

		Convey("AllowsAction()   should return false", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When unsetting SetActionAllowed(true)", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", true)
		acl.UnsetActionAllowed(testUserAllowed, "test")

		Convey("AllowsAction()   should return false after unset", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return false after unset", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When unsetting SetActionAllowed(false)", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", false)
		acl.UnsetActionAllowed(testUserAllowed, "test")

		Convey("AllowsAction()   should return false after unset", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return false after unset", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When unsetting SetActionAllowedOn(true)", t, func() {
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true)
		acl.UnsetActionAllowedOn(testUserAllowed, "test", testResourceA)

		Convey("AllowsAction()   should return false after unset", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return false after unset", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When unsetting SetActionAllowedOn(false)", t, func() {
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, false)
		acl.UnsetActionAllowedOn(testUserAllowed, "test", testResourceA)

		Convey("AllowsAction()   should return false after unset", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return false after unset", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When unsetting SetActionAllowed(true) having SetActionAllowedOn(true)", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", true)
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, true)
		acl.UnsetActionAllowed(testUserAllowed, "test")

		Convey("AllowsAction()   should return false after unset", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true  after unset", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When unsetting SetActionAllowedOn(false) having SetActionAllowed(true)", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", true)
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, false)
		acl.UnsetActionAllowedOn(testUserAllowed, "test", testResourceA)

		Convey("AllowsAction()   should return false after unset", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true  after unset", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")

	Convey("When unsetting SetActionAllowedOn(true) having SetActionAllowed(false)", t, func() {
		acl.SetActionAllowed(testUserAllowed, "test", false)
		acl.SetActionAllowedOn(testUserAllowed, "test", testResourceA, false)
		acl.UnsetActionAllowedOn(testUserAllowed, "test", testResourceA)

		Convey("AllowsAction()   should return false after unset", func() {
			allowed, err := acl.AllowsAction(testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true  after unset", func() {
			allowed, err := acl.AllowsActionOn(testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	})

	db.Exec("TRUNCATE \"ACL_Test\";")
	db.Exec("TRUNCATE \"ACL_TestTree\";")

	Convey("With no hierarchy", t, func() {
		Convey("GetActorInherits() should return empty array", func() {
			parents, err := acl.GetActorInherits(testUserAllowed)

			So(err, ShouldBeNil)
			So(len(parents), ShouldEqual, 0)
		})

		Convey("GetActorDescendants() should return empty array", func() {
			children, err := acl.GetActorChildren(testUserForbidden)

			So(err, ShouldBeNil)
			So(len(children), ShouldEqual, 0)
		})
	})

	Convey("When using SetActorInherits() to establish a hierarchy", t, func() {
		Convey("It should not error when setting a new relation", func() {
			err := acl.SetActorInherits(testUserAllowed, testUserForbidden)

			So(err, ShouldBeNil)
		})

		Convey("It should not error when setting an already set relation", func() {
			err := acl.SetActorInherits(testUserAllowed, testUserForbidden)
			So(err, ShouldBeNil)

			err = acl.SetActorInherits(testUserAllowed, testUserForbidden)
			So(err, ShouldBeNil)
		})

		Convey("GetActorInherits() should display the relation", func() {
			err := acl.SetActorInherits(testUserAllowed, testUserForbidden)
			So(err, ShouldBeNil)

			parents, err := acl.GetActorInherits(testUserAllowed)

			So(err, ShouldBeNil)
			So(parents, ShouldResemble, []string{testUserForbidden.GetId()})
		})

		Convey("GetActorInherits() shoud display all parents", func() {
			err := acl.SetActorInherits(testUserAllowed, testUserForbidden)
			So(err, ShouldBeNil)

			err = acl.SetActorInherits(testUserAllowed, dummyUser)
			So(err, ShouldBeNil)

			parents, err := acl.GetActorInherits(testUserAllowed)

			So(err, ShouldBeNil)
			So(parents, ShouldResemble, []string{testUserForbidden.GetId(), dummyUser.GetId()})
		})

		Convey("GetActorChildren() should display all children", func() {
			err := acl.SetActorInherits(testUserAllowed, testUserForbidden)
			So(err, ShouldBeNil)

			err = acl.SetActorInherits(dummyUser, testUserForbidden)
			So(err, ShouldBeNil)

			children, err := acl.GetActorChildren(testUserForbidden)

			So(err, ShouldBeNil)
			So(children, ShouldResemble, []string{testUserAllowed.GetId(), dummyUser.GetId()})
		})
	})

	Convey("When a hierarchy exists", t, func() {
		err := acl.SetActorInherits(testUserAllowed, testUserForbidden)
		So(err, ShouldBeNil)

		err = acl.SetActorInherits(testUserAllowed, dummyUser)
		So(err, ShouldBeNil)

		err = acl.SetActorInherits(dummyUser, testUserForbidden)
		So(err, ShouldBeNil)

		Convey("RemoveActorInherits() should remove the relation", func() {
			children, err := acl.GetActorChildren(testUserForbidden)

			So(err, ShouldBeNil)
			So(children, ShouldResemble, []string{testUserAllowed.GetId(), dummyUser.GetId()})

			err = acl.RemoveActorInherits(testUserAllowed, testUserForbidden)

			So(err, ShouldBeNil)

			children, err = acl.GetActorChildren(testUserForbidden)

			So(err, ShouldBeNil)
			So(children, ShouldResemble, []string{dummyUser.GetId()})

			children, err = acl.GetActorChildren(dummyUser)

			So(err, ShouldBeNil)
			So(children, ShouldResemble, []string{testUserAllowed.GetId()})
		})
	})

	db.Exec("TRUNCATE \"ACL_TestTree\";")

	Convey("When a relation exists between A -> B", t, func() {
		err := acl.SetActorInherits(testUserAllowed, testUserForbidden)
		So(err, ShouldBeNil)

		Convey("Attempting to establish B -> A should return an error", func() {
			err := acl.SetActorInherits(testUserForbidden, testUserAllowed)
			So(err, ShouldNotBeNil)

			Convey("And the relation should not be established", func() {
				children, err := acl.GetActorInherits(testUserForbidden)
				So(err, ShouldBeNil)
				So(children, ShouldNotContain, testUserAllowed.GetId())
			})
		})

		Convey("Attempting to establish B -> C -> A should return an error", func() {
			err := acl.SetActorInherits(testUserForbidden, dummyUser)
			So(err, ShouldBeNil)

			err = acl.SetActorInherits(dummyUser, testUserAllowed)
			So(err, ShouldNotBeNil)

			Convey("And the relation should not be established", func() {
				children, err := acl.GetActorInherits(dummyUser)
				So(err, ShouldBeNil)
				So(children, ShouldNotContain, testUserAllowed.GetId())
			})
		})
	})

	/* TODO: Tests for ARO hierarchy */
}
