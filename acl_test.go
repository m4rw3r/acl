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

func WithTransaction(db *sql.DB, f func(tx *sql.Tx)) func() {
	return func() {
		tx, err := db.Begin()
		So(err, ShouldBeNil)

		/* Clear tables used in tests */
		_, err = tx.Exec("TRUNCATE \"ACL_Test\";")
		So(err, ShouldBeNil)
		_, err = tx.Exec("TRUNCATE \"ACL_TestTree\";")
		So(err, ShouldBeNil)

		Reset(func() {
			defer tx.Rollback()

			_, err := tx.Exec("SELECT 1")
			So(err, ShouldBeNil)
		})

		f(tx)
	}
}

func WithTransactionExpectFail(db *sql.DB, f func(tx *sql.Tx)) func() {
	return func() {
		tx, err := db.Begin()
		So(err, ShouldBeNil)

		/* Clear tables used in tests */
		_, err = tx.Exec("TRUNCATE \"ACL_Test\";")
		So(err, ShouldBeNil)
		_, err = tx.Exec("TRUNCATE \"ACL_TestTree\";")
		So(err, ShouldBeNil)

		Reset(func() {
			defer tx.Rollback()

			_, err := tx.Exec("SELECT 1")
			So(err, ShouldNotBeNil)
		})

		f(tx)
	}
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

	acl := New("ACL_TestTree", "ACL_Test")
	aclWithBypassTrue := NewWithBypass("ACL_TestTree", "ACL_Test", func(actor Resource, action string, target Resource) bool {
		return true
	})
	aclWithBypassFalse := NewWithBypass("ACL_TestTree", "ACL_Test", func(actor Resource, action string, target Resource) bool {
		return false
	})

	Convey("With a missing table", t, WithTransactionExpectFail(db, func(tx *sql.Tx) {
		aclNoTable := New("ACL_TestTree", "ACL_TestDoesNotExist")

		Convey("AllowsAction() should return false and error", func() {
			allowed, err := aclNoTable.AllowsAction(tx, testUserAllowed, "test")

			So(allowed, ShouldEqual, false)
			So(err, ShouldNotBeNil)
		})

		Convey("AllowsActionOn() should return false and error", func() {
			allowed, err := aclNoTable.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)

			So(allowed, ShouldEqual, false)
			So(err, ShouldNotBeNil)
		})
	}))

	Convey("With an empty database", t, WithTransaction(db , func(tx *sql.Tx) {
		Convey("It should always deny access requests without a bypassFunc", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)

			allowed, err = acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)

			allowed, err = acl.AllowsAction(tx, testUserForbidden, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)

			allowed, err = acl.AllowsActionOn(tx, testUserForbidden, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("It should always deny access requests with bypassFunc giving false", func() {

			allowed, err := aclWithBypassFalse.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)

			allowed, err = aclWithBypassFalse.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("It should always allow access requests with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)

			allowed, err = aclWithBypassTrue.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	}))

	Convey("When a bypassFunc is set", t, WithTransaction(db, func(tx *sql.Tx) {
		Convey("The bypassFunc should receive the actor, action and NilResource on AllowsAction()", func() {
			testActor := Resource(&idAble{id: "a"})
			testAction := ""
			testTarget := Resource(&idAble{id: "b"})

			dummyActor := Resource(&idAble{id: "c"})

			aclWithFunc := NewWithBypass("ACL_TestTree", "ACL_Test", func(actor Resource, action string, target Resource) bool {
				testActor = actor
				testAction = action
				testTarget = target

				return true
			})

			allowed, err := aclWithFunc.AllowsAction(tx, dummyActor, "testString")

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

			aclWithFunc := NewWithBypass("ACL_TestTree", "ACL_Test", func(actor Resource, action string, target Resource) bool {
				testActor = actor
				testAction = action
				testTarget = target

				return true
			})

			allowed, err := aclWithFunc.AllowsActionOn(tx, dummyActor, "testString", dummyTarget)

			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
			So(testActor, ShouldEqual, dummyActor)
			So(testAction, ShouldEqual, "testString")
			So(testTarget, ShouldEqual, dummyTarget)
		})
	}))

	Convey("When SetActionAllowed() is set to true", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowed(tx, testUserAllowed, "test", true)

		Convey("AllowsAction()   should return true", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		aclWithBypassFalse.SetActionAllowed(tx, testUserAllowed, "test", true)

		Convey("AllowsAction()   should return true with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	}))

	Convey("When SetActionAllowedOn() is set to true", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, true)

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsAction()   should return false", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassFalse.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, true)

		Convey("AllowsActionOn() should return true  with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsAction()   should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassTrue.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, true)

		Convey("AllowsActionOn() should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsAction()   should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	}))

	Convey("When SetActionAllowed() is set to false", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowed(tx, testUserAllowed, "test", true)

		Convey("AllowsAction()   should return false", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return false", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassFalse.SetActionAllowed(tx, testUserAllowed, "test", false)

		Convey("AllowsAction()   should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassTrue.SetActionAllowed(tx, testUserAllowed, "test", false)

		Convey("AllowsAction()   should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	}))

	Convey("When SetActionAllowed() is set to true and SetActionAllowedOn() is set to false", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowed(tx, testUserAllowed, "test", true)
		acl.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, false)

		Convey("AllowsAction()   should return true", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return false", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassFalse.SetActionAllowed(tx, testUserAllowed, "test", true)
		aclWithBypassFalse.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, false)

		Convey("AllowsAction()   should return true  with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		aclWithBypassFalse.SetActionAllowed(tx, testUserAllowed, "test", true)
		aclWithBypassFalse.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, false)

		Convey("AllowsAction()   should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	}))

	Convey("When SetActionAllowed() is set to false and SetActionAllowedOn() is set to true", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowed(tx, testUserAllowed, "test", false)
		acl.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, true)

		Convey("AllowsAction()   should return false", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		aclWithBypassFalse.SetActionAllowed(tx, testUserAllowed, "test", false)
		aclWithBypassFalse.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, true)

		Convey("AllowsAction()   should return false with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true  with bypassFunc giving false", func() {
			allowed, err := aclWithBypassFalse.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		aclWithBypassFalse.SetActionAllowed(tx, testUserAllowed, "test", false)
		aclWithBypassFalse.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, true)

		Convey("AllowsAction()   should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true  with bypassFunc giving true", func() {
			allowed, err := aclWithBypassTrue.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	}))

	Convey("When AllowsAction(true) is called after AllowsAction(false)", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowed(tx, testUserAllowed, "test", false)
		acl.SetActionAllowed(tx, testUserAllowed, "test", true)

		Convey("AllowsAction()   should return true", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	}))

	Convey("When AllowsAction(false) is called after AllowsAction(true)", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowed(tx, testUserAllowed, "test", true)
		acl.SetActionAllowed(tx, testUserAllowed, "test", false)

		Convey("AllowsAction()   should return true", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	}))

	Convey("When AllowsActionOn(true) is called after AllowsActionOn(false)", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, false)
		acl.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, true)

		Convey("AllowsAction()   should return false", func() {
			acl.UnsetActionAllowed(tx, testUserAllowed, "test")

			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true", func() {

			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	}))

	Convey("When AllowsActionOn(false) is called after AllowsActionOn(true)", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, true)
		acl.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, false)

		Convey("AllowsAction()   should return false", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	}))

	Convey("When unsetting SetActionAllowed(true)", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowed(tx, testUserAllowed, "test", true)
		acl.UnsetActionAllowed(tx, testUserAllowed, "test")

		Convey("AllowsAction()   should return false after unset", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return false after unset", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	}))

	Convey("When unsetting SetActionAllowed(false)", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowed(tx, testUserAllowed, "test", false)
		acl.UnsetActionAllowed(tx, testUserAllowed, "test")

		Convey("AllowsAction()   should return false after unset", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return false after unset", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	}))

	Convey("When unsetting SetActionAllowedOn(true)", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, true)
		acl.UnsetActionAllowedOn(tx, testUserAllowed, "test", testResourceA)

		Convey("AllowsAction()   should return false after unset", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return false after unset", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	}))

	Convey("When unsetting SetActionAllowedOn(false)", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, false)
		acl.UnsetActionAllowedOn(tx, testUserAllowed, "test", testResourceA)

		Convey("AllowsAction()   should return false after unset", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return false after unset", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	}))

	Convey("When unsetting SetActionAllowed(true) having SetActionAllowedOn(true)", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowed(tx, testUserAllowed, "test", true)
		acl.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, true)
		acl.UnsetActionAllowed(tx, testUserAllowed, "test")

		Convey("AllowsAction()   should return false after unset", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true  after unset", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	}))

	Convey("When unsetting SetActionAllowedOn(false) having SetActionAllowed(true)", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowed(tx, testUserAllowed, "test", true)
		acl.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, false)
		acl.UnsetActionAllowedOn(tx, testUserAllowed, "test", testResourceA)

		Convey("AllowsAction()   should return false after unset", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("AllowsActionOn() should return true  after unset", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})
	}))

	Convey("When unsetting SetActionAllowedOn(true) having SetActionAllowed(false)", t, WithTransaction(db, func(tx *sql.Tx) {
		acl.SetActionAllowed(tx, testUserAllowed, "test", false)
		acl.SetActionAllowedOn(tx, testUserAllowed, "test", testResourceA, false)
		acl.UnsetActionAllowedOn(tx, testUserAllowed, "test", testResourceA)

		Convey("AllowsAction()   should return false after unset", func() {
			allowed, err := acl.AllowsAction(tx, testUserAllowed, "test")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})

		Convey("AllowsActionOn() should return true  after unset", func() {
			allowed, err := acl.AllowsActionOn(tx, testUserAllowed, "test", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	}))

	Convey("With no hierarchy", t, WithTransaction(db, func(tx *sql.Tx) {
		Convey("GetActorInherits() should return empty array", func() {
			parents, err := acl.GetActorInherits(tx, testUserAllowed)

			So(err, ShouldBeNil)
			So(len(parents), ShouldEqual, 0)
		})

		Convey("GetActorDescendants() should return empty array", func() {
			children, err := acl.GetActorChildren(tx, testUserForbidden)

			So(err, ShouldBeNil)
			So(len(children), ShouldEqual, 0)
		})
	}))

	Convey("When using SetActorInherits() to establish a hierarchy", t, WithTransaction(db, func(tx *sql.Tx) {
		Convey("It should not error when setting a new relation", func() {
			err := acl.SetActorInherits(tx, testUserAllowed, testUserForbidden)

			So(err, ShouldBeNil)
		})

		Convey("It should not error when setting an already set relation", func() {
			err := acl.SetActorInherits(tx, testUserAllowed, testUserForbidden)
			So(err, ShouldBeNil)

			err = acl.SetActorInherits(tx, testUserAllowed, testUserForbidden)
			So(err, ShouldBeNil)
		})

		Convey("GetActorInherits() should display the relation", func() {
			err := acl.SetActorInherits(tx, testUserAllowed, testUserForbidden)
			So(err, ShouldBeNil)

			parents, err := acl.GetActorInherits(tx, testUserAllowed)

			So(err, ShouldBeNil)
			So(parents, ShouldResemble, []string{testUserForbidden.GetId()})
		})

		Convey("GetActorInherits() shoud display all parents", func() {
			err := acl.SetActorInherits(tx, testUserAllowed, testUserForbidden)
			So(err, ShouldBeNil)

			err = acl.SetActorInherits(tx, testUserAllowed, dummyUser)
			So(err, ShouldBeNil)

			parents, err := acl.GetActorInherits(tx, testUserAllowed)

			So(err, ShouldBeNil)
			So(parents, ShouldResemble, []string{testUserForbidden.GetId(), dummyUser.GetId()})
		})

		Convey("GetActorChildren() should display all children", func() {
			err := acl.SetActorInherits(tx, testUserAllowed, testUserForbidden)
			So(err, ShouldBeNil)

			err = acl.SetActorInherits(tx, dummyUser, testUserForbidden)
			So(err, ShouldBeNil)

			children, err := acl.GetActorChildren(tx, testUserForbidden)

			So(err, ShouldBeNil)
			So(children, ShouldResemble, []string{testUserAllowed.GetId(), dummyUser.GetId()})
		})
	}))

	Convey("When a hierarchy exists", t, WithTransaction(db, func(tx *sql.Tx) {
		err := acl.SetActorInherits(tx, testUserAllowed, testUserForbidden)
		So(err, ShouldBeNil)

		err = acl.SetActorInherits(tx, testUserAllowed, dummyUser)
		So(err, ShouldBeNil)

		err = acl.SetActorInherits(tx, dummyUser, testUserForbidden)
		So(err, ShouldBeNil)

		Convey("RemoveActorInherits() should remove the relation", func() {
			children, err := acl.GetActorChildren(tx, testUserForbidden)

			So(err, ShouldBeNil)
			So(children, ShouldResemble, []string{testUserAllowed.GetId(), dummyUser.GetId()})

			err = acl.RemoveActorInherits(tx, testUserAllowed, testUserForbidden)

			So(err, ShouldBeNil)

			children, err = acl.GetActorChildren(tx, testUserForbidden)

			So(err, ShouldBeNil)
			So(children, ShouldResemble, []string{dummyUser.GetId()})

			children, err = acl.GetActorChildren(tx, dummyUser)

			So(err, ShouldBeNil)
			So(children, ShouldResemble, []string{testUserAllowed.GetId()})
		})
	}))

	Convey("When a relation exists between A -> B", t, WithTransactionExpectFail(db, func(tx *sql.Tx) {
		err = acl.SetActorInherits(tx, testUserAllowed, testUserForbidden)
		So(err, ShouldBeNil)

		Convey("Attempting to establish B -> A should return an error", func() {
			err := acl.SetActorInherits(tx, testUserForbidden, testUserAllowed)
			So(err, ShouldNotBeNil)
		})

		Convey("Attempting to establish B -> C -> A should return an error", func() {
			err := acl.SetActorInherits(tx, testUserForbidden, dummyUser)
			So(err, ShouldBeNil)

			err = acl.SetActorInherits(tx, dummyUser, testUserAllowed)
			So(err, ShouldNotBeNil)
		})
	}))

	Convey("When A inherits from B", t, WithTransaction(db, func(tx *sql.Tx) {
		err := acl.SetActorInherits(tx, testUserAllowed, testUserForbidden)
		So(err, ShouldBeNil)

		Convey("SetActionAllowed(true) on B should allow A", func() {
			err = acl.SetActionAllowed(tx, testUserForbidden, "testing", true)
			So(err, ShouldBeNil)

			allowed, err := acl.AllowsAction(tx, testUserForbidden, "testing")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)

			allowed, err = acl.AllowsAction(tx, testUserAllowed, "testing")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)

			Convey("And SetActionAllowed(false) on A should disable A", func() {
				err = acl.SetActionAllowed(tx, testUserAllowed, "testing", false)
				So(err, ShouldBeNil)

				allowed, err := acl.AllowsAction(tx, testUserForbidden, "testing")
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, true)

				allowed, err = acl.AllowsAction(tx, testUserAllowed, "testing")
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, false)
			})

			Convey("And SetActionAllowed(true) on A should enable A", func() {
				err = acl.SetActionAllowed(tx, testUserAllowed, "testing", true)
				So(err, ShouldBeNil)

				allowed, err := acl.AllowsAction(tx, testUserForbidden, "testing")
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, true)

				allowed, err = acl.AllowsAction(tx, testUserAllowed, "testing")
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, true)
			})
		})

		Convey("SetActionAllowed(false) on B should disable A", func() {
			err = acl.SetActionAllowed(tx, testUserForbidden, "testing", false)
			So(err, ShouldBeNil)

			allowed, err := acl.AllowsAction(tx, testUserForbidden, "testing")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)

			allowed, err = acl.AllowsAction(tx, testUserAllowed, "testing")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)

			Convey("And SetActionAllowed(true) on A should allow A", func() {
				err = acl.SetActionAllowed(tx, testUserAllowed, "testing", true)
				So(err, ShouldBeNil)

				allowed, err := acl.AllowsAction(tx, testUserForbidden, "testing")
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, false)

				allowed, err = acl.AllowsAction(tx, testUserAllowed, "testing")
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, true)
			})

			Convey("And SetActionAllowed(false) on A should still disable A", func() {
				err = acl.SetActionAllowed(tx, testUserAllowed, "testing", false)
				So(err, ShouldBeNil)

				allowed, err := acl.AllowsAction(tx, testUserForbidden, "testing")
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, false)

				allowed, err = acl.AllowsAction(tx, testUserAllowed, "testing")
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, false)
			})
		})

		Convey("SetActionAllowedOn(true) on B should allow A on resource", func() {
			err = acl.SetActionAllowedOn(tx, testUserForbidden, "testing", testResourceA, true)
			So(err, ShouldBeNil)

			allowed, err := acl.AllowsActionOn(tx, testUserForbidden, "testing", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)

			allowed, err = acl.AllowsActionOn(tx, testUserAllowed, "testing", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)

			Convey("And SetActionAllowedOn(false) on A should disable A on resource", func() {
				err = acl.SetActionAllowedOn(tx, testUserAllowed, "testing", testResourceA, false)
				So(err, ShouldBeNil)

				allowed, err := acl.AllowsActionOn(tx, testUserForbidden, "testing", testResourceA)
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, true)

				allowed, err = acl.AllowsActionOn(tx, testUserAllowed, "testing", testResourceA)
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, false)
			})

			Convey("And SetActionAllowedOn(true) on A should enable A on resource", func() {
				err = acl.SetActionAllowedOn(tx, testUserAllowed, "testing", testResourceA, true)
				So(err, ShouldBeNil)

				allowed, err := acl.AllowsActionOn(tx, testUserForbidden, "testing", testResourceA)
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, true)

				allowed, err = acl.AllowsActionOn(tx, testUserAllowed, "testing", testResourceA)
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, true)
			})
		})

		Convey("SetActionAllowedOn(false) on B should disable A on resource", func() {
			err = acl.SetActionAllowedOn(tx, testUserForbidden, "testing", testResourceA, false)
			So(err, ShouldBeNil)

			allowed, err := acl.AllowsActionOn(tx, testUserForbidden, "testing", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)

			allowed, err = acl.AllowsActionOn(tx, testUserAllowed, "testing", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)

			Convey("And SetActionAllowedOn(false) on A should still disable A on resource", func() {
				err = acl.SetActionAllowedOn(tx, testUserAllowed, "testing", testResourceA, false)
				So(err, ShouldBeNil)

				allowed, err := acl.AllowsActionOn(tx, testUserForbidden, "testing", testResourceA)
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, false)

				allowed, err = acl.AllowsActionOn(tx, testUserAllowed, "testing", testResourceA)
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, false)
			})

			Convey("And SetActionAllowedOn(true) on A should enable A on resource", func() {
				err = acl.SetActionAllowedOn(tx, testUserAllowed, "testing", testResourceA, true)
				So(err, ShouldBeNil)

				allowed, err := acl.AllowsActionOn(tx, testUserForbidden, "testing", testResourceA)
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, false)

				allowed, err = acl.AllowsActionOn(tx, testUserAllowed, "testing", testResourceA)
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, true)
			})
		})

		Convey("SetActionAllowedOn(true) on B should allow A on resource", func() {
			err = acl.SetActionAllowedOn(tx, testUserForbidden, "testing", testResourceA, true)
			So(err, ShouldBeNil)

			allowed, err := acl.AllowsActionOn(tx, testUserForbidden, "testing", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)

			allowed, err = acl.AllowsActionOn(tx, testUserAllowed, "testing", testResourceA)
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)

			Convey("And SetActionAllowed(false) on A should disable A on resource", func() {
				err = acl.SetActionAllowed(tx, testUserAllowed, "testing", false)
				So(err, ShouldBeNil)

				allowed, err := acl.AllowsActionOn(tx, testUserForbidden, "testing", testResourceA)
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, true)

				allowed, err = acl.AllowsActionOn(tx, testUserAllowed, "testing", testResourceA)
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, false)
			})

			Convey("And SetActionAllowed(true) on A should still enable A on resource", func() {
				err = acl.SetActionAllowed(tx, testUserAllowed, "testing",  true)
				So(err, ShouldBeNil)

				allowed, err := acl.AllowsActionOn(tx, testUserForbidden, "testing", testResourceA)
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, true)

				allowed, err = acl.AllowsActionOn(tx, testUserAllowed, "testing", testResourceA)
				So(err, ShouldBeNil)
				So(allowed, ShouldEqual, true)
			})
		})
	}))

	Convey("When A inherits from B and C", t, WithTransaction(db, func(tx *sql.Tx) {
		err := acl.SetActorInherits(tx, testUserAllowed, testUserForbidden)
		So(err, ShouldBeNil)

		err = acl.SetActorInherits(tx, testUserAllowed, dummyUser)
		So(err, ShouldBeNil)

		Convey("SetActionAllowed(true) on only B should allow A", func() {
			err := acl.SetActionAllowed(tx, testUserForbidden, "testing", true)
			So(err, ShouldBeNil)

			allowed, err := acl.AllowsAction(tx, testUserForbidden, "testing")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)

			allowed, err = acl.AllowsAction(tx, testUserAllowed, "testing")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("SetActionAllowed(true) on both B and C should allow A", func() {
			err := acl.SetActionAllowed(tx, testUserForbidden, "testing", true)
			So(err, ShouldBeNil)

			err = acl.SetActionAllowed(tx, dummyUser, "testing", true)
			So(err, ShouldBeNil)

			allowed, err := acl.AllowsAction(tx, testUserForbidden, "testing")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)

			allowed, err = acl.AllowsAction(tx, dummyUser, "testing")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)

			allowed, err = acl.AllowsAction(tx, testUserAllowed, "testing")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)
		})

		Convey("SetActionAllowed(true) on B and SetActionAllowed(false) on C should disable A", func() {
			err := acl.SetActionAllowed(tx, testUserForbidden, "testing", true)
			So(err, ShouldBeNil)

			err = acl.SetActionAllowed(tx, dummyUser, "testing", false)
			So(err, ShouldBeNil)

			allowed, err := acl.AllowsAction(tx, testUserForbidden, "testing")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, true)

			allowed, err = acl.AllowsAction(tx, dummyUser, "testing")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)

			allowed, err = acl.AllowsAction(tx, testUserAllowed, "testing")
			So(err, ShouldBeNil)
			So(allowed, ShouldEqual, false)
		})
	}))

	/* TODO: Tests for 3 levels of permissions, to make sure intermediate levels are taken into account */
	/* TODO: More for ARO hierarchy, combine levels with generic and resource specific permissions */
}
