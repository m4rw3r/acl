package acl

import (
	"database/sql"
	"testing"

	"lab.likipe.se/worktaim-api/config"
	"lab.likipe.se/worktaim-api/postgresql"

	. "github.com/smartystreets/goconvey/convey"
)

func TestMakeTable(t *testing.T) {
	uuid1 := "0323663c-5ce7-4a12-a221-79b0159264cb"
	uuid2 := "1364b583-20a1-4aeb-aad8-cc134daeae00"
	uuid3 := "48e68e18-769e-4d74-a349-a4e530ce0056"
	uuid4 := "9e72d92b-15f5-4a26-9647-f244b6caf668"

	config := config.LoadConfiguration("../config_test.json")

	/* Extract normal databse/sql DB instance */
	db := postgresql.CreateConnection(config).DB

	Convey("When the database is empty", t, func() {
		clean(db)

		Convey("EnsureTableAndRulesAreCreated() should not raise an error without links", func() {
			err := EnsureTableAndRulesAreCreated(db, "ACLTest", Cascades{})

			So(err, ShouldEqual, nil)
		})

		Convey("EnsureTableAndRulesAreCreated() should raise an error with links to missing actor table", func() {
			err := EnsureTableAndRulesAreCreated(db, "ACLTest", Cascades{Actors: []Link{{Table: "ACLTestActors", Key: "id"}}, Targets: []Link{}})

			So(err, ShouldNotBeNil)

			Convey("And it should have done a rollback", func() {
				row := db.QueryRow("SELECT 1 FROM information_schema.tables WHERE table_name = $1", "ACLTest")

				hasTable := 0
				err := row.Scan(&hasTable)

				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "sql: no rows in result set")
				So(hasTable, ShouldEqual, 0)

				row = db.QueryRow("SELECT 1 FROM pg_rules WHERE tablename = $1 AND rulename = $2", "ACLTest", "ACLTest_INSERT")

				hasTable = 0
				err = row.Scan(&hasTable)

				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "sql: no rows in result set")
				So(hasTable, ShouldEqual, 0)

				row = db.QueryRow("SELECT 1 FROM pg_rules WHERE tablename = $1 AND rulename = $2", "ACLTestActors", "ACLTest_ACTOR_ACLTestActors_DELETE")

				hasTable = 0
				err = row.Scan(&hasTable)

				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "sql: no rows in result set")
				So(hasTable, ShouldEqual, 0)

				row = db.QueryRow("SELECT 1 FROM pg_rules WHERE tablename = $1 AND rulename = $2", "ACLTestActors", "ACLTest_TARGET_ACLTestTargets_DELETE")

				hasTable = 0
				err = row.Scan(&hasTable)

				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "sql: no rows in result set")
				So(hasTable, ShouldEqual, 0)
			})
		})

		Convey("EnsureTableAndRulesAreCreated() should raise an error with links to missing target table", func() {
			err := EnsureTableAndRulesAreCreated(db, "ACLTest", Cascades{Actors: []Link{}, Targets: []Link{{Table: "ACLTestTargets", Key: "id"}}})

			So(err, ShouldNotBeNil)

			Convey("And it should have done a rollback", func() {
				row := db.QueryRow("SELECT 1 FROM information_schema.tables WHERE table_name = $1", "ACLTest")

				hasTable := 0
				err := row.Scan(&hasTable)

				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "sql: no rows in result set")
				So(hasTable, ShouldEqual, 0)

				row = db.QueryRow("SELECT 1 FROM pg_rules WHERE tablename = $1 AND rulename = $2", "ACLTest", "ACLTest_INSERT")

				hasTable = 0
				err = row.Scan(&hasTable)

				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "sql: no rows in result set")
				So(hasTable, ShouldEqual, 0)

				row = db.QueryRow("SELECT 1 FROM pg_rules WHERE tablename = $1 AND rulename = $2", "ACLTestActors", "ACLTest_ACTOR_ACLTestActors_DELETE")

				hasTable = 0
				err = row.Scan(&hasTable)

				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "sql: no rows in result set")
				So(hasTable, ShouldEqual, 0)

				row = db.QueryRow("SELECT 1 FROM pg_rules WHERE tablename = $1 AND rulename = $2", "ACLTestActors", "ACLTest_TARGET_ACLTestTargets_DELETE")

				hasTable = 0
				err = row.Scan(&hasTable)

				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "sql: no rows in result set")
				So(hasTable, ShouldEqual, 0)
			})
		})
	})

	clean(db)

	Convey("When the database contains the required tables", t, func() {
		Convey("EnsureTableAndRulesAreCreated() should not raise an error with links", func() {
			createResourceTables(db)

			err := EnsureTableAndRulesAreCreated(db, "ACLTest", Cascades{Actors: []Link{{Table: "ACLTestActors", Key: "id"}}, Targets: []Link{{Table: "ACLTestTargets", Key: "id"}}})

			So(err, ShouldEqual, nil)
		})

		Convey("Inserts into ACLTest table should behave", func() {
			Convey("Like INSERT if nothing with that primary key exists", func() {
				row := db.QueryRow(`SELECT COUNT(1) FROM "ACLTest"`)

				numRows := 0
				err := row.Scan(&numRows)

				So(err, ShouldBeNil)
				So(numRows, ShouldEqual, 0)

				_, err = db.Query(`INSERT INTO "ACLTest" ("actor_id", "action", "target_id", "allowed") VALUES($1, $2, $3, $4)`, uuid1, "testing", uuid2, true)

				So(err, ShouldBeNil)

				row = db.QueryRow(`SELECT * FROM "ACLTest"`)

				actor_id := ""
				action := ""
				target_id := ""
				allowed := false

				err = row.Scan(&actor_id, &action, &target_id, &allowed)

				So(err, ShouldBeNil)
				So(actor_id, ShouldEqual, uuid1)
				So(action, ShouldEqual, "testing")
				So(target_id, ShouldEqual, uuid2)
				So(allowed, ShouldEqual, true)
			})

			Convey("Like UPDATE if a primary key exists", func() {
				row := db.QueryRow(`SELECT COUNT(1) FROM "ACLTest"`)

				numRows := 0
				err := row.Scan(&numRows)

				So(err, ShouldBeNil)
				So(numRows, ShouldEqual, 1)

				_, err = db.Query(`INSERT INTO "ACLTest" ("actor_id", "action", "target_id", "allowed") VALUES($1, $2, $3, $4)`, uuid1, "testing", uuid2, false)

				So(err, ShouldBeNil)

				row = db.QueryRow(`SELECT COUNT(1) FROM "ACLTest"`)

				numRows = 0
				err = row.Scan(&numRows)

				So(err, ShouldBeNil)
				So(numRows, ShouldEqual, 1)

				row = db.QueryRow(`SELECT * FROM "ACLTest"`)

				actor_id := ""
				action := ""
				target_id := ""
				allowed := true

				err = row.Scan(&actor_id, &action, &target_id, &allowed)

				So(err, ShouldBeNil)
				So(actor_id, ShouldEqual, uuid1)
				So(action, ShouldEqual, "testing")
				So(target_id, ShouldEqual, uuid2)
				So(allowed, ShouldEqual, false)
			})
		})

		Convey("DELETE should also work", func() {
			result, err := db.Exec(`DELETE FROM "ACLTest" WHERE "actor_id" = $1 AND "action" = $2 AND "target_id" = $3`, uuid1, "testing", uuid2)

			So(err, ShouldBeNil)

			num, err := result.RowsAffected()
			So(num, ShouldEqual, 1)
		})
	})

	Convey("When linked rows exist", t, func() {
		clean(db)
		createResourceTables(db)
		err := EnsureTableAndRulesAreCreated(db, "ACLTest", Cascades{Actors: []Link{{Table: "ACLTestActors", Key: "id"}}, Targets: []Link{{Table: "ACLTestTargets", Key: "id"}}})
		if err != nil {
			panic(err)
		}

		_, err = db.Exec(`INSERT INTO "ACLTestActors" ("id") VALUES ($1)`, uuid1)
		if err != nil {
			panic(err)
		}
		_, err = db.Exec(`INSERT INTO "ACLTestActors" ("id") VALUES ($1)`, uuid3)
		if err != nil {
			panic(err)
		}
		// So(err, ShouldBeNil)
		_, err = db.Exec(`INSERT INTO "ACLTestTargets" ("id") VALUES ($1)`, uuid2)
		if err != nil {
			panic(err)
		}
		// So(err, ShouldBeNil)
		_, err = db.Exec(`INSERT INTO "ACLTestTargets" ("id") VALUES ($1)`, uuid4)
		if err != nil {
			panic(err)
		}
		_, err = db.Exec(`INSERT INTO "ACLTest" ("actor_id", "action", "target_id", "allowed") VALUES ($1, $2, $3, $4)`, uuid1, "testing", uuid2, true)
		if err != nil {
			panic(err)
		}
		_, err = db.Exec(`INSERT INTO "ACLTest" ("actor_id", "action", "target_id", "allowed") VALUES ($1, $2, $3, $4)`, uuid3, "testing", uuid4, false)
		if err != nil {
			panic(err)
		}

		Convey("DELETE on an actor row should remove the corresponding ACL entry", func() {
			row := db.QueryRow(`SELECT COUNT(1) FROM "ACLTest"`)

			numRows := 0
			err := row.Scan(&numRows)

			So(err, ShouldBeNil)
			So(numRows, ShouldEqual, 2)

			_, err = db.Exec(`DELETE FROM "ACLTestActors" WHERE "id" = $1`, uuid1)
			So(err, ShouldBeNil)

			row = db.QueryRow(`SELECT COUNT(1) FROM "ACLTest"`)

			numRows = 0
			err = row.Scan(&numRows)

			So(err, ShouldBeNil)
			So(numRows, ShouldEqual, 1)

			row = db.QueryRow(`SELECT * FROM "ACLTest"`)

			actor_id := ""
			action := ""
			target_id := ""
			allowed := false

			err = row.Scan(&actor_id, &action, &target_id, &allowed)

			So(err, ShouldBeNil)
			So(actor_id, ShouldEqual, uuid3)
			So(action, ShouldEqual, "testing")
			So(target_id, ShouldEqual, uuid4)
			So(allowed, ShouldEqual, false)

			Convey("Should also delete original row", func() {
				row := db.QueryRow(`SELECT COUNT(1) FROM "ACLTestActors" WHERE "id" = $1`, uuid1)

				numRows := 0
				err := row.Scan(&numRows)

				So(err, ShouldBeNil)
				So(numRows, ShouldEqual, 0)
			})

			Convey("Should preserve other rows", func() {
				row := db.QueryRow(`SELECT COUNT(1) FROM "ACLTestActors" WHERE "id" = $1`, uuid3)

				numRows := 0
				err := row.Scan(&numRows)

				So(err, ShouldBeNil)
				So(numRows, ShouldEqual, 1)
			})
		})

		Convey("DELETE on a target row should remove the corresponding ACL entry", func() {
			row := db.QueryRow(`SELECT COUNT(1) FROM "ACLTest"`)

			numRows := 0
			err := row.Scan(&numRows)

			So(err, ShouldBeNil)
			So(numRows, ShouldEqual, 2)

			_, err = db.Exec(`DELETE FROM "ACLTestTargets" WHERE "id" = $1`, uuid4)
			So(err, ShouldBeNil)

			row = db.QueryRow(`SELECT COUNT(1) FROM "ACLTest"`)

			numRows = 0
			err = row.Scan(&numRows)

			So(err, ShouldBeNil)
			So(numRows, ShouldEqual, 1)

			row = db.QueryRow(`SELECT * FROM "ACLTest"`)

			actor_id := ""
			action := ""
			target_id := ""
			allowed := false

			err = row.Scan(&actor_id, &action, &target_id, &allowed)

			So(err, ShouldBeNil)
			So(actor_id, ShouldEqual, uuid1)
			So(action, ShouldEqual, "testing")
			So(target_id, ShouldEqual, uuid2)
			So(allowed, ShouldEqual, true)

			Convey("Should also delete original row", func() {
				row := db.QueryRow(`SELECT COUNT(1) FROM "ACLTestTargets" WHERE "id" = $1`, uuid4)

				numRows := 0
				err := row.Scan(&numRows)

				So(err, ShouldBeNil)
				So(numRows, ShouldEqual, 0)
			})

			Convey("Should also preserve other rows", func() {
				row := db.QueryRow(`SELECT COUNT(1) FROM "ACLTestTargets" WHERE "id" = $1`, uuid2)

				numRows := 0
				err := row.Scan(&numRows)

				So(err, ShouldBeNil)
				So(numRows, ShouldEqual, 1)
			})
		})
	})
}

func createResourceTables(db *sql.DB) {
	queries := []string{
		`CREATE TABLE "ACLTestActors"
(
	"id" uuid,
	PRIMARY KEY("id")
);`,
		`CREATE TABLE "ACLTestTargets"
(
	"id" uuid,
	PRIMARY KEY("id")
);`}

	for _, q := range queries {
		_, err := db.Exec(q)
		if err != nil {
			panic(err)
		}
	}
}

func clean(db *sql.DB) {
	queries := []string{
		`DROP TABLE IF EXISTS "ACLTest" CASCADE`,
		`DROP TABLE IF EXISTS "ACLTestActors" CASCADE`,
		`DROP TABLE IF EXISTS "ACLTestTargets" CASCADE`}

	for _, q := range queries {
		_, err := db.Exec(q)
		if err != nil {
			panic(err)
		}
	}
}
