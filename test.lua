---@diagnostic disable: undefined-global
local Sql = require("xodel.xodel")
local set = require("xodel.set")
describe("Busted unit testing framework", function()
  it("Sql.", function()

  end)
  it("Sql._get_insert_values_token", function()
    local values, columns = Sql:_get_insert_values_token { name = "kate", age = 11 }
    -- assert.are.same(columns, { "age", "name" })
    -- assert.are.same("(11, 'kate')", values)
  end)
  it("Sql._get_insert_values_token (with columns)", function()
    local values, columns = Sql:_get_insert_values_token({ name = "kate", age = 11 }, { "name", "age", "sex" })
    assert.are.same(columns, { "name", "age", "sex" })
    assert.are.same("('kate', 11, DEFAULT)", values)
  end)
  it("Sql._get_keys", function()
    local c1 = Sql:_get_keys { a = 1, b = 2, c = 3 }
    assert.truthy(set(c1) == set { "a", "b", "c" })
    local c2 = Sql:_get_keys { { a = 1 }, { b = 2 }, { d = 3 } }
    assert.truthy(set(c2) == set { "a", "b", "d" })
  end)
  it("Sql._rows_to_array", function()
    local v1 = Sql:_rows_to_array({ { name = "kate", age = 11 }, { name = "tom", age = 12 } }, { "name", "age" })
    assert.are.same(v1, { { "kate", 11 }, { "tom", 12 } })
    local v2 = Sql:_rows_to_array({ { name = "kate", age = 11 }, { name = "tom", age = 12 } }, { "age", "name" })
    assert.are.same(v2, { { 11, "kate", }, { 12, "tom", } })
  end)
  it("Sql._get_bulk_insert_values_token", function()
    local d = Sql("v"):delete { foo = 1 }:cte_returning { columns = { 'a', 'b' }, literal_columns = { 'c', 'd' },
      literals = { 11, 12 } }
    print(Sql("t"):insert(d):statement())
  end)
  it("Sql.insert", function()
    local d = Sql("v"):insert({ a = 'foo', b = 2, c = true }, { "a", "b", "c" })
    -- assert.are.same(d:statement(), "")
    assert.are.same(d:statement(), "INSERT INTO v (a, b, c) VALUES ('foo', 2, TRUE)")
    d = Sql("v"):insert({ { a = 1, b = 2 }, { a = 3, b = 4 } }, {"a","b"})
    assert.are.same(d:statement(), 'INSERT INTO v (a, b) VALUES (1, 2), (3, 4)')
    d = Sql("v"):insert({ a = 1, b = 2 }, { "a", "b", "c" })
    assert.are.same(d:statement(), "INSERT INTO v (a, b, c) VALUES (1, 2, DEFAULT)")
    d = Sql("v"):insert(Sql("t"):select("a", "b", "c"))
    assert.are.same(d:statement(), "INSERT INTO v (a, b, c) SELECT a, b, c FROM t")
    d = Sql("v"):insert(Sql("t"):delete{a='foo'}:returning("a", "b", "c"))
    assert.are.same(d:statement(),
      "WITH d(a, b, c) AS (DELETE FROM t WHERE a = 'foo' RETURNING a, b, c) INSERT INTO v (a, b, c) SELECT a, b, c FROM d")
    d = Sql("v"):insert(Sql("t"):delete { a = 'foo' }:cte_returning { columns = { "a", "b", "c" },
      literals = { "val", 1, true }, literal_columns = { 'd', 'e', 'f' } })
    assert.are.same(d:statement(),
      "WITH d(a, b, c, d, e, f) AS (DELETE FROM t WHERE a = 'foo' RETURNING a, b, c, 'val', 1, TRUE) INSERT INTO v (a, b, c, d, e, f) SELECT a, b, c, d, e, f FROM d")
    print(d:statement())
  end)
  it("Sql.update", function()
    local d = Sql("t"):update { a = 1 }
    assert.are.same(d:statement(), "UPDATE t SET a = 1")
    d = Sql("t"):update(Sql("v"):select("a", "b"))
    assert.are.same(d:statement(), "UPDATE t SET (a, b) = (SELECT a, b FROM v)")
    print(d:statement())
  end)
  describe("should be awesome", function()
    it("should be easy to use", function()
      assert.truthy("Yup.")
    end)

    it("should have lots of features", function()
      -- deep check comparisons!
      assert.are.same({ table = "great" }, { table = "great" })

      -- or check by reference!
      assert.are_not.equal({ table = "great" }, { table = "great" })

      assert.truthy("this is a string") -- truthy: not false or nil

      assert.True(1 == 1)
      assert.is_true(1 == 1)

      assert.falsy(nil)
      assert.has_error(function() error("Wat") end, "Wat")
    end)

    it("should provide some shortcuts to common functions", function()
      assert.are.unique({ { thing = 1 }, { thing = 2 }, { thing = 3 } })
    end)

    -- it("should have mocks and spies for functional tests", function()
    --   local thing = require("thing_module")
    --   spy.on(thing, "greet")
    --   thing.greet("Hi!")

    --   assert.spy(thing.greet).was.called()
    --   assert.spy(thing.greet).was.called_with("Hi!")
    -- end)
  end)
end)
