-- https://www.postgreSql.org/docs/current/sql-select.html
-- https://www.postgreSql.org/docs/current/sql-insert.html
-- https://www.postgreSql.org/docs/current/sql-update.html
-- https://www.postgreSql.org/docs/current/sql-delete.html
local array = require "xodel.array"
local object = require "xodel.object"
local utils = require "xodel.utils"
local Field = require "xodel.field"
local nkeys = require "table.nkeys"
local setmetatable = setmetatable
local ipairs = ipairs
local tostring = tostring
local type = type
local pairs = pairs
local assert = assert
local error = error
local string_format = string.format
local table_concat = table.concat
local table_insert = table.insert
local ngx_localtime = ngx.localtime
local match = ngx.re.match
local ngx_re = require "ngx.re"
local split = ngx_re.split


local table_new, clone, NULL
if ngx then
  table_new = table.new
  clone = require("table.clone")
  NULL = ngx.null
else
  table_new = function(a, b)
    return {}
  end
  clone = function(t)
    local res = {}
    for key, value in pairs(t) do
      res[key] = value
    end
    return res
  end
  NULL = setmetatable({}, {
    __newindex = function()
      return error("NULL object is read only")
    end
  })
end
local DEFAULT_STRING_MAXLENGTH = 256
local FOREIGN_KEY = 2
local NON_FOREIGN_KEY = 3
local END = 4
local COMPARE_OPERATORS = { lt = "<", lte = "<=", gt = ">", gte = ">=", ne = "<>", eq = "=" }
local PG_KEYWORDS =
"ALL,ANALYSE,ANALYZE,AND,ANY,ARRAY,AS,ASC,ASYMMETRIC,AUTHORIZATION,BINARY,BOTH,CASE,CAST,CHECK,COLLATE,COLLATION,COLUMN,CONCURRENTLY,CONSTRAINT,CREATE,CROSS,CURRENT_CATALOG,CURRENT_DATE,CURRENT_ROLE,CURRENT_SCHEMA,CURRENT_TIME,CURRENT_TIMESTAMP,CURRENT_USER,DEFAULT,DEFERRABLE,DESC,DISTINCT,DO,ELSE,END,EXCEPT,FALSE,FETCH,FOR,FOREIGN,FREEZE,FROM,FULL,GRANT,GROUP,HAVING,ILIKE,IN,INITIALLY,INNER,INTERSECT,INTO,IS,ISNULL,JOIN,LATERAL,LEADING,LEFT,LIKE,LIMIT,LOCALTIME,LOCALTIMESTAMP,NATURAL,NOT,NOTNULL,NULL,OFFSET,ON,ONLY,OR,ORDER,OUTER,OVERLAPS,PLACING,PRIMARY,REFERENCES,RETURNING,RIGHT,SELECT,SESSION_USER,SIMILAR,SOME,SYMMETRIC,TABLE,TABLESAMPLE,THEN,TO,TRAILING,TRUE,UNION,UNIQUE,USER,USING,VARIADIC,VERBOSE,WHEN,WHERE,WINDOW,WITH"
local IS_PG_KEYWORDS = utils.from_entries(utils.map(split(PG_KEYWORDS, ","), function(e)
  return { e, true }
end))
local non_merge_names = { sql = true, fields = true, field_names = true, extends = true, mixins = true, __index = true,
  admin = true }
local function model_ready_for_sql(model)
  return model.table_name and model.field_names and model.fields
end
---@alias keys string|string[]
local base_model = {
  abstract = true,
  field_names = array { "id", "ctime", "utime" },
  fields = {
    id = { type = "integer", primary_key = true, serial = true },
    ctime = { label = "创建时间", type = "datetime", auto_now_add = true },
    utime = { label = "更新时间", type = "datetime", auto_now = true }
  }
}
local function check_reserved(name)
  assert(type(name) == "string", string_format("name must by string, not %s (%s)", type(name), name))
  assert(not name:find("__", 1, true), "don't use __ in a field name")
  assert(not IS_PG_KEYWORDS[name:upper()], string_format("%s is a postgresql reserved word", name))
end

local function normalize_array_and_hash_fields(fields)
  assert(type(fields) == "table", "you must provide fields for a model")
  local aligned_fields = {}
  for name, field in pairs(fields) do
    if type(name) == 'number' then
      assert(field.name, "you must define name for a field when using array fields")
      aligned_fields[field.name] = field
    else
      aligned_fields[name] = field
    end
  end
  return aligned_fields
end

local function normalize_field_names(field_names)
  assert(type(field_names) == "table", "you must provide field_names for a model")
  for _, name in ipairs(field_names) do
    assert(type(name) == 'string', "element of field_names must be string")
  end
  return array(field_names)
end

local function is_field_class(t)
  return type(t) == 'table' and getmetatable(t) and getmetatable(t).__is_field_class__
end

local function model_new(cls, attrs)
  return cls:new(attrs)
end

local function model_caller(cls, options)
  return cls:make_class(options)
end


local function get_foreign_object(attrs, prefix)
  -- when in : attrs = {id=1, buyer__name='tom', buyer__id=2}, prefix = 'buyer__'
  -- when out: attrs = {id=1}, fk_instance = {name='tom', id=2}
  local fk = {}
  local n = #prefix
  for k, v in pairs(attrs) do
    if k:sub(1, n) == prefix then
      fk[k:sub(n + 1)] = v
      attrs[k] = nil
    end
  end
  return fk
end

local function make_model_instance_meta(model, cls)
  local meta = {}
  function meta.__call(self, data)
    for k, v in pairs(data) do
      self[k] = v
    end
    return self
  end

  function meta.delete(self, key)
    key = key or model.primary_key
    return cls.delete(model, { [key] = self[key] }):exec()
  end

  function meta.save(self, names, key)
    return cls.save(model, self, names, key)
  end

  function meta.save_create(self, names, key)
    return cls.save_create(model, self, names, key)
  end

  function meta.save_update(self, names, key)
    return cls.save_update(model, self, names, key)
  end

  function meta.save_from(self, key)
    return cls.save_from(model, self, key)
  end

  function meta.create_from(self, key)
    return cls.create_from(model, self, key)
  end

  function meta.update_from(self, key)
    return cls.update_from(model, self, key)
  end

  function meta.validate(self, names, key)
    return cls.validate(model, self, names, key)
  end

  function meta.validate_update(self, names)
    return cls.validate_update(model, self, names)
  end

  function meta.validate_create(self, names)
    return cls.validate_create(model, self, names)
  end

  return setmetatable(meta, model)
end
---comment
---@param rows rows
---@param key keys
---@return rows?, keys?
local function check_upsert_key(rows, key)
  assert(key, "no key for upsert")
  if rows[1] then
    if type(key) == "string" then
      for i, row in ipairs(rows) do
        if row[key] == nil or row[key] == '' then
          return nil, {
            index = i,
            name = key,
            err = 'value of key is required for upsert/merge'
          }
        end
      end
    else
      for i, row in ipairs(rows) do
        local empty_keys = true
        for _, k in ipairs(key) do
          if not (row[k] == nil or row[k] == '') then
            empty_keys = false
            break
          end
        end
        if empty_keys then
          return nil, "empty keys for upsert"
        end
      end
    end
  elseif type(key) == "string" then
    if rows[key] == nil or rows[key] == '' then
      return nil, { name = key, err = 'value of key is required' }
    end
  else
    for _, k in ipairs(key) do
      if rows[k] == nil or rows[k] == '' then
        return nil, { name = k, err = 'value of key is required' }
      end
    end
  end
  return rows, key
end
local function make_field_from_json(json, kwargs)
  local options = utils.dict(json, kwargs)
  if not options.type then
    if options.reference then
      options.type = "foreignkey"
    elseif options.model or options.subfields then
      options.type = "table"
    else
      options.type = "string"
    end
  end
  if (options.type == "string" or options.type == "alioss") and not options.maxlength then
    options.maxlength = DEFAULT_STRING_MAXLENGTH
  end
  local fcls = Field[options.type]
  if not fcls then
    error("invalid field type:" .. tostring(options.type))
  end
  return fcls(options)
end
---make a function that returns string
---@param s string # token string
---@return fun(): string
local function make_raw_token(s)
  local function raw_token()
    return s
  end

  return raw_token
end

local DEFAULT = make_raw_token("DEFAULT")
---@enum sql_defaults
local SQL_DEFAULTS = {
  NULL = 1,
  DEFAULT = 2,
}
---map util
---@param tbl any[] # element array
---@param func fun(any):any # element callback
---@return any[]
local function map(tbl, func)
  local res = {}
  for i = 1, #tbl do
    res[i] = func(tbl[i])
  end
  return res
end

---flatten an array
---@param tbl any[]
---@return any[]
local function flat(tbl)
  local res = {}
  for i = 1, #tbl do
    local t = tbl[i]
    if type(t) ~= "table" then
      res[#res + 1] = t
    else
      for _, e in ipairs(flat(t)) do
        res[#res + 1] = e
      end
    end
  end
  return res
end

---merge two array to one new array
---@param t1 any[]
---@param t2? any[]
---@return any[]
local function merge_table(t1, t2)
  local res = clone(t1)
  if t2 then
    for i = 1, #t2 do
      res[#res + 1] = t2[i]
    end
  end
  return res
end

---@alias set_type "_union"|"_union_all"| "_except"| "_except_all"|"_intersect"|"_intersect_all"
local PG_SET_MAP = {
  _union = 'UNION',
  _union_all = 'UNION ALL',
  _except = 'EXCEPT',
  _except_all = 'EXCEPT ALL',
  _intersect = 'INTERSECT',
  _intersect_all = 'INTERSECT ALL'
}

---adding v-prefix
---@param column string
---@return string
local function _prefix_with_V(column)
  return "V." .. column
end

---check if row a ModelSql instance
---@param row table
---@return boolean
local function is_sql_instance(row)
  local meta = getmetatable(row)
  return meta and meta.__SQL_BUILDER__
end

---@alias toker fun(): string
---@alias dbvalue string|number|boolean|table|toker
---@param is_literal boolean escape as literal or not
---@param is_bracket boolean surrounding with () or not
---@return fun(value:dbvalue):string
local function _escape_factory(is_literal, is_bracket)
  ---value escaper for lua value
  ---@param value dbvalue
  ---@return string
  local function as_sql_token(value)
    local value_type = type(value)
    if "string" == value_type then
      if is_literal then
        return "'" .. (value:gsub("'", "''")) .. "'"
      else
        return value
      end
    elseif "number" == value_type then
      return tostring(value)
    elseif "boolean" == value_type then
      return value and "TRUE" or "FALSE"
    elseif "function" == value_type then
      return value()
    elseif "table" == value_type then
      if is_sql_instance(value) then
        return "(" .. value:statement() .. ")"
      elseif value[1] ~= nil then
        local token = table_concat(map(value, as_sql_token), ", ")
        if is_bracket then
          return "(" .. token .. ")"
        else
          return token
        end
      else
        error("empty table as a ModelSql value is not allowed")
      end
    elseif NULL == value then
      return 'NULL'
    else
      error(string_format("don't know how to escape value: %s (%s)", value, value_type))
    end
  end

  return as_sql_token
end

local as_literal = _escape_factory(true, true)
local as_token = _escape_factory(false, false)


---a helper
---@param columns dbvalue[]
---@param literals? string[]
---@return string[]
local function get_cte_returning_values(columns, literals)
  local values = {}
  for _, col in ipairs(columns) do
    values[#values + 1] = as_token(col)
  end
  if literals then
    for _, e in ipairs(literals) do
      values[#values + 1] = as_literal(e)
    end
  end
  return values
end

---helper
---@alias cte_returning_opts {columns: string[], literals: dbvalue[], literal_columns: string[]}
---@param opts {returning: dbvalue[],cte_returning:cte_returning_opts}
---@return string
local function get_returning_token(opts)
  if opts.cte_returning then
    return " RETURNING " .. as_token(get_cte_returning_values(opts.cte_returning.columns, opts.cte_returning.literals))
  elseif opts.returning then
    return " RETURNING " .. opts.returning
  else
    return ""
  end
end

---@alias sql_options {table_name:string,delete?:boolean,distinct?:boolean,from?:string,group?:string,having?:string,insert?:string,limit?:number,offset?:number,order?:string,select?:string,update?:string,using?:string,where?:string,with?:string,returning?: string,cte_returning?:cte_returning_opts}
---assemble a sql
---@param opts sql_options
---@return string
local function assemble_sql(opts)
  local statement
  if opts.update then
    local from = opts.from and " FROM " .. opts.from or ""
    local where = opts.where and " WHERE " .. opts.where or ""
    local returning = get_returning_token(opts)
    statement = string_format("UPDATE %s SET %s%s%s%s", opts.table_name, opts.update, from, where, returning)
  elseif opts.insert then
    local returning = get_returning_token(opts)
    statement = string_format("INSERT INTO %s %s%s", opts.table_name, opts.insert, returning)
  elseif opts.delete then
    local using = opts.using and " USING " .. opts.using or ""
    local where = opts.where and " WHERE " .. opts.where or ""
    local returning = get_returning_token(opts)
    statement = string_format("DELETE FROM %s%s%s%s", opts.table_name, using, where, returning)
  else
    local from = opts.from or opts.table_name
    local where = opts.where and " WHERE " .. opts.where or ""
    local group = opts.group and " GROUP BY " .. opts.group or ""
    local having = opts.having and " HAVING " .. opts.having or ""
    local order = opts.order and " ORDER BY " .. opts.order or ""
    local limit = opts.limit and " LIMIT " .. opts.limit or ""
    local offset = opts.offset and " OFFSET " .. opts.offset or ""
    local distinct = opts.distinct and "DISTINCT " or ""
    local select = opts.select or "*"
    statement = string_format("SELECT %s%s FROM %s%s%s%s%s%s%s",
      distinct, select, from, where, group, having, order, limit, offset)
  end
  return opts.with and string_format("WITH %s %s", opts.with, statement) or statement
end

---@class Sql
local Sql = {}
---make a Sql instance
---@param cls ModelSql
---@param self? table
---@return ModelSql
function Sql.new(cls, self)
  return setmetatable(self or {}, cls)
end

---@param self ModelSql
---@param a dbvalue
---@param b? dbvalue
---@param ...? dbvalue[]
---@return ModelSql
function Sql.select(self, a, b, ...)
  local s = self:_get_select_token(a, b, ...)
  if not self._select then
    self._select = s
  elseif s ~= nil and s ~= "" then
    self._select = self._select .. ", " .. s
  end
  return self
end


---comment
---@param self ModelSql
---@param rows rows|ModelSql
---@param columns? string[]
---@return ModelSql
function Sql.insert(self, rows, columns)
  if type(rows) == "table" then
    if self:is_instance(rows) then
      if rows._select then
        self:_set_select_subquery_insert_token(rows, columns)
      else
        self:_set_cud_subquery_insert_token(rows)
      end
    elseif rows[1] then
      self._insert = self:_get_bulk_insert_token(rows, columns)
    elseif next(rows) ~= nil then
      self._insert = self:_get_insert_token(rows, columns)
    else
      error("can't pass empty table to Sql.insert")
    end
  elseif type(rows) == 'string' then
    self._insert = rows
  else
    error("invalid value type to Sql.insert:" .. type(rows))
  end
  return self
end

---comment
---@param self ModelSql
---@param row row|string|Sql
---@param columns? string[]
---@return ModelSql
function Sql.update(self, row, columns)
  if self:is_instance(row) then
    self._update = self:_get_update_query_token(row--[[@as ModelSql]] , columns)
  elseif type(row) == "table" then
    self._update = self:_get_update_token(row, columns)
  else
    self._update = row --[[@as string]]
  end
  return self
end

---comment
---@param self ModelSql
---@param rows row[]
---@param keys keys
---@return ModelSql
function Sql.merge_gets(self, rows, keys)
  -- {{id=1}, {id=2}, {id=3}} => columns: {'id'}
  -- each row of keys must be the same struct, so get columns from first row
  local columns = self:_get_keys(rows[1])
  rows, columns = self:_get_cte_values_literal(rows, columns)
  local join_cond = self:_get_join_conditions(keys, "V", self._as or self.table_name)
  local cte_name = string_format("V(%s)", table_concat(columns, ", "))
  local cte_values = string_format("(VALUES %s)", as_token(rows))
  return self.Sql.select(self, "V.*"):with(cte_name, cte_values):right_join("V", join_cond)
end

---comment
---@param self ModelSql
---@param rows row[]
---@param key keys
---@param columns string[]
---@return ModelSql
function Sql.merge(self, rows, key, columns)
  if #rows == 0 then
    error("empty rows passed to merge")
  end
  rows, columns = self:_get_cte_values_literal(rows, columns)
  local cte_name = string_format("V(%s)", table_concat(columns, ", "))
  local cte_values = string_format("(VALUES %s)", as_token(rows))
  local join_cond = self:_get_join_conditions(key, "V", "T")
  local vals_columns = map(columns, _prefix_with_V)
  local insert_subquery = Sql:new { table_name = "V" }:select(vals_columns):left_join("U AS T", join_cond):
      where_null(
        "T." .. (key[1] or key))
  local updated_subquery
  if (type(key) == "table" and #key == #columns) or #columns == 1 then
    updated_subquery = Sql:new { table_name = "V" }:select(vals_columns):join(self.table_name .. " AS T", join_cond)
  else
    updated_subquery = Sql:new { table_name = self.table_name, _as = "T" }
        :update(self:_get_update_token_with_prefix(columns, key, "V")):from("V"):where(join_cond)
        :returning(vals_columns)
  end
  self:with(cte_name, cte_values):with("U", updated_subquery)
  return Sql.insert(self, insert_subquery, columns)
end

---comment
---@param self ModelSql
---@param rows row[]
---@param key keys
---@param columns? string[]
---@return ModelSql
function Sql.upsert(self, rows, key, columns)
  assert(key, "you must provide key for upsert(string or table)")
  if self:is_instance(rows) then
    assert(columns ~= nil, "you must specify columns when use subquery as values of upsert")
    self._insert = self:_get_upsert_query_token(rows, key, columns)
  elseif rows[1] then
    self._insert = self:_get_bulk_upsert_token(rows, key, columns)
  else
    self._insert = self:_get_upsert_token(rows, key, columns)
  end
  return self
end

---comment
---@param self ModelSql
---@param rows row[]|ModelSql
---@param key keys
---@param columns string[]
---@return ModelSql
function Sql.updates(self, rows, key, columns)
  if self:is_instance(rows) then
    columns = columns or flat(rows._returning_args)
    local cte_name = string_format("V(%s)", table_concat(columns, ", "))
    local join_cond = self:_get_join_conditions(key, "V", self._as or self.table_name)
    self:with(cte_name, rows)
    return Sql.update(self, self:_get_update_token_with_prefix(columns, key, "V")):from("V"):where(join_cond)
  elseif #rows == 0 then
    error("empty rows passed to updates")
  else
    rows, columns = self:_get_cte_values_literal(rows, columns)
    local cte_name = string_format("V(%s)", table_concat(columns, ", "))
    local cte_values = string_format("(VALUES %s)", as_token(rows))
    local join_cond = self:_get_join_conditions(key, "V", self._as or self.table_name)
    self:with(cte_name, cte_values)
    return Sql.update(self, self:_get_update_token_with_prefix(columns, key, "V")):from("V"):where(join_cond)
  end
end

--- {{id=1}, {id=2}, {id=3}} => columns: {'id'}  keys: {{1},{2},{3}}
--- each row of keys must be the same struct, so get columns from first row
---@param self ModelSql
---@param keys row[]
---@param columns? string[]
---@return ModelSql
function Sql.gets(self, keys, columns)
  if #keys == 0 then
    error("empty keys passed to gets")
  end
  columns = columns or self:_get_keys(keys[1])
  keys, columns = self:_get_cte_values_literal(keys, columns)
  local join_cond = self:_get_join_conditions(columns, "V", self._as or self.table_name)
  local cte_name = string_format("V(%s)", table_concat(columns, ", "))
  local cte_values = string_format("(VALUES %s)", as_token(keys))
  return self:with(cte_name, cte_values):right_join("V", join_cond)
end
---@param self ModelSql
---@return ModelSql
function Sql.join(self, ...)
  local join_token = self:_get_inner_join(...)
  self._from = string_format("%s %s", self._from or self:get_table(), join_token)
  return self
end

function Sql.inner_join(self, ...) return self:join(...) end
---@param self ModelSql
---@return ModelSql
function Sql.left_join(self, ...)
  local join_token = self:_get_left_join(...)
  self._from = string_format("%s %s", self._from or self:get_table(), join_token)
  return self
end
---@param self ModelSql
---@return ModelSql
function Sql.right_join(self, ...)
  local join_token = self:_get_right_join(...)
  self._from = string_format("%s %s", self._from or self:get_table(), join_token)
  return self
end
---@param self ModelSql
---@return ModelSql
function Sql.full_join(self, ...)
  local join_token = self:_get_full_join(...)
  self._from = string_format("%s %s", self._from or self:get_table(), join_token)
  return self
end

---@param self ModelSql
---@param kwargs {[string|number]:any}
---@param logic? string
---@return string
function Sql._get_condition_token_from_table(self, kwargs, logic)
  local tokens = {}
  for k, value in pairs(kwargs) do
    if type(k) == "string" then
      tokens[#tokens + 1] = string_format("%s = %s", k, as_literal(value))
    else
      local token = self:_get_condition_token(value)
      if token ~= nil and token ~= "" then
        tokens[#tokens + 1] = '(' .. token .. ')'
      end
    end
  end
  if logic == nil then
    return table_concat(tokens, " AND ")
  else
    return table_concat(tokens, " " .. logic .. " ")
  end
end

---@param self ModelSql
---@param a table|string|function
---@param b? dbvalue
---@param c? dbvalue
---@return string
function Sql._get_condition_token(self, a, b, c)
  if b == nil then
    local argtype = type(a)
    if argtype == "table" then
      return self:_get_condition_token_from_table(a)
    elseif argtype == "string" then
      return a
    elseif argtype == "function" then
      local old_where = self._where
      self._where = nil
      local res, err = a(self)
      if res ~= nil then
        if res == self then
          local group_where = self._where
          if group_where == nil then
            error("no where token generate after calling condition function")
          else
            self._where = old_where
            return group_where
          end
        else
          self._where = old_where
          return res
        end
      else
        error(err or "nil returned in condition function")
      end
    else
      error("invalid condition type: " .. argtype)
    end
  elseif c == nil then
    return string_format("%s = %s", a, as_literal(b))
  else
    return string_format("%s %s %s", a, b, as_literal(c))
  end
end

---@param self ModelSql
function Sql.where_in(self, cols, range)
  local in_token = self:_get_in_token(cols, range)
  if self._where then
    self._where = string_format("(%s) AND %s", self._where, in_token)
  else
    self._where = in_token
  end
  return self
end

---@param self ModelSql
function Sql.where_not_in(self, cols, range)
  local not_in_token = self:_get_in_token(cols, range, "NOT IN")
  if self._where then
    self._where = string_format("(%s) AND %s", self._where, not_in_token)
  else
    self._where = not_in_token
  end
  return self
end

---@param self ModelSql
function Sql.where_null(self, col)
  if self._where then
    self._where = string_format("(%s) AND %s IS NULL", self._where, col)
  else
    self._where = col .. " IS NULL"
  end
  return self
end

---@param self ModelSql
function Sql.where_not_null(self, col)
  if self._where then
    self._where = string_format("(%s) AND %s IS NOT NULL", self._where, col)
  else
    self._where = col .. " IS NOT NULL"
  end
  return self
end

---@param self ModelSql
function Sql.where_between(self, col, low, high)
  if self._where then
    self._where = string_format("(%s) AND (%s BETWEEN %s AND %s)", self._where, col, low, high)
  else
    self._where = string_format("%s BETWEEN %s AND %s", col, low, high)
  end
  return self
end

---@param self ModelSql
function Sql.where_not_between(self, col, low, high)
  if self._where then
    self._where = string_format("(%s) AND (%s NOT BETWEEN %s AND %s)", self._where, col, low, high)
  else
    self._where = string_format("%s NOT BETWEEN %s AND %s", col, low, high)
  end
  return self
end

---@param self ModelSql
function Sql.or_where_in(self, cols, range)
  local in_token = self:_get_in_token(cols, range)
  if self._where then
    self._where = string_format("%s OR %s", self._where, in_token)
  else
    self._where = in_token
  end
  return self
end

---@param self ModelSql
function Sql.or_where_not_in(self, cols, range)
  local not_in_token = self:_get_in_token(cols, range, "NOT IN")
  if self._where then
    self._where = string_format("%s OR %s", self._where, not_in_token)
  else
    self._where = not_in_token
  end
  return self
end

---@param self ModelSql
function Sql.or_where_null(self, col)
  if self._where then
    self._where = string_format("%s OR %s IS NULL", self._where, col)
  else
    self._where = col .. " IS NULL"
  end
  return self
end

---@param self ModelSql
function Sql.or_where_not_null(self, col)
  if self._where then
    self._where = string_format("%s OR %s IS NOT NULL", self._where, col)
  else
    self._where = col .. " IS NOT NULL"
  end
  return self
end

---@param self ModelSql
function Sql.or_where_between(self, col, low, high)
  if self._where then
    self._where = string_format("%s OR (%s BETWEEN %s AND %s)", self._where, col, low, high)
  else
    self._where = string_format("%s BETWEEN %s AND %s", col, low, high)
  end
  return self
end

---@param self ModelSql
function Sql.or_where_not_between(self, col, low, high)
  if self._where then
    self._where = string_format("%s OR (%s NOT BETWEEN %s AND %s)", self._where, col, low, high)
  else
    self._where = string_format("%s NOT BETWEEN %s AND %s", col, low, high)
  end
  return self
end

local SqlMeta = {}
function SqlMeta.__call(cls, kwargs)
  if type(kwargs) == "string" then
    return setmetatable({ table_name = kwargs }, cls)
  else
    return setmetatable(kwargs or {}, cls)
  end
end

---@class ModelSql
---@field Sql  Sql
---@field table_name string
---@field fields table
---@field field_names string[]
---@field auto_now_name string
---@field foreign_keys table
---@field name_cache {[string]:string}
---@field query function
---@field primary_key string
---@field _skip_validate? boolean
---@field _compact? boolean
---@field _commit? boolean
---@field _pcall? boolean
---@field _raw? boolean
---@field _join_keys? table
---@field _load_fk? table
---@field _as?  string
---@field _with?  string
---@field _join?  string
---@field _distinct?  boolean
---@field _returning?  string
---@field _cte_returning?  cte_returning_opts
---@field _returning_args?  dbvalue[]
---@field _insert?  string
---@field _update?  string
---@field _delete?  boolean
---@field _using?  string
---@field _select?  string
---@field _from?  string
---@field _where?  string
---@field _group?  string
---@field _having?  string
---@field _order?  string
---@field _limit?  number
---@field _offset?  number
---@field _union?  ModelSql | string
---@field _union_all?  ModelSql | string
---@field _except?  ModelSql | string
---@field _except_all?  ModelSql | string
---@field _intersect?  ModelSql | string
---@field _intersect_all?  ModelSql | string
local ModelSql = setmetatable({
  __SQL_BUILDER__ = true,
  r = make_raw_token,
  DEFAULT = DEFAULT,
  NULL = NULL,
  as_token = as_token,
  as_literal = as_literal,
}, SqlMeta)
ModelSql.__index = ModelSql
function ModelSql.__tostring(self)
  return self:statement()
end

function ModelSql.__call(cls, ...)
  return cls.new(cls, ...)
end

---make a ModelSql instance
---@param cls ModelSql
---@param self? table
---@return ModelSql
function ModelSql.new(cls, self)
  return setmetatable(self or {}, cls)
end
function ModelSql.make_class(cls, options)
  -- foreign_keys, label_to_name, name_to_label, primary_key, disable_auto_primary_key
  -- abstract, sql, query, table_name, field_names, fields, extends, mixins
  return cls:make_model_class(cls:normalize(options))
end

function ModelSql.normalize(cls, options)
  assert(type(options) == "table", "model must be a table")
  -- **或更详细的empty判断逻辑(即检测是否定义了任一值: extends, mixins, able_name, field_names, fields等)
  assert(next(options), "model must not be empty")
  -- **是否考虑确保parent一定是一个ModelSql
  local extends = options.extends
  local model = {}
  local opts_fields = normalize_array_and_hash_fields(options.fields or {})
  local opts_names = options.field_names
  if not opts_names then
    opts_names = object(opts_fields):keys():sort()
  end
  model.field_names = normalize_field_names(clone(opts_names))
  model.fields = {}
  for i, name in ipairs(opts_names) do
    check_reserved(name)
    if cls[name] then
      error(string_format("field name `%s` conflicts with model class attributes", name))
    end
    local field = opts_fields[name]
    if not field then
      local tname = options.table_name or '[abstract model]'
      if extends then
        field = extends.fields[name]
        if not field then
          error(string_format("'%s' field name '%s' is not in fields and parent fields", tname, name))
        end
      else
        error(string_format("'%s' field name '%s' is not in fields", tname, name))
      end
    elseif not is_field_class(field) then
      if extends then
        local pfield = extends.fields[name]
        if pfield then
          field = utils.dict(pfield:get_options(), field)
          if pfield.model and field.model then
            -- ** 这里选择extends而非mixins, 有待观察
            field.model = cls:make_class {
              abstract = true,
              extends = pfield.model,
              fields = field.model.fields,
              field_names = field.model.field_names
            }
          end
        end
      else
        -- 以json形式定义了一个新的field
      end
    else
      -- 以class形式定义field, 不考虑和父类合并
    end
    if not is_field_class(field) then
      model.fields[name] = make_field_from_json(field, { name = name })
    else
      -- 原样引用还是重新创建一次class? 我选择重新创建
      model.fields[name] = make_field_from_json(field:get_options(), { name = name, type = field.type })
    end
  end
  for key, value in pairs(options) do
    if model[key] == nil and not non_merge_names[key] then
      model[key] = value
    end
  end
  local abstract
  if options.abstract ~= nil then
    abstract = not not options.abstract
  else
    abstract = options.table_name == nil
  end
  model.abstract = abstract
  model.__normalized__ = true
  if options.mixins then
    return cls:merge_models(array(options.mixins) + array { model })
  else
    return model
  end
end

function ModelSql.make_model_class(cls, model)
  -- set foreign_keys, names, auto_now_name, primary_key, sql, name_cache, name_to_label, label_to_name
  -- __index, __is_model_class__, instance_meta
  setmetatable(model, cls)
  local not_abstract = not model.abstract
  if not_abstract then
    if not model.table_name then
      local names_hint = model.field_names and model.field_names:join(",") or "no field_names"
      error(string_format("you must define table_name for a non-abstract model (%s)", names_hint))
    end
    check_reserved(model.table_name)
  end
  local pk_defined = false
  model.foreign_keys = {}
  model.names = array {}
  for name, field in pairs(model.fields) do
    local fk_model = field.reference
    if fk_model == "self" then
      fk_model = model
      field.reference = model
    end
    if fk_model then
      model.foreign_keys[name] = field
    end
    if field.primary_key then
      local pk_name = field.name
      assert(not pk_defined, string_format('duplicated primary key: "%s" and "%s"', pk_name, pk_defined))
      pk_defined = pk_name
      model.primary_key = pk_name
    elseif field.auto_now then
      model.auto_now_name = field.name
    elseif field.auto_now_add then
    else
      model.names:push(name)
    end
  end
  -- ensure primary key
  if not_abstract and not pk_defined and not model.disable_auto_primary_key then
    local pk_name = model.default_primary_key or "id"
    model.primary_key = pk_name
    model.fields[pk_name] = Field.integer { name = pk_name, primary_key = true, serial = true }
    table.insert(model.field_names, 1, pk_name)
  end
  -- sql

  if not_abstract then
    model.name_cache = {}
  end
  model.label_to_name = {}
  model.name_to_label = {}
  for name, field in pairs(model.fields) do
    model.label_to_name[field.label] = name
    model.name_to_label[name] = field.label
    if not_abstract then
      model.name_cache[name] = model.table_name .. "." .. name
    end
    if field.db_type == Field.basefield.NOT_DEFIEND then
      field.db_type = model.fields[field.reference_column].db_type
    end
  end
  if model.abstract then
    return model
  end
  model.__index = model
  model.__is_model_class__ = true
  model.instance_meta = make_model_instance_meta(model, cls)
  return model
end

function ModelSql.mix_with_base(cls, ...)
  return cls:mix(base_model, ...)
end

function ModelSql.mix(cls, ...)
  local models = array { ... }
  if #models == 1 then
    -- 只有一个model, reduce不会调用merge_model_fn, 所以手动处理
    -- ** 或者此处考虑直接报错, 因为1个model混合个啥?
    return cls:make_class(models[1])
  elseif #models > 1 then
    return cls:make_model_class(cls:merge_models(models))
  else
    error("empty mixins passed to model.mix")
  end
end

function ModelSql.merge_model_fn(a, b)
  return ModelSql:merge_model(a, b)
end

function ModelSql.merge_models(cls, models)
  return array(models):reduce(cls.merge_model_fn)
end

function ModelSql.merge_model(cls, a, b)
  local A = a.__normalized__ and a or cls:normalize(a)
  local B = b.__normalized__ and b or cls:normalize(b)
  local C = {}
  local field_names = (A.field_names + B.field_names):uniq()
  local fields = {}
  for i, name in ipairs(field_names) do
    local a_field = A.fields[name]
    local b_field = B.fields[name]
    if a_field and b_field then
      fields[name] = ModelSql:merge_field(a_field, b_field)
    elseif a_field then
      fields[name] = a_field
    else
      fields[name] = b_field
    end
  end
  -- merge的时候abstract应该当做可合并的属性
  for i, M in ipairs { A, B } do
    for key, value in pairs(M) do
      if not non_merge_names[key] then
        C[key] = value
      end
    end
  end
  C.field_names = field_names
  C.fields = fields
  return cls:normalize(C)
end

function ModelSql.merge_field(cls, a, b)
  local aopts = a.__is_field_class__ and a:get_options() or clone(a)
  local bopts = b.__is_field_class__ and b:get_options() or clone(b)
  local options = utils.dict(aopts, bopts)
  if aopts.model and bopts.model then
    options.model = cls:merge_model(aopts.model, bopts.model)
  end
  return make_field_from_json(options)
end

-- function ModelSql.new(cls, attrs)
--   return setmetatable(attrs or {}, cls.instance_meta)
-- end

function ModelSql.all(cls)
  local records = assert(cls.query("SELECT * FROM " .. cls.table_name))
  for i = 1, #records do
    records[i] = cls:load(records[i])
  end
  return setmetatable(records, array)
end

function ModelSql.save(cls, input, names, key)
  key = key or cls.primary_key
  if rawget(input, key) ~= nil then
    return cls:save_update(input, names, key)
  else
    return cls:save_create(input, names, key)
  end
end

function ModelSql.save_create(cls, input, names, key)
  local data, err = cls:validate_create(input, names)
  if err then
    return nil, err
  else
    return cls:create_from(data, key)
  end
end

function ModelSql.save_update(cls, input, names, key)
  local data, err = cls:validate_update(input, names)
  if err then
    return nil, err
  else
    key = key or cls.primary_key
    data[key] = input[key] -- ensure key is in
    return cls:update_from(data, key)
  end
end

function ModelSql.save_from(cls, data, key)
  key = key or cls.primary_key
  if rawget(data, key) ~= nil then
    return cls:update_from(data, key)
  else
    return cls:create_from(data, key)
  end
end

function ModelSql.create_from(cls, data, key)
  key = key or cls.primary_key
  local prepared, err = cls:prepare_for_db(data)
  if prepared == nil then
    return nil, err
  end
  local created = Sql.insert(cls:new {}, prepared):returning(key):execr()
  data[key] = created[1][key]
  return cls:new(data)
end

function ModelSql.update_from(cls, data, key)
  key = key or cls.primary_key
  local prepared, err = cls:prepare_for_db(data, nil, true)
  if prepared == nil then
    return nil, err
  end
  local look_value = assert(data[key], "no key provided for update")
  local ok, res = pcall(function()
    return Sql.update(cls:new {}, prepared):where { [key] = look_value }:execr()
  end)
  if ok then
    if res.affected_rows == 1 then
      return cls:new(data)
    elseif res.affected_rows == 0 then
      error(string_format("update failed, record does not exist(model:%s, key:%s, value:%s)", cls.table_name,
        key, look_value))
    else
      error(
        string_format("not 1 record are updated(model:%s, key:%s, value:%s)", cls.table_name, key, look_value))
    end
  else
    error("update error:" .. tostring(res))
  end
end

function ModelSql.prepare_for_db(cls, data, columns, is_update)
  local prepared = {}
  for _, name in ipairs(columns or cls.names) do
    local field = cls.fields[name]
    if not field then
      error(string_format("invalid field name '%s' for model '%s'", name, cls.table_name))
    end
    local value = data[name]
    if field.prepare_for_db and value ~= nil then
      local val, err = field:prepare_for_db(value, data)
      if val == nil and err then
        return nil, { name = name, err = err, label = field.label }
      else
        prepared[name] = val
      end
    else
      prepared[name] = value
    end
  end
  if is_update and cls.auto_now_name then
    prepared[cls.auto_now_name] = ngx_localtime()
  end
  return prepared
end


function ModelSql.validate(cls, input, names, key)
  if rawget(input, key or cls.primary_key) ~= nil then
    return cls:validate_update(input, names)
  else
    return cls:validate_create(input, names)
  end
end

function ModelSql.validate_create(cls, input, names)
  local data = {}
  local value, err
  for _, name in ipairs(names or cls.names) do
    local field = cls.fields[name]
    if not field then
      error(string_format("invalid field name '%s' for model '%s'", name, cls.table_name))
    end
    value, err = field:validate(rawget(input, name), input)
    if err ~= nil then
      return nil, { name = name, err = err, label = field.label, http_code = 422 }
    elseif field.default and (value == nil or value == "") then
      if type(field.default) ~= "function" then
        value = field.default
      else
        value, err = field.default(input)
        if value == nil then
          return nil, { name = name, err = err, label = field.label, http_code = 422 }
        end
      end
    end
    data[name] = value
  end
  if not cls.clean then
    return data
  else
    local res, clean_err = cls:clean(data)
    if res == nil then
      return nil, cls:parse_error_message(clean_err)
    else
      return res
    end
  end
end

function ModelSql.validate_update(cls, input, names)
  local data = {}
  local value, err
  for _, name in ipairs(names or cls.names) do
    local field = cls.fields[name]
    if not field then
      error(string_format("invalid field name '%s' for model '%s'", name, cls.table_name))
    end
    value = rawget(input, name)
    if value ~= nil then
      value, err = field:validate(value, input)
      if err ~= nil then
        return nil, { name = name, err = err, label = field.label, http_code = 422 }
      elseif value == nil then
        -- value is nil again after `validate`,its a non-required field whose value is empty string.
        -- data[name] = field.get_empty_value_to_update(input)
        -- 这里统一用空白字符串占位,以便prepare_for_db处pairs能处理该name
        data[name] = ""
      else
        data[name] = value
      end
    end
  end
  if not cls.clean then
    return data
  else
    local res, clean_err = cls:clean(data)
    if res == nil then
      return nil, cls:parse_error_message(clean_err)
    else
      return res
    end
  end
end
---comment
---@param cls ModelSql
---@param rows rows
---@param columns string[]?
---@return table?, string[]?
function ModelSql.validate_create_data(cls, rows, columns)
  local err_obj, cleaned
  columns = columns or cls:_get_keys(rows)
  if rows[1] then
    cleaned = {}
    for i, row in ipairs(rows) do
      row, err_obj = cls:validate_create(row, columns)
      if err_obj then
        err_obj.index = i
        return nil, err_obj
      end
      cleaned[i] = row
    end
  else
    cleaned, err_obj = cls:validate_create(rows, columns)
    if err_obj then
      return nil, err_obj
    end
  end
  return cleaned, columns
end

function ModelSql.validate_update_data(cls, rows, columns)
  local err_obj, cleaned
  columns = columns or cls:_get_keys(rows)
  if rows[1] then
    cleaned = {}
    for i, row in ipairs(rows) do
      row, err_obj = cls:validate_update(row, columns)
      if err_obj then
        err_obj.index = i
        return nil, err_obj
      end
      cleaned[i] = row
    end
  else
    cleaned, err_obj = cls:validate_update(rows, columns)
    if err_obj then
      return nil, err_obj
    end
  end
  return cleaned, columns
end
---comment
---@param cls ModelSql
---@param rows rows
---@param key keys?
---@param columns string[]?
---@return rows?, keys?, string[]?
function ModelSql.validate_create_rows(cls, rows, key, columns)
  local rows2, key2 = check_upsert_key(rows, key or cls.primary_key)
  if rows2 == nil then
    return nil, key2
  end
  rows2, columns = cls:validate_create_data(rows2, columns)
  if rows2 == nil then
    return nil, columns
  end
  return rows2, key2, columns
end



function ModelSql.parse_error_message(cls, err)
  if type(err) == 'table' then
    return err
  end
  local captured = match(err, '^(?<name>.+?)~(?<message>.+?)$', 'josui')
  if not captured then
    return error("can't parse this model error message: " .. err)
  else
    local name = captured.name
    local message = captured.message
    local label = cls.name_to_label[name]
    return { name = name, err = message, label = label, http_code = 422 } -- string_format("%s：%s", name, message)
  end
end

function ModelSql.load(cls, data)
  local err
  for _, name in ipairs(cls.names) do
    local field = cls.fields[name]
    local value = data[name]
    if value ~= nil then
      if not field.load then
        data[name] = value
      else
        data[name], err = field:load(value)
        if err then
          error(err, 0)
        end
      end
    end
  end
  return cls:new(data)
end

function ModelSql.validate_update_rows(cls, rows, key, columns)
  rows, key = check_upsert_key(rows, key or cls.primary_key)
  if rows == nil then
    return nil, key
  end
  rows, columns = cls:validate_update_data(rows, columns)
  if rows == nil then
    return nil, columns
  end
  return rows, key, columns
end
---comment
---@param cls ModelSql
---@param rows rows
---@param columns keys?
---@param is_update boolean?
---@return table?, keys?
function ModelSql.prepare_db_rows(cls, rows, columns, is_update)
  local err, cleaned
  columns = columns or cls:_get_keys(rows)
  if rows[1] then
    cleaned = {}
    for i, row in ipairs(rows) do
      row, err = cls:prepare_for_db(row, columns, is_update)
      if row == nil then
        return nil, err
      end
      cleaned[i] = row
    end
  else
    cleaned, err = cls:prepare_for_db(rows, columns, is_update)
    if cleaned == nil then
      return nil, err
    end
  end
  if is_update then
    local utime = cls.auto_now_name
    if utime and not array(columns):includes(utime) then
      columns[#columns + 1] = utime
    end
    return cleaned, columns
  else
    return cleaned, columns
  end
end

function ModelSql.pcall(self)
  self._pcall = true
  return self
end

---@param self ModelSql
---@param err string|table
---@param level? number
---@return nil, string|table
---@return any
function ModelSql.error(self, err, level)
  if self._pcall then
    return nil, err
  else
    error(err, level)
  end
end

---@alias row {[string]:dbvalue}
---@alias rows row[]
---get keys array from a row or row array
---@param self ModelSql
---@param rows row|rows
---@return string[]
function ModelSql._get_keys(self, rows)
  local columns = {}
  if rows[1] then
    local d = {}
    for _, row in ipairs(rows) do
      for k, _ in pairs(row) do
        if not d[k] then
          d[k] = true
          table_insert(columns, k)
        end
      end
    end
  else
    for k, _ in pairs(rows) do
      table_insert(columns, k)
    end
  end
  return columns
end

---convert rows to array of array that insert values use
---@param self ModelSql
---@param rows row[]
---@param columns string[]
---@return dbvalue[][]
function ModelSql._rows_to_array(self, rows, columns)
  local c = #columns
  local n = #rows
  local res = table_new(n, 0)
  local fields = self.fields
  for i = 1, n do
    res[i] = table_new(c, 0)
  end
  for i, col in ipairs(columns) do
    for j = 1, n do
      local v = rows[j][col]
      if v ~= nil and v ~= '' then
        res[j][i] = v
      elseif fields[col] then
        local default = fields[col].default
        if default ~= nil then
          res[j][i] = fields[col]:get_default(rows[j])
        else
          res[j][i] = NULL
        end
      else
        res[j][i] = NULL
      end
    end
  end
  return res
end

---{name="kate", age=11} => "('kate', 11)", {"name", "age"}
---@param self ModelSql
---@param row row
---@param columns? string[]
---@return string, string[]
function ModelSql._get_insert_values_token(self, row, columns)
  local value_list = {}
  if not columns then
    columns = {}
    for k, v in pairs(row) do
      table_insert(columns, k)
      table_insert(value_list, v)
    end
  else
    for _, col in pairs(columns) do
      local v = row[col]
      if v ~= nil then
        table_insert(value_list, v)
      else
        table_insert(value_list, DEFAULT)
      end
    end
  end
  return as_literal(value_list), columns
end

---@param self ModelSql
---@param rows row[]
---@param columns? string[]
---@return string[], string[]
function ModelSql._get_bulk_insert_values_token(self, rows, columns)
  columns = columns or self:_get_keys(rows)
  rows = self:_rows_to_array(rows, columns)
  return map(rows, as_literal), columns
end

---f({'a','b','c'}, 'a', 'V') => 'b = V.b, c = V.c'
---f({'a','b','c'}, {'a','b'}, 'V') => 'c = V.c'
---use V as data table name so both ModelSql.upsert and ModelSql.merge can use it.
---@param self ModelSql
---@param columns string[]
---@param key keys
---@param table_name string
---@return string
function ModelSql._get_update_token_with_prefix(self, columns, key, table_name)
  local tokens = {}
  if type(key) == "string" then
    for i, col in ipairs(columns) do
      if col ~= key then
        table_insert(tokens, string_format("%s = %s.%s", col, table_name, col))
      end
    end
  else
    local sets = {}
    for i, k in ipairs(key) do
      sets[k] = true
    end
    for i, col in ipairs(columns) do
      if not sets[col] then
        table_insert(tokens, string_format("%s = %s.%s", col, table_name, col))
      end
    end
  end
  return table_concat(tokens, ", ")
end

---parse select token
---@param self ModelSql
---@param a dbvalue
---@param b? dbvalue
---@param ...? dbvalue[]
---@return string
function ModelSql._get_select_token(self, a, b, ...)
  if a == nil then
    error(b or "augument is required for _get_select_token")
  elseif b == nil then
    if type(a) == "table" then
      local tokens = {}
      for i = 1, #a do
        tokens[i] = self:_get_column(a[i])
      end
      return as_token(tokens)
    elseif type(a) == "string" then
      return self:_get_column(a)
    else
      return as_token(a)
    end
  else
    a = self:_get_column(a)
    b = self:_get_column(b)
    local s = as_token(a) .. ", " .. as_token(b)
    for i = 1, select("#", ...) do
      local name = select(i, ...)
      s = s .. ", " .. as_token(self:_get_column(name))
    end
    return s
  end
end

---parse select literal token
---@param self ModelSql
---@param a dbvalue
---@param b? dbvalue
---@param ...? dbvalue[]
---@return string
function ModelSql._get_select_token_literal(self, a, b, ...)
  if b == nil then
    if type(a) == "table" then
      local tokens = {}
      for i = 1, #a do
        tokens[i] = as_literal(a[i])
      end
      return as_token(tokens)
    else
      return as_literal(a)
    end
  else
    local s = as_literal(a) .. ", " .. as_literal(b)
    for i = 1, select("#", ...) do
      local name = select(i, ...)
      s = s .. ", " .. as_literal(name)
    end
    return s
  end
end

---f{name='kate', age=22} => "name = 'kate', age = 22"
---@param self ModelSql
---@param row row
---@param columns? string[]
---@return string
function ModelSql._get_update_token(self, row, columns)
  local kv = {}
  if not columns then
    for k, v in pairs(row) do
      table_insert(kv, string_format("%s = %s", k, as_literal(v)))
    end
  else
    for _, k in ipairs(columns) do
      local v = row[k]
      table_insert(kv, string_format("%s = %s", k, v ~= nil and as_literal(v) or 'DEFAULT'))
    end
  end
  return table_concat(kv, ", ")
end

---@param self ModelSql
---@param name string
---@param token? ModelSql|dbvalue
---@return string
function ModelSql._get_with_token(self, name, token)
  if token == nil then
    return name
  elseif self:is_instance(token) then
    return string_format("%s AS (%s)", name, token:statement())
  else
    return string_format("%s AS %s", name, token)
  end
end

---return a string like: (col, col2) VALUES ('v1', 'v2')
---@param self ModelSql
---@param row row
---@param columns? string[]
---@return string
function ModelSql._get_insert_token(self, row, columns)
  local values_token, insert_columns = self:_get_insert_values_token(row, columns)
  return string_format("(%s) VALUES %s", as_token(insert_columns), values_token)
end

---@param self ModelSql
---@param rows row[]
---@param columns? string[]
---@return string
function ModelSql._get_bulk_insert_token(self, rows, columns)
  rows, columns = self:_get_bulk_insert_values_token(rows, columns)
  return string_format("(%s) VALUES %s", as_token(columns), as_token(rows))
end

---comment
---@param self ModelSql
---@param sub_query ModelSql
---@param columns? string[]
function ModelSql._set_select_subquery_insert_token(self, sub_query, columns)
  local columns_token = as_token(columns or sub_query._select or "")
  if columns_token ~= "" then
    self._insert = string_format("(%s) %s", columns_token, sub_query:statement())
  else
    self._insert = sub_query:statement()
  end
end

--- 当literal_columns存在时:with d(c1,c2) as (delete from t returning c1,c2,'v1','v2')
--- 但似乎没有影响, 即returning列多于with d(c1,c2)中的列
---set insert values from insert/update/delete returning
---@param self ModelSql
---@param sub_query ModelSql
function ModelSql._set_cud_subquery_insert_token(self, sub_query)
  local cte_return = sub_query._cte_returning
  if cte_return then
    local cte_columns = cte_return.columns
    local insert_columns = merge_table(cte_columns, cte_return.literal_columns)
    -- local cud_select_query = ModelSql:new { table_name = "d" }:select(cte_columns):select_literal(cte_return.literals)
    local cud_select_query = ModelSql:new { table_name = "d" }:select(insert_columns)
    -- self:with(string_format("d(%s)", as_token(cte_columns)), sub_query)
    self:with(string_format("d(%s)", as_token(insert_columns)), sub_query)
    self._insert = string_format("(%s) %s", as_token(insert_columns), cud_select_query:statement())
  elseif sub_query._returning_args then
    local insert_columns = flat(sub_query._returning_args)
    local cud_select_query = ModelSql:new { table_name = "d" }:select(insert_columns)
    self:with(string_format("d(%s)", as_token(insert_columns)), sub_query)
    self._insert = string_format("(%s) %s", as_token(insert_columns), cud_select_query:statement())
  end
end

---comment
---@param self ModelSql
---@param row row
---@param key keys
---@param columns? string[]
---@return string
function ModelSql._get_upsert_token(self, row, key, columns)
  local values_token, columns = self:_get_insert_values_token(row, columns)
  local insert_token = string_format("(%s) VALUES %s ON CONFLICT (%s)", as_token(columns), values_token,
    self:_get_select_token(key))
  if (type(key) == "table" and #key == #columns) or #columns == 1 then
    return string_format("%s DO NOTHING", insert_token)
  else
    return string_format("%s DO UPDATE SET %s", insert_token,
      self:_get_update_token_with_prefix(columns, key, "EXCLUDED"))
  end
end

---comment
---@param self ModelSql
---@param rows row[]
---@param key keys
---@param columns? string[]
---@return string
function ModelSql._get_bulk_upsert_token(self, rows, key, columns)
  rows, columns = self:_get_bulk_insert_values_token(rows, columns)
  local insert_token = string_format("(%s) VALUES %s ON CONFLICT (%s)", as_token(columns), as_token(rows),
    self:_get_select_token(key))
  if (type(key) == "table" and #key == #columns) or #columns == 1 then
    return string_format("%s DO NOTHING", insert_token)
  else
    return string_format("%s DO UPDATE SET %s", insert_token,
      self:_get_update_token_with_prefix(columns, key, "EXCLUDED"))
  end
end

---comment
---@param self ModelSql
---@param rows ModelSql
---@param key keys
---@param columns string[]
---@return string
function ModelSql._get_upsert_query_token(self, rows, key, columns)
  local columns_token = self:_get_select_token(columns)
  local insert_token = string_format("(%s) %s ON CONFLICT (%s)", columns_token, rows:statement(),
    self:_get_select_token(key))
  if (type(key) == "table" and #key == #columns) or #columns == 1 then
    return string_format("%s DO NOTHING", insert_token)
  else
    return string_format("%s DO UPDATE SET %s", insert_token,
      self:_get_update_token_with_prefix(columns, key, "EXCLUDED"))
  end
end

---comment
---@param self ModelSql
---@param a string
---@param b? string
---@param c? string
---@return string
function ModelSql._get_join_expr(self, a, b, c)
  if b == nil then
    return a
  elseif c == nil then
    return string_format("%s = %s", a, b)
  else
    return string_format("%s %s %s", a, b, c)
  end
end

---comment
---@param self ModelSql
---@param join_type string
---@param right_table string
---@param conditions string
---@param ... string
---@return string
function ModelSql._get_join_token(self, join_type, right_table, conditions, ...)
  if conditions ~= nil then
    return string_format("%s JOIN %s ON (%s)", join_type, right_table, self:_get_join_expr(conditions, ...))
  else
    return string_format("%s JOIN %s", join_type, right_table)
  end
end

---comment
---@param self ModelSql
---@param right_table string
---@param conditions string
---@param ... string
---@return string
function ModelSql._get_inner_join(self, right_table, conditions, ...)
  return self:_get_join_token("INNER", right_table, conditions, ...)
end

---@param self ModelSql
---@param right_table string
---@param conditions string
---@param ... string
---@return string
function ModelSql._get_left_join(self, right_table, conditions, ...)
  return self:_get_join_token("LEFT", right_table, conditions, ...)
end

---@param self ModelSql
---@param right_table string
---@param conditions string
---@param ... string
---@return string
function ModelSql._get_right_join(self, right_table, conditions, ...)
  return self:_get_join_token("RIGHT", right_table, conditions, ...)
end

---@param self ModelSql
---@param right_table string
---@param conditions string
---@param ... string
---@return string
function ModelSql._get_full_join(self, right_table, conditions, ...)
  return self:_get_join_token("FULL", right_table, conditions, ...)
end

---comment
---@param self ModelSql
---@param cols keys
---@param range ModelSql|table|string
---@param operator? string
---@return string
function ModelSql._get_in_token(self, cols, range, operator)
  cols = as_token(cols)
  operator = operator or "IN"
  if type(range) == 'table' then
    if self:is_instance(range) then
      return string_format("(%s) %s (%s)", cols, operator, range:statement())
    else
      return string_format("(%s) %s %s", cols, operator, as_literal(range))
    end
  else
    return string_format("(%s) %s %s", cols, operator, range)
  end
end

---@param self ModelSql
---@param sub_select ModelSql
---@param columns? string[]
---@return string
function ModelSql._get_update_query_token(self, sub_select, columns)
  local columns_token = columns and self:_get_select_token(columns) or sub_select._select
  return string_format("(%s) = (%s)", columns_token, sub_select:statement())
end

---@param self ModelSql
---@param key keys
---@param left_table string
---@param right_table string
---@return string
function ModelSql._get_join_conditions(self, key, left_table, right_table)
  if type(key) == "string" then
    return string_format("%s.%s = %s.%s", left_table, key, right_table, key)
  end
  local res = {}
  for _, k in ipairs(key) do
    res[#res + 1] = string_format("%s.%s = %s.%s", left_table, k, right_table, k)
  end
  return table_concat(res, " AND ")
end

---@param self ModelSql
---@param rows row[]
---@param columns string[]
---@param no_check? boolean
---@return string[], string[]
function ModelSql._get_cte_values_literal(self, rows, columns, no_check)
  columns = columns or self:_get_keys(rows)
  rows = self:_rows_to_array(rows, columns)
  local first_row = rows[1]
  for i, col in ipairs(columns) do
    local field = self:_find_field_model(col)
    if field then
      first_row[i] = string_format("%s::%s", as_literal(first_row[i]), field.db_type)
    elseif no_check then
      first_row[i] = as_literal(first_row[i])
    else
      error("invalid field name for _get_cte_values_literal: " .. col)
    end
  end
  ---@type string[]
  local res = {}
  res[1] = '(' .. as_token(first_row) .. ')'
  for i = 2, #rows, 1 do
    res[i] = as_literal(rows[i])
  end
  return res, columns
end

function ModelSql._handle_join(self, join_type, join_table, join_cond)
  if self._update then
    self:from(join_table)
    self:where(join_cond)
  elseif self._delete then
    self:using(join_table)
    self:where(join_cond)
  else
    self.Sql[join_type .. '_join'](self, join_table, join_cond)
  end
end

function ModelSql._register_join_model(self, join_args, join_type)
  join_type = join_type or join_args.join_type or "INNER"
  local find = true
  local model = join_args.model or self
  local fk_model = join_args.fk_model
  local column = join_args.column
  local fk_column = join_args.fk_column
  local join_key
  if join_args.join_key == nil then
    if self.table_name == model.table_name then
      -- 如果是本体model连接, 则join_key的定义方式与_get_where_key和load_fk一致,避免生成重复的join
      -- 同一个列,可能和不同的表join多次, 因此要加上外键表名, 避免自动判断错误
      join_key = column .. "__" .. fk_model.table_name
    else
      join_key = string_format("%s__%s__%s__%s__%s", join_type, model.table_name, column, fk_model.table_name,
        fk_column)
    end
  else
    join_key = join_args.join_key
  end
  if not self._join_keys then
    self._join_keys = {}
  end
  local join_obj = self._join_keys[join_key]
  if not join_obj then
    find = false
    join_obj = {
      join_type = join_type,
      model = model,
      column = column,
      alias = join_args.alias or model.table_name,
      fk_model = fk_model,
      fk_column = fk_column,
      fk_alias = 'T' .. self:_get_join_number()
    }
    local join_table = string_format("%s %s", fk_model.table_name, join_obj.fk_alias)
    local join_cond = string_format("%s.%s = %s.%s", join_obj.alias, join_obj.column, join_obj.fk_alias,
      join_obj.fk_column)
    self:_handle_join(join_type:lower(), join_table, join_cond)
    self._join_keys[join_key] = join_obj
  end
  return join_obj, find
end

---comment
---@param self ModelSql
---@param col string
---@return table?, ModelSql?, string?
function ModelSql._find_field_model(self, col)
  local field = self.fields[col]
  if field then
    return field, self, self._as or self.table_name
  end
  if not self._join_keys then
    return
  end
  for _, join_obj in pairs(self._join_keys) do
    local fk_field = join_obj.fk_model.fields[col]
    if join_obj.model.table_name == self.table_name and fk_field then
      return fk_field, join_obj.fk_model, (join_obj.fk_alias or join_obj.fk_model.table_name)
    end
  end
end

function ModelSql._get_where_key(self, key)
  local a, b = key:find("__", 1, true)
  if not a then
    return self:_get_column(key), "eq"
  end
  local e = key:sub(1, a - 1)
  local field, model, prefix = self:_find_field_model(e)
  if not field or not model then
    error(string_format("%s is not a valid field name for %s", e, self.table_name))
  end
  local i, state, fk_model, rc, join_key
  local operator = "eq"
  local field_name = e
  if field.reference then
    fk_model = field.reference
    rc = field.reference_column
    state = FOREIGN_KEY
  else
    state = NON_FOREIGN_KEY
  end
  while true do
    i = b + 1
    a, b = key:find("__", i, true)
    if not a then
      e = key:sub(i)
    else
      e = key:sub(i, a - 1)
    end
    if state == NON_FOREIGN_KEY then
      -- foo__lt, foo__gt, etc
      operator = e
      state = END
    elseif state == FOREIGN_KEY then
      local field_of_fk = fk_model.fields[e]
      if field_of_fk then
        -- profile{usr__sfzh}, fk_model: usr, rc: id
        if not join_key then
          join_key = field_name .. "__" .. fk_model.table_name
        else
          join_key = join_key .. "__" .. field_name
        end
        local join_obj = self:_register_join_model {
          join_key = join_key,
          model = model,
          column = field_name,
          alias = prefix or model.table_name,
          fk_model = fk_model,
          fk_column = rc
        }
        prefix = join_obj.fk_alias
        if field_of_fk.reference then
          -- -- profile{usr__addr__like}, fk_model: usr, rc: id
          model = fk_model
          fk_model = field_of_fk.reference
          rc = field_of_fk.reference_column
        else
          -- fk1__name
          state = NON_FOREIGN_KEY
        end
        field_name = e
      else
        -- fk__eq, fk__lt, etc
        operator = e
        state = END
      end
    else
      return self:error(string_format("invalid condition table key parsing state %s with token %s", state, e))
    end
    if not a then
      break
    end
  end
  return prefix .. "." .. field_name, operator
end

function ModelSql._get_column(self, key)
  if self.fields[key] then
    return self._as and (self._as .. '.' .. key) or self.name_cache[key]
  end
  if not self._join_keys then
    return key
  end
  for _, join_obj in pairs(self._join_keys) do
    if join_obj.model.table_name == self.table_name and join_obj.fk_model.fields[key] then
      return join_obj.fk_alias .. '.' .. key
    end
  end
  return key
end

function ModelSql._get_expr_token(self, value, key, op)
  if op == "eq" then
    return string_format("%s = %s", key, as_literal(value))
  elseif op == "in" then
    return string_format("%s IN %s", key, as_literal(value))
  elseif op == "notin" then
    return string_format("%s NOT IN %s", key, as_literal(value))
  elseif COMPARE_OPERATORS[op] then
    return string_format("%s %s %s", key, COMPARE_OPERATORS[op], as_literal(value))
  elseif op == "contains" then
    return string_format("%s LIKE '%%%s%%'", key, value:gsub("'", "''"))
  elseif op == "startswith" then
    return string_format("%s LIKE '%s%%'", key, value:gsub("'", "''"))
  elseif op == "endswith" then
    return string_format("%s LIKE '%%%s'", key, value:gsub("'", "''"))
  elseif op == "null" then
    if value then
      return string_format("%s IS NULL", key)
    else
      return string_format("%s IS NOT NULL", key)
    end
  else
    error("invalid sql operator: " .. tostring(op))
  end
end

function ModelSql._get_join_number(self)
  if self._join_keys then
    return nkeys(self._join_keys) + 1
  else
    return 1
  end
end

---@param self ModelSql
---@param where_token string
---@param tpl string
---@return ModelSql
function ModelSql._handle_where_token(self, where_token, tpl)
  if where_token == "" then
    return self
  elseif self._where == nil then
    self._where = where_token
  else
    self._where = string_format(tpl, self._where, where_token)
  end
  return self
end

---@param self ModelSql
---@param kwargs {[string|number]:any}
---@param logic? string
---@return string
function ModelSql._get_condition_token_from_table(self, kwargs, logic)
  local tokens = {}
  for k, value in pairs(kwargs) do
    if type(k) == "string" then
      tokens[#tokens + 1] = self:_get_expr_token(value, self:_get_where_key(k))
    else
      local token = self:_get_condition_token(value)
      if token ~= nil and token ~= "" then
        tokens[#tokens + 1] = '(' .. token .. ')'
      end
    end
  end
  if logic == nil then
    return table_concat(tokens, " AND ")
  else
    return table_concat(tokens, " " .. logic .. " ")
  end
end

---@param self ModelSql
---@param a table|string|function
---@param b? dbvalue
---@param c? dbvalue
---@return string
function ModelSql._get_condition_token(self, a, b, c)
  if b == nil then
    return self.Sql._get_condition_token(self, a)
  elseif c == nil then
    return string_format("%s = %s", self:_get_column(a), as_literal(b))
  else
    return string_format("%s %s %s", self:_get_column(a), b, as_literal(c))
  end
end

---@param self ModelSql
---@param a table|string|function
---@param b? dbvalue
---@param c? dbvalue
---@return string
function ModelSql._get_condition_token_or(self, a, b, c)
  if type(a) == "table" then
    return self:_get_condition_token_from_table(a, "OR")
  else
    return self:_get_condition_token(a, b, c)
  end
end

---@param self ModelSql
---@param a table|string|function
---@param b? dbvalue
---@param c? dbvalue
---@return string
function ModelSql._get_condition_token_not(self, a, b, c)
  local token
  if type(a) == "table" then
    token = self:_get_condition_token_from_table(a, "OR")
  else
    token = self:_get_condition_token(a, b, c)
  end
  return token ~= "" and string_format("NOT (%s)", token) or ""
end

---@param self ModelSql
---@param other_sql ModelSql
---@param inner_attr set_type
---@return ModelSql
function ModelSql._handle_set_option(self, other_sql, inner_attr)
  if not self[inner_attr] then
    self[inner_attr] = other_sql:statement();
  else
    self[inner_attr] = string_format("(%s) %s (%s)", self[inner_attr], PG_SET_MAP[inner_attr], other_sql:statement());
  end
  if self ~= ModelSql then
    self.statement = self._statement_for_set
  else
    error("don't call _handle_set_option directly on ModelSql class")
  end
  return self;
end

---@param self ModelSql
---@return string
function ModelSql._statement_for_set(self)
  local statement = ModelSql.statement(self)
  if self._intersect then
    statement = string_format("(%s) INTERSECT (%s)", statement, self._intersect)
  elseif self._intersect_all then
    statement = string_format("(%s) INTERSECT ALL (%s)", statement, self._intersect_all)
  elseif self._union then
    statement = string_format("(%s) UNION (%s)", statement, self._union)
  elseif self._union_all then
    statement = string_format("(%s) UNION ALL (%s)", statement, self._union_all)
  elseif self._except then
    statement = string_format("(%s) EXCEPT (%s)", statement, self._except)
  elseif self._except_all then
    statement = string_format("(%s) EXCEPT ALL (%s)", statement, self._except_all)
  end
  return statement
end

---@param self ModelSql
---@return string
function ModelSql.statement(self)
  local table_name = self:get_table()
  local statement = assemble_sql {
    table_name = table_name,
    with = self._with,
    join = self._join,
    distinct = self._distinct,
    returning = self._returning,
    cte_returning = self._cte_returning,
    insert = self._insert,
    update = self._update,
    delete = self._delete,
    using = self._using,
    select = self._select,
    from = self._from,
    where = self._where,
    group = self._group,
    having = self._having,
    order = self._order,
    limit = self._limit,
    offset = self._offset
  }
  return statement
end

---@param self ModelSql
---@param name string
---@param token? dbvalue
---@return ModelSql
function ModelSql.with(self, name, token)
  local with_token = self:_get_with_token(name, token)
  if self._with then
    self._with = string_format("%s, %s", self._with, with_token)
  else
    self._with = with_token
  end
  return self
end

---comment
---@param self ModelSql
---@param other_sql ModelSql
---@return ModelSql
function ModelSql.union(self, other_sql)
  return self:_handle_set_option(other_sql, "_union");
end

function ModelSql.union_all(self, other_sql)
  return self:_handle_set_option(other_sql, "_union_all");
end

function ModelSql.except(self, other_sql)
  return self:_handle_set_option(other_sql, "_except");
end

function ModelSql.except_all(self, other_sql)
  return self:_handle_set_option(other_sql, "_except_all");
end

function ModelSql.intersect(self, other_sql)
  return self:_handle_set_option(other_sql, "_intersect");
end

function ModelSql.intersect_all(self, other_sql)
  return self:_handle_set_option(other_sql, "_intersect_all");
end

---comment
---@param self ModelSql
---@param table_alias string
---@return ModelSql
function ModelSql.as(self, table_alias)
  self._as = table_alias
  return self
end

---comment
---@param self ModelSql
---@param name string
---@param rows row[]
---@return ModelSql
function ModelSql.with_values(self, name, rows)
  local columns = self:_get_keys(rows[1])
  rows, columns = self:_get_cte_values_literal(rows, columns, true)
  local cte_name = string_format("%s(%s)", name, table_concat(columns, ", "))
  local cte_values = string_format("(VALUES %s)", as_token(rows))
  return self:with(cte_name, cte_values)
end

---comment
---@param self ModelSql
---@param rows rows|ModelSql
---@param columns? string[]
---@return ModelSql
function ModelSql.insert(self, rows, columns)
  if not self:is_instance(rows) then
    if not self._skip_validate then
      rows, columns = self:validate_create_data(rows, columns)
      if rows == nil then
        error(columns)
      end
    end
    rows, columns = self:prepare_db_rows(rows, columns)
    if rows == nil then
      error(columns)
    end
  end
  return self.Sql.insert(self, rows, columns)
end

---comment
---@param self ModelSql
---@param row row|string|ModelSql
---@param columns? string[]
---@return ModelSql
function ModelSql.update(self, row, columns)
  if not self:is_instance(row) then
    if not self._skip_validate then
      row, columns = self:validate_update(row, columns)
      if row == nil then
        error(columns)
      end
    end
    row, columns = self:prepare_db_rows(row, columns, true)
    if row == nil then
      error(columns)
    end
  end
  return self.Sql.update(self, row, columns)
end

function ModelSql.gets(self, keys, columns)
  if self._commit == nil or self._commit then
    return self.Sql.gets(self, keys, columns):execr()
  else
    return self.Sql.gets(self, keys, columns)
  end
end

---comment
---@param self ModelSql
---@param row any
---@return boolean
function ModelSql.is_instance(self, row)
  return is_sql_instance(row)
end

---comment
---@param self ModelSql
---@param rows row[]
---@param key keys?
---@param columns string[]?
---@return ModelSql
function ModelSql.merge(self, rows, key, columns)
  if #rows == 0 then
    error("empty rows passed to merge")
  end
  if not self._skip_validate then
    rows, key, columns = self:validate_create_rows(rows, key, columns)
    if rows == nil then
      error(key)
    end
  end
  rows, columns = self:prepare_db_rows(rows, columns, false)
  if rows == nil then
    error(columns)
  end
  self = Sql.merge(self, rows, key, columns)
  if self._commit == nil or self._commit then
    if not self._returning then
      return self:returning(key):compact():execr()
    else
      return self:compact():execr()
    end
  else
    return self
  end
end

---comment
---@param self ModelSql
---@param rows row[]
---@param key keys
---@param columns string[]
---@return ModelSql
function ModelSql.upsert(self, rows, key, columns)
  if #rows == 0 then
    error("empty rows passed to merge")
  end
  if not self._skip_validate then
    rows, key, columns = self:validate_create_rows(rows, key, columns)
    if rows == nil then
      error(key)
    end
  end
  rows, columns = self:prepare_db_rows(rows, columns, false)
  if rows == nil then
    error(columns)
  end
  self = Sql.upsert(self, rows, key, columns)
  if self._commit == nil or self._commit then
    if not self._returning then
      return self:returning(key):compact():execr()
    else
      return self:compact():execr()
    end
  else
    return self
  end
end

---comment
---@param self ModelSql
---@param rows row[]|ModelSql
---@param key keys
---@param columns string[]
---@return ModelSql
function ModelSql.updates(self, rows, key, columns)
  if #rows == 0 then
    error("empty rows passed to merge")
  end
  if not self._skip_validate then
    rows, key, columns = self:validate_updates_rows(rows, key, columns)
    if rows == nil then
      error(key)
    end
  end
  rows, columns = self:prepare_db_rows(rows, columns, false)
  if rows == nil then
    error(columns)
  end
  self = Sql.updates(self, rows, key, columns)
  if self._commit == nil or self._commit then
    if not self._returning then
      return self:returning(key):compact():execr()
    else
      return self:compact():execr()
    end
  else
    return self
  end
end

---comment
---@param self ModelSql
---@param rows row[]
---@param keys keys
---@return ModelSql
function ModelSql.merge_gets(self, rows, keys)
  local columns = self:_get_keys(rows[1])
  rows, columns = self:_get_cte_values_literal(rows, columns, true)
  local join_cond = self:_get_join_conditions(keys, "V", self._as or self.table_name)
  local cte_name = string_format("V(%s)", table_concat(columns, ", "))
  local cte_values = string_format("(VALUES %s)", as_token(rows))
  local res = self.Sql.select(self, "V.*"):with(cte_name, cte_values):right_join("V", join_cond)
  if self._commit == nil or self._commit then
    return res:execr()
  else
    return res
  end
end

---comment
---@param self ModelSql
---@return ModelSql
function ModelSql.copy(self)
  local copy_sql = {}
  for key, value in pairs(self) do
    if type(value) == 'table' then
      copy_sql[key] = clone(value)
    else
      copy_sql[key] = value
    end
  end
  return setmetatable(copy_sql, getmetatable(self))
end

---comment
---@param self ModelSql
---@param ...? unknown
---@return ModelSql
function ModelSql.delete(self, ...)
  self._delete = true
  if ... ~= nil then
    self:where(...)
  end
  return self
end

---comment
---@param self ModelSql
---@return ModelSql
function ModelSql.distinct(self)
  self._distinct = true
  return self
end

---comment
---@param self ModelSql
---@param ...? dbvalue[]
---@return ModelSql
function ModelSql.select(self, ...)
  local s = self:_get_select_token(...)
  if not self._select then
    self._select = s
  elseif s ~= nil and s ~= "" then
    self._select = self._select .. ", " .. s
  end
  return self
end

---comment
---@param self ModelSql
---@param ...? dbvalue[]
---@return ModelSql
function ModelSql.select_literal(self, ...)
  local s = self:_get_select_token_literal(...)
  if not self._select then
    self._select = s
  elseif s ~= nil and s ~= "" then
    self._select = self._select .. ", " .. s
  end
  return self
end

---@param self ModelSql
---@param ...? dbvalue[]
---@return ModelSql
function ModelSql.returning(self, ...)
  local s = self:_get_select_token(...)
  if not self._returning then
    self._returning = s
  elseif s ~= nil and s ~= "" then
    self._returning = self._returning .. ", " .. s
  else
    return self
  end
  if self._returning_args then
    self._returning_args = { self._returning_args, ... }
  else
    self._returning_args = { ... }
  end
  return self
end

---@param self ModelSql
---@param ...? dbvalue[]
---@return ModelSql
function ModelSql.returning_literal(self, ...)
  local s = self:_get_select_token_literal(...)
  if not self._returning then
    self._returning = s
  elseif s ~= nil and s ~= "" then
    self._returning = self._returning .. ", " .. s
  end
  if self._returning_args then
    self._returning_args = { self._returning_args, ... }
  else
    self._returning_args = { ... }
  end
  return self
end

---comment
---@param self ModelSql
---@param opts cte_returning_opts
---@return ModelSql
function ModelSql.cte_returning(self, opts)
  self._cte_returning = opts
  return self
end

function ModelSql.group(self, ...)
  if not self._group then
    self._group = self:_get_select_token(...)
  else
    self._group = self._group .. ", " .. self:_get_select_token(...)
  end
  return self
end

function ModelSql.group_by(self, ...) return self:group(...) end

function ModelSql.order(self, ...)
  if not self._order then
    self._order = self:_get_select_token(...)
  else
    self._order = self._order .. ", " .. self:_get_select_token(...)
  end
  return self
end

function ModelSql.order_by(self, ...) return self:order(...) end

function ModelSql._get_args_token(self, ...) return self:_get_select_token(...) end

function ModelSql.using(self, ...)
  self._delete = true
  self._using = self:_get_args_token(...)
  return self
end

function ModelSql.from(self, ...)
  if not self._from then
    self._from = self:_get_args_token(...)
  else
    self._from = self._from .. ", " .. self:_get_args_token(...)
  end
  return self
end

function ModelSql.get_table(self)
  return (self._as == nil and self.table_name) or (self.table_name .. ' AS ' .. self._as)
end

function ModelSql.join(self, join_args, ...)
  if type(join_args) == 'table' then
    self:_register_join_model(join_args, "INNER")
  else
    self.Sql.join(self, join_args, ...)
  end
  return self
end

function ModelSql.inner_join(self, join_args, ...)
  if type(join_args) == 'table' then
    self:_register_join_model(join_args, "INNER")
  else
    self.Sql.join(self, join_args, ...)
  end
  return self
end

function ModelSql.left_join(self, join_args, ...)
  if type(join_args) == 'table' then
    self:_register_join_model(join_args, "LEFT")
  else
    self.Sql.left_join(self, join_args, ...)
  end
  return self
end

function ModelSql.right_join(self, join_args, ...)
  if type(join_args) == 'table' then
    self:_register_join_model(join_args, "RIGHT")
  else
    self.Sql.right_join(self, join_args, ...)
  end
  return self
end

function ModelSql.full_join(self, join_args, ...)
  if type(join_args) == 'table' then
    self:_register_join_model(join_args, "FULL")
  else
    self.Sql.full_join(self, join_args, ...)
  end
  return self
end

function ModelSql.limit(self, n)
  self._limit = n
  return self
end

function ModelSql.offset(self, n)
  self._offset = n
  return self
end

function ModelSql.where(self, first, ...)
  local where_token = self:_get_condition_token(first, ...)
  return self:_handle_where_token(where_token, "(%s) AND (%s)")
end

function ModelSql.where_or(self, first, ...)
  local where_token = self:_get_condition_token_or(first, ...)
  return self:_handle_where_token(where_token, "(%s) AND (%s)")
end

function ModelSql.or_where_or(self, first, ...)
  local where_token = self:_get_condition_token_or(first, ...)
  return self:_handle_where_token(where_token, "%s OR %s")
end

function ModelSql.where_not(self, first, ...)
  local where_token = self:_get_condition_token_not(first, ...)
  return self:_handle_where_token(where_token, "(%s) AND (%s)")
end

function ModelSql.or_where(self, first, ...)
  local where_token = self:_get_condition_token(first, ...)
  return self:_handle_where_token(where_token, "%s OR %s")
end

function ModelSql.or_where_not(self, first, ...)
  local where_token = self:_get_condition_token_not(first, ...)
  return self:_handle_where_token(where_token, "%s OR %s")
end

function ModelSql.where_exists(self, builder)
  if self._where then
    self._where = string_format("(%s) AND EXISTS (%s)", self._where, builder)
  else
    self._where = string_format("EXISTS (%s)", builder)
  end
  return self
end

function ModelSql.where_not_exists(self, builder)
  if self._where then
    self._where = string_format("(%s) AND NOT EXISTS (%s)", self._where, builder)
  else
    self._where = string_format("NOT EXISTS (%s)", builder)
  end
  return self
end

function ModelSql.where_in(self, cols, range)
  if type(cols) == "string" then
    return self.Sql.where_in(self, self:_get_column(cols), range)
  else
    local res = {}
    for i = 1, #cols do
      res[i] = self:_get_column(cols[i])
    end
    return self.Sql.where_in(self, res, range)
  end
end

function ModelSql.where_not_in(self, cols, range)
  if type(cols) == "string" then
    cols = self:_get_column(cols)
  else
    for i = 1, #cols do
      cols[i] = self:_get_column(cols[i])
    end
  end
  return self.Sql.where_not_in(self, cols, range)
end

function ModelSql.where_null(self, col)
  return self.Sql.where_null(self, self:_get_column(col))
end

function ModelSql.where_not_null(self, col)
  return self.Sql.where_not_null(self, self:_get_column(col))
end

function ModelSql.where_between(self, col, low, high)
  return self.Sql.where_between(self, self:_get_column(col), low, high)
end

function ModelSql.where_not_between(self, col, low, high)
  return self.Sql.where_not_between(self, self:_get_column(col), low, high)
end

function ModelSql.or_where_in(self, cols, range)
  if type(cols) == "string" then
    cols = self:_get_column(cols)
  else
    for i = 1, #cols do
      cols[i] = self:_get_column(cols[i])
    end
  end
  return self.Sql.or_where_in(self, cols, range)
end

function ModelSql.or_where_not_in(self, cols, range)
  if type(cols) == "string" then
    cols = self:_get_column(cols)
  else
    for i = 1, #cols do
      cols[i] = self:_get_column(cols[i])
    end
  end
  return self.Sql.or_where_not_in(self, cols, range)
end

function ModelSql.or_where_null(self, col)
  return self.Sql.or_where_null(self, self:_get_column(col))
end

function ModelSql.or_where_not_null(self, col)
  return self.Sql.or_where_not_null(self, self:_get_column(col))
end

function ModelSql.or_where_between(self, col, low, high)
  return self.Sql.or_where_between(self, self:_get_column(col), low, high)
end

function ModelSql.or_where_not_between(self, col, low, high)
  return self.Sql.or_where_not_between(self, self:_get_column(col), low, high)
end

function ModelSql.where_raw(self, where_token)
  if where_token == "" then
    return self
  elseif self._where then
    self._where = string_format("(%s) AND (%s)", self._where, where_token)
  else
    self._where = where_token
  end
  return self
end

function ModelSql.or_where_exists(self, builder)
  if self._where then
    self._where = string_format("%s OR EXISTS (%s)", self._where, builder)
  else
    self._where = string_format("EXISTS (%s)", builder)
  end
  return self
end

function ModelSql.or_where_not_exists(self, builder)
  if self._where then
    self._where = string_format("%s OR NOT EXISTS (%s)", self._where, builder)
  else
    self._where = string_format("NOT EXISTS (%s)", builder)
  end
  return self
end

function ModelSql.or_where_raw(self, where_token)
  if where_token == "" then
    return self
  elseif self._where then
    self._where = string_format("%s OR %s", self._where, where_token)
  else
    self._where = where_token
  end
  return self
end

function ModelSql.having(self, ...)
  if self._having then
    self._having = string_format("(%s) AND (%s)", self._having, self:_get_condition_token(...))
  else
    self._having = self:_get_condition_token(...)
  end
  return self
end

function ModelSql.having_not(self, ...)
  if self._having then
    self._having = string_format("(%s) AND (%s)", self._having, self:_get_condition_token_not(...))
  else
    self._having = self:_get_condition_token_not(...)
  end
  return self
end

function ModelSql.having_exists(self, builder)
  if self._having then
    self._having = string_format("(%s) AND EXISTS (%s)", self._having, builder)
  else
    self._having = string_format("EXISTS (%s)", builder)
  end
  return self
end

function ModelSql.having_not_exists(self, builder)
  if self._having then
    self._having = string_format("(%s) AND NOT EXISTS (%s)", self._having, builder)
  else
    self._having = string_format("NOT EXISTS (%s)", builder)
  end
  return self
end

function ModelSql.having_in(self, cols, range)
  local in_token = self:_get_in_token(cols, range)
  if self._having then
    self._having = string_format("(%s) AND %s", self._having, in_token)
  else
    self._having = in_token
  end
  return self
end

function ModelSql.having_not_in(self, cols, range)
  local not_in_token = self:_get_in_token(cols, range, "NOT IN")
  if self._having then
    self._having = string_format("(%s) AND %s", self._having, not_in_token)
  else
    self._having = not_in_token
  end
  return self
end

function ModelSql.having_null(self, col)
  if self._having then
    self._having = string_format("(%s) AND %s IS NULL", self._having, col)
  else
    self._having = col .. " IS NULL"
  end
  return self
end

function ModelSql.having_not_null(self, col)
  if self._having then
    self._having = string_format("(%s) AND %s IS NOT NULL", self._having, col)
  else
    self._having = col .. " IS NOT NULL"
  end
  return self
end

function ModelSql.having_between(self, col, low, high)
  if self._having then
    self._having = string_format("(%s) AND (%s BETWEEN %s AND %s)", self._having, col, low, high)
  else
    self._having = string_format("%s BETWEEN %s AND %s", col, low, high)
  end
  return self
end

function ModelSql.having_not_between(self, col, low, high)
  if self._having then
    self._having = string_format("(%s) AND (%s NOT BETWEEN %s AND %s)", self._having, col, low, high)
  else
    self._having = string_format("%s NOT BETWEEN %s AND %s", col, low, high)
  end
  return self
end

function ModelSql.having_raw(self, token)
  if self._having then
    self._having = string_format("(%s) AND (%s)", self._having, token)
  else
    self._having = token
  end
  return self
end

function ModelSql.or_having(self, ...)
  if self._having then
    self._having = string_format("%s OR %s", self._having, self:_get_condition_token(...))
  else
    self._having = self:_get_condition_token(...)
  end
  return self
end

function ModelSql.or_having_not(self, ...)
  if self._having then
    self._having = string_format("%s OR %s", self._having, self:_get_condition_token_not(...))
  else
    self._having = self:_get_condition_token_not(...)
  end
  return self
end

function ModelSql.or_having_exists(self, builder)
  if self._having then
    self._having = string_format("%s OR EXISTS (%s)", self._having, builder)
  else
    self._having = string_format("EXISTS (%s)", builder)
  end
  return self
end

function ModelSql.or_having_not_exists(self, builder)
  if self._having then
    self._having = string_format("%s OR NOT EXISTS (%s)", self._having, builder)
  else
    self._having = string_format("NOT EXISTS (%s)", builder)
  end
  return self
end

function ModelSql.or_having_in(self, cols, range)
  local in_token = self:_get_in_token(cols, range)
  if self._having then
    self._having = string_format("%s OR %s", self._having, in_token)
  else
    self._having = in_token
  end
  return self
end

function ModelSql.or_having_not_in(self, cols, range)
  local not_in_token = self:_get_in_token(cols, range, "NOT IN")
  if self._having then
    self._having = string_format("%s OR %s", self._having, not_in_token)
  else
    self._having = not_in_token
  end
  return self
end

function ModelSql.or_having_null(self, col)
  if self._having then
    self._having = string_format("%s OR %s IS NULL", self._having, col)
  else
    self._having = col .. " IS NULL"
  end
  return self
end

function ModelSql.or_having_not_null(self, col)
  if self._having then
    self._having = string_format("%s OR %s IS NOT NULL", self._having, col)
  else
    self._having = col .. " IS NOT NULL"
  end
  return self
end

function ModelSql.or_having_between(self, col, low, high)
  if self._having then
    self._having = string_format("%s OR (%s BETWEEN %s AND %s)", self._having, col, low, high)
  else
    self._having = string_format("%s BETWEEN %s AND %s", col, low, high)
  end
  return self
end

function ModelSql.or_having_not_between(self, col, low, high)
  if self._having then
    self._having = string_format("%s OR (%s NOT BETWEEN %s AND %s)", self._having, col, low, high)
  else
    self._having = string_format("%s NOT BETWEEN %s AND %s", col, low, high)
  end
  return self
end

function ModelSql.or_having_raw(self, token)
  if self._having then
    self._having = string_format("%s OR %s", self._having, token)
  else
    self._having = token
  end
  return self
end

function ModelSql.filter(self, kwargs)
  local where_token = self:_get_condition_token_from_table(kwargs)
  return self:_handle_where_token(where_token, "(%s) AND (%s)"):exec()
end

function ModelSql.exists(self)
  local statement = string_format("SELECT EXISTS (%s)", self:select(""):limit(1):statement())
  local res, err = self.query(statement, true)
  if res == nil then
    return self:error(err)
  else
    return res[1][1]
  end
end

function ModelSql.commit(self, bool)
  self._commit = bool
  return self
end

function ModelSql.skip_validate(self, bool)
  if bool == nil then
    bool = true
  end
  self._skip_validate = bool
  return self
end

function ModelSql.flat(self, depth)
  return self:compact():execr():flat(depth)
end

function ModelSql.get(self, ...)
  ---
  local records
  if select('#', ...) > 0 then
    records = self:where(...):limit(2):exec()
  else
    records = self:limit(2):exec()
  end
  if #records == 1 then
    return records[1]
  else
    return self:error("not 1 record returned:" .. #records)
  end
end

function ModelSql.get_or_create(self, params, ...)
  local records = self:select(...):where(params):limit(2):exec()
  if #records == 1 then
    return records[1]
  elseif #records == 0 then
    local pk = self.primary_key
    local res = self:new {}:insert(params):returning(pk):execr()
    params[pk] = res[1][pk]
    return self:new(params), true
  else
    error("expect 1 row returned, but now get " .. #records)
  end
end

function ModelSql.as_set(self)
  return self:compact():execr():flat():as_set()
end

function ModelSql.count(self, ...)
  local res, err = self:select("count(*)"):where(...):compact():exec()
  if res == nil then
    return nil, err
  else
    return res[1][1]
  end
end

function ModelSql.execr(self)
  return self:raw():exec()
end

---comment
---@param self ModelSql
---@return row[]
function ModelSql.exec(self)
  local statement = self:statement()
  local records, err = self.query(statement, self._compact)
  if records == nil then
    error(err)
  end
  setmetatable(records, array)
  if self._raw or self._compact then
    return records
  elseif self._select or (not self._update and not self._insert and not self._delete) then
    if not self._load_fk then
      for i, record in ipairs(records) do
        records[i] = self:load(record)
      end
    else
      local fields = self.fields
      local field_names = self.field_names
      for i, record in ipairs(records) do
        for _, name in ipairs(field_names) do
          local field = fields[name]
          local value = record[name]
          if value ~= nil then
            local fk_model = self._load_fk[name]
            if not fk_model then
              if not field.load then
                record[name] = value
              else
                record[name], err = field:load(value)
                if err then
                  error(err)
                end
              end
            else
              -- `_load_fk` means reading attributes of a foreignkey,
              -- so the on-demand reading mode of `foreignkey_db_to_lua_validator` is not proper here
              record[name] = fk_model:load(get_foreign_object(record, name .. "__"))
            end
          end
        end
        records[i] = self:new(record)
      end
    end
    return records
  else
    return records
  end
end

function ModelSql.compact(self)
  self._compact = true
  return self
end

function ModelSql.raw(self)
  self._raw = true
  return self
end

function ModelSql.load_fk(self, fk_name, first, ...)
  local fk = self.foreign_keys[fk_name]
  if fk == nil then
    return self:error(fk_name .. " is not a valid forein key name for " .. self.table_name)
  end
  local fk_model = fk.reference
  local join_key = fk_name .. '__' .. fk_model.table_name
  local join_obj = self:_register_join_model {
    join_key = join_key,
    column = fk_name,
    fk_model = fk_model,
    fk_column = fk.reference_column
  }
  if not self._load_fk then
    self._load_fk = {}
  end
  self._load_fk[fk_name] = fk_model
  if not first then
    return self
  end
  local right_alias = join_obj.fk_alias
  local fks
  if type(first) == 'table' then
    local res = {}
    for _, fkn in ipairs(first) do
      assert(fk_model.fields[fkn], "invalid field name for fk model: " .. fkn)
      res[#res + 1] = string_format("%s.%s AS %s__%s", right_alias, fkn, fk_name, fkn)
    end
    fks = table_concat(res, ', ')
  elseif first == '*' then
    local res = {}
    for i, fkn in ipairs(fk_model.field_names) do
      res[#res + 1] = string_format("%s.%s AS %s__%s", right_alias, fkn, fk_name, fkn)
    end
    fks = table_concat(res, ', ')
  elseif type(first) == 'string' then
    assert(fk_model.fields[first], "invalid field name for fk model: " .. first)
    fks = string_format("%s.%s AS %s__%s", right_alias, first, fk_name, first)
    for i = 1, select("#", ...) do
      local fkn = select(i, ...)
      assert(fk_model.fields[fkn], "invalid field name for fk model: " .. fkn)
      fks = string_format("%s, %s.%s AS %s__%s", fks, right_alias, fkn, fk_name, fkn)
    end
  else
    error(string_format("invalid argument type %s for load_fk", type(first)))
  end
  return self.Sql.select(self, fks)
end

return ModelSql
