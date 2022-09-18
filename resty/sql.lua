-- https://www.postgresql.org/docs/current/sql-select.html
-- https://www.postgresql.org/docs/current/sql-insert.html
-- https://www.postgresql.org/docs/current/sql-update.html
-- https://www.postgresql.org/docs/current/sql-delete.html
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

---check if row a Sql instance
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
        error("empty table as a Sql value is not allowed")
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

local SqlMeta = {}
function SqlMeta.__call(cls, kwargs)
  if type(kwargs) == "string" then
    return setmetatable({ table_name = kwargs }, cls)
  else
    return setmetatable(kwargs or {}, cls)
  end
end

---@class Sql
---@field table_name string
---@field _pcall? boolean
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
---@field _union?  Sql | string
---@field _union_all?  Sql | string
---@field _except?  Sql | string
---@field _except_all?  Sql | string
---@field _intersect?  Sql | string
---@field _intersect_all?  Sql | string
local Sql = setmetatable({
  __SQL_BUILDER__ = true,
  r = make_raw_token,
  DEFAULT = DEFAULT,
  NULL = NULL,
  as_token = as_token,
  as_literal = as_literal,
}, SqlMeta)
Sql.__index = Sql
function Sql.__tostring(self)
  return self:statement()
end

function Sql.__call(cls, ...)
  return cls.new(cls, ...)
end

---make a Sql instance
---@param cls Sql
---@param self? table
---@return Sql
function Sql.new(cls, self)
  return setmetatable(self or {}, cls)
end

function Sql.pcall(self)
  self._pcall = true
  return self
end

---@param self Sql
---@param err string|table
---@param level? number
---@return nil, string|table
---@return any
function Sql.error(self, err, level)
  if self._pcall then
    return nil, err
  else
    error(err, level)
  end
end

function Sql.make_class(cls, ...)
  local subcls = {}
  for i, t in ipairs({ cls, ... }) do
    for k, v in pairs(t) do
      subcls[k] = v
    end
  end
  subcls.__index = subcls
  subcls.__call = SqlMeta.__call
  return setmetatable(subcls, cls)
end

---@alias row {[string]:dbvalue}
---@alias rows row[]
---get keys array from a row or row array
---@param self Sql
---@param rows row|rows
---@return string[]
function Sql._get_keys(self, rows)
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
---@param self Sql
---@param rows row[]
---@param columns string[]
---@param fallback? any
---@return dbvalue[][]
function Sql._rows_to_array(self, rows, columns, fallback)
  local c = #columns
  local r = #rows
  local values = table_new(r, 0)
  for i = 1, r do
    values[i] = table_new(c, 0)
  end
  for i, col in ipairs(columns) do
    for j = 1, r do
      local v = rows[j][col]
      if v ~= nil then
        values[j][i] = v
      else
        values[j][i] = fallback
      end
    end
  end
  return values
end

---{name="kate", age=11} => "('kate', 11)", {"name", "age"}
---@param self Sql
---@param row row
---@param columns? string[]
---@return string, string[]
function Sql._get_insert_values_token(self, row, columns)
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

---@param self Sql
---@param rows row[]
---@param columns? string[]
---@param fallback? any
---@return string[], string[]
function Sql._get_bulk_insert_values_token(self, rows, columns, fallback)
  columns = columns or self:_get_keys(rows)
  rows = self:_rows_to_array(rows, columns, fallback)
  return map(rows, as_literal), columns
end

---f({'a','b','c'}, 'a', 'V') => 'b = V.b, c = V.c'
---f({'a','b','c'}, {'a','b'}, 'V') => 'c = V.c'
---use V as data table name so both Sql.upsert and Sql.merge can use it.
---@param self Sql
---@param columns string[]
---@param key string|string[]
---@param table_name string
---@return string
function Sql._get_update_token_with_prefix(self, columns, key, table_name)
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
---@param self Sql
---@param a dbvalue
---@param b? dbvalue
---@param ...? dbvalue[]
---@return string
function Sql._get_select_token(self, a, b, ...)
  if b == nil then
    return as_token(a)
  else
    local s = as_token(a) .. ", " .. as_token(b)
    for i = 1, select("#", ...) do
      s = s .. ", " .. as_token(select(i, ...))
    end
    return s
  end
end

---parse select literal token
---@param self Sql
---@param a dbvalue
---@param b? dbvalue
---@param ...? dbvalue[]
---@return string
function Sql._get_select_token_literal(self, a, b, ...)
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
---@param self Sql
---@param row row
---@param columns? string[]
---@return string
function Sql._get_update_token(self, row, columns)
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

---@param self Sql
---@param name string
---@param token? Sql|dbvalue
---@return string
function Sql._get_with_token(self, name, token)
  if token == nil then
    return name
  elseif self:is_instance(token) then
    return string_format("%s AS (%s)", name, token:statement())
  else
    return string_format("%s AS %s", name, token)
  end
end

---return a string like: (col, col2) VALUES ('v1', 'v2')
---@param self Sql
---@param row row
---@param columns? string[]
---@return string
function Sql._get_insert_token(self, row, columns)
  local values_token, insert_columns = self:_get_insert_values_token(row, columns)
  return string_format("(%s) VALUES %s", as_token(insert_columns), values_token)
end

---@param self Sql
---@param rows row[]
---@param columns? string[]
---@return string
function Sql._get_bulk_insert_token(self, rows, columns)
  rows, columns = self:_get_bulk_insert_values_token(rows, columns, DEFAULT)
  return string_format("(%s) VALUES %s", as_token(columns), as_token(rows))
end

---comment
---@param self Sql
---@param sub_query Sql
---@param columns? string[]
function Sql._set_select_subquery_insert_token(self, sub_query, columns)
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
---@param self Sql
---@param sub_query Sql
function Sql._set_cud_subquery_insert_token(self, sub_query)
  local cte_return = sub_query._cte_returning
  if cte_return then
    local cte_columns = cte_return.columns
    local insert_columns = merge_table(cte_columns, cte_return.literal_columns)
    -- local cud_select_query = Sql:new { table_name = "d" }:select(cte_columns):select_literal(cte_return.literals)
    local cud_select_query = Sql:new { table_name = "d" }:select(insert_columns)
    -- self:with(string_format("d(%s)", as_token(cte_columns)), sub_query)
    self:with(string_format("d(%s)", as_token(insert_columns)), sub_query)
    self._insert = string_format("(%s) %s", as_token(insert_columns), cud_select_query:statement())
  elseif sub_query._returning_args then
    local insert_columns = flat(sub_query._returning_args)
    local cud_select_query = Sql:new { table_name = "d" }:select(insert_columns)
    self:with(string_format("d(%s)", as_token(insert_columns)), sub_query)
    self._insert = string_format("(%s) %s", as_token(insert_columns), cud_select_query:statement())
  end
end

---comment
---@param self Sql
---@param row row
---@param key string|string[]
---@param columns? string[]
---@return string
function Sql._get_upsert_token(self, row, key, columns)
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
---@param self Sql
---@param rows row[]
---@param key string|string[]
---@param columns? string[]
---@return string
function Sql._get_bulk_upsert_token(self, rows, key, columns)
  rows, columns = self:_get_bulk_insert_values_token(rows, columns, DEFAULT)
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
---@param self Sql
---@param rows Sql
---@param key string|string[]
---@param columns string[]
---@return string
function Sql._get_upsert_query_token(self, rows, key, columns)
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
---@param self Sql
---@param a string
---@param b? string
---@param c? string
---@return string
function Sql._get_join_expr(self, a, b, c)
  if b == nil then
    return a
  elseif c == nil then
    return string_format("%s = %s", a, b)
  else
    return string_format("%s %s %s", a, b, c)
  end
end

---comment
---@param self Sql
---@param join_type string
---@param right_table string
---@param conditions string
---@param ... string[]
---@return string
function Sql._get_join_token(self, join_type, right_table, conditions, ...)
  if conditions ~= nil then
    return string_format("%s JOIN %s ON (%s)", join_type, right_table, self:_get_join_expr(conditions, ...))
  else
    return string_format("%s JOIN %s", join_type, right_table)
  end
end

---comment
---@param self Sql
---@param right_table string
---@param conditions string
---@param ... string[]
---@return string
function Sql._get_inner_join(self, right_table, conditions, ...)
  return self:_get_join_token("INNER", right_table, conditions, ...)
end

---@param self Sql
---@param right_table string
---@param conditions string
---@param ... string[]
---@return string
function Sql._get_left_join(self, right_table, conditions, ...)
  return self:_get_join_token("LEFT", right_table, conditions, ...)
end

---@param self Sql
---@param right_table string
---@param conditions string
---@param ... string[]
---@return string
function Sql._get_right_join(self, right_table, conditions, ...)
  return self:_get_join_token("RIGHT", right_table, conditions, ...)
end

---@param self Sql
---@param right_table string
---@param conditions string
---@param ... string[]
---@return string
function Sql._get_full_join(self, right_table, conditions, ...)
  return self:_get_join_token("FULL", right_table, conditions, ...)
end

---comment
---@param self Sql
---@param cols string|string[]
---@param range Sql|table|string
---@param operator? string
---@return string
function Sql._get_in_token(self, cols, range, operator)
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

---@param self Sql
---@param sub_select Sql
---@param columns? string[]
---@return string
function Sql._get_update_query_token(self, sub_select, columns)
  local columns_token = columns and self:_get_select_token(columns) or sub_select._select
  return string_format("(%s) = (%s)", columns_token, sub_select:statement())
end

---@param self Sql
---@param key string|string[]
---@param left_table string
---@param right_table string
---@return string
function Sql._get_join_conditions(self, key, left_table, right_table)
  if type(key) == "string" then
    return string_format("%s.%s = %s.%s", left_table, key, right_table, key)
  end
  local res = {}
  for _, k in ipairs(key) do
    res[#res + 1] = string_format("%s.%s = %s.%s", left_table, k, right_table, k)
  end
  return table_concat(res, " AND ")
end

---@param self Sql
---@param rows row[]
---@param columns string[]
---@return string[], string[]
function Sql._get_cte_values_literal(self, rows, columns)
  return self:_get_bulk_insert_values_token(rows, columns, NULL)
end

---@param self Sql
---@param where_token string
---@param tpl string
---@return Sql
function Sql._handle_where_token(self, where_token, tpl)
  if where_token == "" then
    return self
  elseif self._where == nil then
    self._where = where_token
  else
    self._where = string_format(tpl, self._where, where_token)
  end
  return self
end

---@param self Sql
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

---@param self Sql
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

---@param self Sql
---@param a table|string|function
---@param b? dbvalue
---@param c? dbvalue
---@return string
function Sql._get_condition_token_or(self, a, b, c)
  if type(a) == "table" then
    return self:_get_condition_token_from_table(a, "OR")
  else
    return self:_get_condition_token(a, b, c)
  end
end

---@param self Sql
---@param a table|string|function
---@param b? dbvalue
---@param c? dbvalue
---@return string
function Sql._get_condition_token_not(self, a, b, c)
  local token
  if type(a) == "table" then
    token = self:_get_condition_token_from_table(a, "OR")
  else
    token = self:_get_condition_token(a, b, c)
  end
  return token ~= "" and string_format("NOT (%s)", token) or ""
end

---@param self Sql
---@param other_sql Sql
---@param inner_attr set_type
---@return Sql
function Sql._handle_set_option(self, other_sql, inner_attr)
  if not self[inner_attr] then
    self[inner_attr] = other_sql:statement();
  else
    self[inner_attr] = string_format("(%s) %s (%s)", self[inner_attr], PG_SET_MAP[inner_attr], other_sql:statement());
  end
  if self ~= Sql then
    self.statement = self._statement_for_set
  else
    error("don't call _handle_set_option directly on Sql class")
  end
  return self;
end

---@param self Sql
---@return string
function Sql._statement_for_set(self)
  local statement = Sql.statement(self)
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

---@param self Sql
---@return string
function Sql.statement(self)
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

---@param self Sql
---@param name string
---@param token? dbvalue
---@return Sql
function Sql.with(self, name, token)
  local with_token = self:_get_with_token(name, token)
  if self._with then
    self._with = string_format("%s, %s", self._with, with_token)
  else
    self._with = with_token
  end
  return self
end

---comment
---@param self Sql
---@param other_sql Sql
---@return Sql
function Sql.union(self, other_sql)
  return self:_handle_set_option(other_sql, "_union");
end

function Sql.union_all(self, other_sql)
  return self:_handle_set_option(other_sql, "_union_all");
end

function Sql.except(self, other_sql)
  return self:_handle_set_option(other_sql, "_except");
end

function Sql.except_all(self, other_sql)
  return self:_handle_set_option(other_sql, "_except_all");
end

function Sql.intersect(self, other_sql)
  return self:_handle_set_option(other_sql, "_intersect");
end

function Sql.intersect_all(self, other_sql)
  return self:_handle_set_option(other_sql, "_intersect_all");
end

---comment
---@param self Sql
---@param table_alias string
---@return Sql
function Sql.as(self, table_alias)
  self._as = table_alias
  return self
end

---comment
---@param self Sql
---@param name string
---@param rows row[]
---@return Sql
function Sql.with_values(self, name, rows)
  local columns = self:_get_keys(rows[1])
  rows, columns = self:_get_cte_values_literal(rows, columns)
  local cte_name = string_format("%s(%s)", name, table_concat(columns, ", "))
  local cte_values = string_format("(VALUES %s)", as_token(rows))
  return self:with(cte_name, cte_values)
end

---comment
---@param self Sql
---@param rows row|row[]|Sql
---@param columns? string[]
---@return Sql
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
      error("can't pass empty table to sql.insert")
    end
  elseif type(rows) == 'string' then
    self._insert = rows
  else
    error("invalid value type to sql.insert:" .. type(rows))
  end
  return self
end

---comment
---@param self Sql
---@param row row|string|Sql
---@param columns? string[]
---@return Sql
function Sql.update(self, row, columns)
  if self:is_instance(row) then
    self._update = self:_get_update_query_token(row--[[@as Sql]], columns)
  elseif type(row) == "table" then
    self._update = self:_get_update_token(row, columns)
  else
    self._update = row --[[@as string]]
  end
  return self
end

---comment
---@param self Sql
---@param rows row[]
---@param key string|string[]
---@param columns? string[]
---@return Sql
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
---@param self Sql
---@param row any
---@return boolean
function Sql.is_instance(self, row)
  return is_sql_instance(row)
end

---comment
---@param self Sql
---@param rows row[]
---@param key string|string[]
---@param columns string[]
---@return Sql
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
---@param self Sql
---@param rows row[]|Sql
---@param key string|string[]
---@param columns string[]
---@return Sql
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
---@param self Sql
---@param keys row[]
---@param columns? string[]
---@return Sql
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

---comment
---@param self Sql
---@param rows row[]
---@param keys string|string[]
---@return Sql
function Sql.merge_gets(self, rows, keys)
  -- {{id=1}, {id=2}, {id=3}} => columns: {'id'}
  -- each row of keys must be the same struct, so get columns from first row
  local columns = self:_get_keys(rows[1])
  rows, columns = self:_get_cte_values_literal(rows, columns)
  local join_cond = self:_get_join_conditions(keys, "V", self._as or self.table_name)
  local cte_name = string_format("V(%s)", table_concat(columns, ", "))
  local cte_values = string_format("(VALUES %s)", as_token(rows))
  return Sql.select(self, "V.*"):with(cte_name, cte_values):right_join("V", join_cond)
end

---comment
---@param self Sql
---@return Sql
function Sql.copy(self)
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
---@param self Sql
---@param ...? unknown
---@return Sql
function Sql.delete(self, ...)
  self._delete = true
  if ... ~= nil then
    self:where(...)
  end
  return self
end

---comment
---@param self Sql
---@return Sql
function Sql.distinct(self)
  self._distinct = true
  return self
end

---comment
---@param self Sql
---@param ...? dbvalue[]
---@return Sql
function Sql.select(self, ...)
  local s = self:_get_select_token(...)
  if not self._select then
    self._select = s
  elseif s ~= nil and s ~= "" then
    self._select = self._select .. ", " .. s
  end
  return self
end

---comment
---@param self Sql
---@param ...? dbvalue[]
---@return Sql
function Sql.select_literal(self, ...)
  local s = self:_get_select_token_literal(...)
  if not self._select then
    self._select = s
  elseif s ~= nil and s ~= "" then
    self._select = self._select .. ", " .. s
  end
  return self
end

---@param self Sql
---@param ...? dbvalue[]
---@return Sql
function Sql.returning(self, ...)
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

---@param self Sql
---@param ...? dbvalue[]
---@return Sql
function Sql.returning_literal(self, ...)
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
---@param self Sql
---@param opts cte_returning_opts
---@return Sql
function Sql.cte_returning(self, opts)
  self._cte_returning = opts
  return self
end

function Sql.group(self, ...)
  if not self._group then
    self._group = self:_get_select_token(...)
  else
    self._group = self._group .. ", " .. self:_get_select_token(...)
  end
  return self
end

function Sql.group_by(self, ...) return self:group(...) end

function Sql.order(self, ...)
  if not self._order then
    self._order = self:_get_select_token(...)
  else
    self._order = self._order .. ", " .. self:_get_select_token(...)
  end
  return self
end

function Sql.order_by(self, ...) return self:order(...) end

function Sql._get_args_token(self, ...) return self:_get_select_token(...) end

function Sql.using(self, ...)
  self._delete = true
  self._using = self:_get_args_token(...)
  return self
end

function Sql.from(self, ...)
  if not self._from then
    self._from = self:_get_args_token(...)
  else
    self._from = self._from .. ", " .. self:_get_args_token(...)
  end
  return self
end

function Sql.get_table(self)
  return (self._as == nil and self.table_name) or (self.table_name .. ' AS ' .. self._as)
end

function Sql.join(self, ...)
  local join_token = self:_get_inner_join(...)
  self._from = string_format("%s %s", self._from or self:get_table(), join_token)
  return self
end

function Sql.inner_join(self, ...) return self:join(...) end

function Sql.left_join(self, ...)
  local join_token = self:_get_left_join(...)
  self._from = string_format("%s %s", self._from or self:get_table(), join_token)
  return self
end

function Sql.right_join(self, ...)
  local join_token = self:_get_right_join(...)
  self._from = string_format("%s %s", self._from or self:get_table(), join_token)
  return self
end

function Sql.full_join(self, ...)
  local join_token = self:_get_full_join(...)
  self._from = string_format("%s %s", self._from or self:get_table(), join_token)
  return self
end

function Sql.limit(self, n)
  self._limit = n
  return self
end

function Sql.offset(self, n)
  self._offset = n
  return self
end

function Sql.where(self, first, ...)
  local where_token = self:_get_condition_token(first, ...)
  return self:_handle_where_token(where_token, "(%s) AND (%s)")
end

function Sql.where_or(self, first, ...)
  local where_token = self:_get_condition_token_or(first, ...)
  return self:_handle_where_token(where_token, "(%s) AND (%s)")
end

function Sql.or_where_or(self, first, ...)
  local where_token = self:_get_condition_token_or(first, ...)
  return self:_handle_where_token(where_token, "%s OR %s")
end

function Sql.where_not(self, first, ...)
  local where_token = self:_get_condition_token_not(first, ...)
  return self:_handle_where_token(where_token, "(%s) AND (%s)")
end

function Sql.or_where(self, first, ...)
  local where_token = self:_get_condition_token(first, ...)
  return self:_handle_where_token(where_token, "%s OR %s")
end

function Sql.or_where_not(self, first, ...)
  local where_token = self:_get_condition_token_not(first, ...)
  return self:_handle_where_token(where_token, "%s OR %s")
end

function Sql.where_exists(self, builder)
  if self._where then
    self._where = string_format("(%s) AND EXISTS (%s)", self._where, builder)
  else
    self._where = string_format("EXISTS (%s)", builder)
  end
  return self
end

function Sql.where_not_exists(self, builder)
  if self._where then
    self._where = string_format("(%s) AND NOT EXISTS (%s)", self._where, builder)
  else
    self._where = string_format("NOT EXISTS (%s)", builder)
  end
  return self
end

function Sql.where_in(self, cols, range)
  local in_token = self:_get_in_token(cols, range)
  if self._where then
    self._where = string_format("(%s) AND %s", self._where, in_token)
  else
    self._where = in_token
  end
  return self
end

function Sql.where_not_in(self, cols, range)
  local not_in_token = self:_get_in_token(cols, range, "NOT IN")
  if self._where then
    self._where = string_format("(%s) AND %s", self._where, not_in_token)
  else
    self._where = not_in_token
  end
  return self
end

function Sql.where_null(self, col)
  if self._where then
    self._where = string_format("(%s) AND %s IS NULL", self._where, col)
  else
    self._where = col .. " IS NULL"
  end
  return self
end

function Sql.where_not_null(self, col)
  if self._where then
    self._where = string_format("(%s) AND %s IS NOT NULL", self._where, col)
  else
    self._where = col .. " IS NOT NULL"
  end
  return self
end

function Sql.where_between(self, col, low, high)
  if self._where then
    self._where = string_format("(%s) AND (%s BETWEEN %s AND %s)", self._where, col, low, high)
  else
    self._where = string_format("%s BETWEEN %s AND %s", col, low, high)
  end
  return self
end

function Sql.where_not_between(self, col, low, high)
  if self._where then
    self._where = string_format("(%s) AND (%s NOT BETWEEN %s AND %s)", self._where, col, low, high)
  else
    self._where = string_format("%s NOT BETWEEN %s AND %s", col, low, high)
  end
  return self
end

function Sql.where_raw(self, where_token)
  if where_token == "" then
    return self
  elseif self._where then
    self._where = string_format("(%s) AND (%s)", self._where, where_token)
  else
    self._where = where_token
  end
  return self
end

function Sql.or_where_exists(self, builder)
  if self._where then
    self._where = string_format("%s OR EXISTS (%s)", self._where, builder)
  else
    self._where = string_format("EXISTS (%s)", builder)
  end
  return self
end

function Sql.or_where_not_exists(self, builder)
  if self._where then
    self._where = string_format("%s OR NOT EXISTS (%s)", self._where, builder)
  else
    self._where = string_format("NOT EXISTS (%s)", builder)
  end
  return self
end

function Sql.or_where_in(self, cols, range)
  local in_token = self:_get_in_token(cols, range)
  if self._where then
    self._where = string_format("%s OR %s", self._where, in_token)
  else
    self._where = in_token
  end
  return self
end

function Sql.or_where_not_in(self, cols, range)
  local not_in_token = self:_get_in_token(cols, range, "NOT IN")
  if self._where then
    self._where = string_format("%s OR %s", self._where, not_in_token)
  else
    self._where = not_in_token
  end
  return self
end

function Sql.or_where_null(self, col)
  if self._where then
    self._where = string_format("%s OR %s IS NULL", self._where, col)
  else
    self._where = col .. " IS NULL"
  end
  return self
end

function Sql.or_where_not_null(self, col)
  if self._where then
    self._where = string_format("%s OR %s IS NOT NULL", self._where, col)
  else
    self._where = col .. " IS NOT NULL"
  end
  return self
end

function Sql.or_where_between(self, col, low, high)
  if self._where then
    self._where = string_format("%s OR (%s BETWEEN %s AND %s)", self._where, col, low, high)
  else
    self._where = string_format("%s BETWEEN %s AND %s", col, low, high)
  end
  return self
end

function Sql.or_where_not_between(self, col, low, high)
  if self._where then
    self._where = string_format("%s OR (%s NOT BETWEEN %s AND %s)", self._where, col, low, high)
  else
    self._where = string_format("%s NOT BETWEEN %s AND %s", col, low, high)
  end
  return self
end

function Sql.or_where_raw(self, where_token)
  if where_token == "" then
    return self
  elseif self._where then
    self._where = string_format("%s OR %s", self._where, where_token)
  else
    self._where = where_token
  end
  return self
end

function Sql.having(self, ...)
  if self._having then
    self._having = string_format("(%s) AND (%s)", self._having, self:_get_condition_token(...))
  else
    self._having = self:_get_condition_token(...)
  end
  return self
end

function Sql.having_not(self, ...)
  if self._having then
    self._having = string_format("(%s) AND (%s)", self._having, self:_get_condition_token_not(...))
  else
    self._having = self:_get_condition_token_not(...)
  end
  return self
end

function Sql.having_exists(self, builder)
  if self._having then
    self._having = string_format("(%s) AND EXISTS (%s)", self._having, builder)
  else
    self._having = string_format("EXISTS (%s)", builder)
  end
  return self
end

function Sql.having_not_exists(self, builder)
  if self._having then
    self._having = string_format("(%s) AND NOT EXISTS (%s)", self._having, builder)
  else
    self._having = string_format("NOT EXISTS (%s)", builder)
  end
  return self
end

function Sql.having_in(self, cols, range)
  local in_token = self:_get_in_token(cols, range)
  if self._having then
    self._having = string_format("(%s) AND %s", self._having, in_token)
  else
    self._having = in_token
  end
  return self
end

function Sql.having_not_in(self, cols, range)
  local not_in_token = self:_get_in_token(cols, range, "NOT IN")
  if self._having then
    self._having = string_format("(%s) AND %s", self._having, not_in_token)
  else
    self._having = not_in_token
  end
  return self
end

function Sql.having_null(self, col)
  if self._having then
    self._having = string_format("(%s) AND %s IS NULL", self._having, col)
  else
    self._having = col .. " IS NULL"
  end
  return self
end

function Sql.having_not_null(self, col)
  if self._having then
    self._having = string_format("(%s) AND %s IS NOT NULL", self._having, col)
  else
    self._having = col .. " IS NOT NULL"
  end
  return self
end

function Sql.having_between(self, col, low, high)
  if self._having then
    self._having = string_format("(%s) AND (%s BETWEEN %s AND %s)", self._having, col, low, high)
  else
    self._having = string_format("%s BETWEEN %s AND %s", col, low, high)
  end
  return self
end

function Sql.having_not_between(self, col, low, high)
  if self._having then
    self._having = string_format("(%s) AND (%s NOT BETWEEN %s AND %s)", self._having, col, low, high)
  else
    self._having = string_format("%s NOT BETWEEN %s AND %s", col, low, high)
  end
  return self
end

function Sql.having_raw(self, token)
  if self._having then
    self._having = string_format("(%s) AND (%s)", self._having, token)
  else
    self._having = token
  end
  return self
end

function Sql.or_having(self, ...)
  if self._having then
    self._having = string_format("%s OR %s", self._having, self:_get_condition_token(...))
  else
    self._having = self:_get_condition_token(...)
  end
  return self
end

function Sql.or_having_not(self, ...)
  if self._having then
    self._having = string_format("%s OR %s", self._having, self:_get_condition_token_not(...))
  else
    self._having = self:_get_condition_token_not(...)
  end
  return self
end

function Sql.or_having_exists(self, builder)
  if self._having then
    self._having = string_format("%s OR EXISTS (%s)", self._having, builder)
  else
    self._having = string_format("EXISTS (%s)", builder)
  end
  return self
end

function Sql.or_having_not_exists(self, builder)
  if self._having then
    self._having = string_format("%s OR NOT EXISTS (%s)", self._having, builder)
  else
    self._having = string_format("NOT EXISTS (%s)", builder)
  end
  return self
end

function Sql.or_having_in(self, cols, range)
  local in_token = self:_get_in_token(cols, range)
  if self._having then
    self._having = string_format("%s OR %s", self._having, in_token)
  else
    self._having = in_token
  end
  return self
end

function Sql.or_having_not_in(self, cols, range)
  local not_in_token = self:_get_in_token(cols, range, "NOT IN")
  if self._having then
    self._having = string_format("%s OR %s", self._having, not_in_token)
  else
    self._having = not_in_token
  end
  return self
end

function Sql.or_having_null(self, col)
  if self._having then
    self._having = string_format("%s OR %s IS NULL", self._having, col)
  else
    self._having = col .. " IS NULL"
  end
  return self
end

function Sql.or_having_not_null(self, col)
  if self._having then
    self._having = string_format("%s OR %s IS NOT NULL", self._having, col)
  else
    self._having = col .. " IS NOT NULL"
  end
  return self
end

function Sql.or_having_between(self, col, low, high)
  if self._having then
    self._having = string_format("%s OR (%s BETWEEN %s AND %s)", self._having, col, low, high)
  else
    self._having = string_format("%s BETWEEN %s AND %s", col, low, high)
  end
  return self
end

function Sql.or_having_not_between(self, col, low, high)
  if self._having then
    self._having = string_format("%s OR (%s NOT BETWEEN %s AND %s)", self._having, col, low, high)
  else
    self._having = string_format("%s NOT BETWEEN %s AND %s", col, low, high)
  end
  return self
end

function Sql.or_having_raw(self, token)
  if self._having then
    self._having = string_format("%s OR %s", self._having, token)
  else
    self._having = token
  end
  return self
end

return Sql
