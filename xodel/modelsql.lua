local array = require "mvc.array"
local Sql = require "mvc.sql"
local utils = require "mvc.utils"
local class = require "mvc.utils".class
local nkeys = require "table.nkeys"
local setmetatable = setmetatable
local ipairs = ipairs
local tostring = tostring
local error = error
local type = type
local pairs = pairs
local select = select
local string_format = string.format
local table_concat = table.concat
local assert = assert
local table_insert = table.insert
local table_new, clone
if ngx then
  table_new = table.new
  clone = require("table.clone")
else
  function table_new(a, b)
    return {}
  end

  function clone(t)
    local res = {}
    for key, value in pairs(t) do
      res[key] = value
    end
    return res
  end
end

-- local version = '1.3'
-- postgresql.org/docs/current/sql-keywords-appendix.html

local FOREIGN_KEY = 2
local NON_FOREIGN_KEY = 3
local END = 4
local COMPARE_OPERATORS = { lt = "<", lte = "<=", gt = ">", gte = ">=", ne = "<>", eq = "=" }

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

local NULL = Sql.NULL
local as_literal = Sql.as_literal
local as_token = Sql.as_token
-- other methods
local bulk_methods = {
  upsert = { validate_method = "validate_create_rows", sql_method = Sql.upsert },
  merge = { validate_method = "validate_create_rows", sql_method = Sql.merge },
  updates = { validate_method = "validate_update_rows", sql_method = Sql.updates }
}
local function bulk_dispatcher(name, self, rows, key, columns)
  if not self:is_instance(rows) then
    if not self._skip_validate then
      rows, key, columns = self.model[bulk_methods[name].validate_method](self.model, rows, key, columns)
      if rows == nil then
        return self:error(key)
      end
    end
    rows, columns = self.model:prepare_db_rows(rows, columns, name == 'updates')
  end
  if rows == nil then
    return self:error(columns)
  end
  local bulk_sql = bulk_methods[name].sql_method(self, rows, key, columns)
  if self._commit == nil or self._commit then
    if not self._returning then
      return bulk_sql:returning(key):compact():execr()
    else
      return bulk_sql:compact():execr()
    end
  else
    return bulk_sql
  end
end

local function join(self, join_args, ...)
  if type(join_args) == 'table' then
    self:_register_join_model(join_args, "INNER")
  else
    self.Sql.join(self, join_args, ...)
  end
  return self
end

local ModelSql = {}

function ModelSql.__tostring(self)
  return self:statement()
end

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

function ModelSql._get_condition_token(self, first, second, third)
  if second == nil then
    return self.Sql._get_condition_token(self, first)
  elseif third == nil then
    return string_format("%s = %s", self:_get_column(first), as_literal(second))
  else
    return string_format("%s %s %s", self:_get_column(first), second, as_literal(third))
  end
end

function ModelSql._get_select_token(self, first, second, ...)
  if first == nil then
    return self:error(second or "augument is required for _get_select_token")
  elseif second == nil then
    if type(first) == "table" then
      local tokens = {}
      for i = 1, #first do
        tokens[i] = self:_get_column(first[i])
      end
      return as_token(tokens)
    elseif type(first) == "string" then
      return self:_get_column(first)
    else
      return as_token(first)
    end
  else
    first = self:_get_column(first)
    second = self:_get_column(second)
    local s = as_token(first) .. ", " .. as_token(second)
    for i = 1, select("#", ...) do
      local name = select(i, ...)
      s = s .. ", " .. as_token(self:_get_column(name))
    end
    return s
  end
end

function ModelSql._rows_to_array(self, rows, columns)
  local c = #columns
  local n = #rows
  local res = table_new(n, 0)
  local fields = self.model.fields
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
      return self:error("invalid field name for _get_cte_values_literal: " .. col)
    end
  end
  rows[1] = '(' .. as_token(first_row) .. ')'
  for i = 2, #rows, 1 do
    rows[i] = as_literal(rows[i])
  end
  return rows, columns
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
  local model = join_args.model or self.model
  local fk_model = join_args.fk_model
  local column = join_args.column
  local fk_column = join_args.fk_column
  local join_key
  if join_args.join_key == nil then
    if self.model == model then
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

function ModelSql._find_field_model(self, col)
  local field = self.model.fields[col]
  if field then
    return field, self.model, self._as or self.model.table_name
  end
  if not self._join_keys then
    return
  end
  for _, join_obj in pairs(self._join_keys) do
    local fk_field = join_obj.fk_model.fields[col]
    if join_obj.model == self.model and fk_field then
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
  if not field then
    return self:error(string_format("%s is not a valid field name for %s", e, self.model.table_name))
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
  if self.model.fields[key] then
    return self._as and (self._as .. '.' .. key) or self.model.name_cache[key]
  end
  if not self._join_keys then
    return key
  end
  for _, join_obj in pairs(self._join_keys) do
    if join_obj.model == self.model and join_obj.fk_model.fields[key] then
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
    return self:error("invalid sql operator: " .. tostring(op))
  end
end

function ModelSql._get_join_number(self)
  if self._join_keys then
    return nkeys(self._join_keys) + 1
  else
    return 1
  end
end

function ModelSql.with_values(self, name, rows)
  local columns = self:_get_keys(rows[1])
  rows, columns = self:_get_cte_values_literal(rows, columns, true)
  local cte_name = string_format("%s(%s)", name, table_concat(columns, ", "))
  local cte_values = string_format("(VALUES %s)", as_token(rows))
  return self:with(cte_name, cte_values)
end

function ModelSql.insert(self, rows, columns)
  if not self:is_instance(rows) then
    if not self._skip_validate then
      rows, columns = self.model:validate_create_data(rows, columns)
      if rows == nil then
        return self:error(columns)
      end
    end
    rows, columns = self.model:prepare_db_rows(rows, columns)
    if rows == nil then
      return self:error(columns)
    end
  end
  return self.Sql.insert(self, rows, columns)
end

function ModelSql.update(self, row, columns)
  local err
  if not self:is_instance(row) then
    if not self._skip_validate then
      row, columns = self.model:validate_update(row, columns)
      if row == nil then
        return self:error(err)
      end
    end
    row, columns = self.model:prepare_db_rows(row, columns, true)
    if row == nil then
      return self:error(columns)
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

local join = join
local inner_join = join
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

function ModelSql.upsert(self, rows, key, columns)
  return bulk_dispatcher('upsert', self, rows, key, columns)
end

function ModelSql.merge(self, rows, key, columns)
  return bulk_dispatcher('merge', self, rows, key, columns)
end

function ModelSql.updates(self, rows, key, columns)
  return bulk_dispatcher('updates', self, rows, key, columns)
end

function ModelSql.filter(self, kwargs)
  local where_token = self:_get_condition_token_from_table(kwargs)
  return self:_handle_where_token(where_token, "(%s) AND (%s)"):exec()
end

function ModelSql.exists(self)
  local statement = string_format("SELECT EXISTS (%s)", self:select(""):limit(1):statement())
  local res, err = self.model.query(statement, true)
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
    local pk = self.model.primary_key
    local res = self.model.sql:new {}:insert(params):returning(pk):execr()
    params[pk] = res[1][pk]
    return self.model:new(params), true
  else
    return self:error("get_or_create: not 1 record returned")
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

function ModelSql.exec(self)
  local statement = self:statement()
  local records, err = self.model.query(statement, self._compact)
  if records == nil then
    return self:error(err)
  end
  setmetatable(records, array)
  if self._raw or self._compact then
    return records
  elseif self._select or (not self._update and not self._insert and not self._delete) then
    if not self._load_fk then
      for i, record in ipairs(records) do
        records[i] = self.model:load(record)
      end
    else
      local fields = self.model.fields
      local field_names = self.model.field_names
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
                  return self:error(err)
                end
              end
            else
              -- `_load_fk` means reading attributes of a foreignkey,
              -- so the on-demand reading mode of `foreignkey_db_to_lua_validator` is not proper here
              record[name] = fk_model:load(get_foreign_object(record, name .. "__"))
            end
          end
        end
        records[i] = self.model:new(record)
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
  local fk = self.model.foreign_keys[fk_name]
  if fk == nil then
    return self:error(fk_name .. " is not a valid forein key name for " .. self.model.table_name)
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
    return self:error(string_format("invalid argument type %s for load_fk", type(first)))
  end
  return self.Sql.select(self, fks)
end

function ModelSql.OR(self, kwargs)
  return self:_get_condition_token_from_table(kwargs, "OR")
end

function ModelSql.AND(self, kwargs)
  return self:_get_condition_token_from_table(kwargs)
end

return ModelSql
