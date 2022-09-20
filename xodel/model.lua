local sql = require "mvc.sql"
-- model.table_name|sql|query|path_table maybe defined at app
local utils = require "mvc.utils"
local modelsql = require "mvc.modelsql"
local FieldClasses = require "mvc.field"
local array = require "mvc.array"
local object = require "mvc.object"
local clone = require "table.clone"
local nkeys = require "table.nkeys"
local ngx_re = require "ngx.re"
local class = utils.class
local match = ngx.re.match
local split = ngx_re.split
local rawget = rawget
local setmetatable = setmetatable
local getmetatable = getmetatable
local ipairs = ipairs
local tostring = tostring
local error = error
local type = type
local pairs = pairs
local select = select
local string_format = string.format
local table_concat = table.concat
local table_insert = table.insert
local ngx_localtime = ngx.localtime
local jsobject = require "mvc.jsobject"
-- local version = '1.3'
-- postgresql.org/docs/current/sql-keywords-appendix.html
local PG_KEYWORDS =
"ALL,ANALYSE,ANALYZE,AND,ANY,ARRAY,AS,ASC,ASYMMETRIC,AUTHORIZATION,BINARY,BOTH,CASE,CAST,CHECK,COLLATE,COLLATION,COLUMN,CONCURRENTLY,CONSTRAINT,CREATE,CROSS,CURRENT_CATALOG,CURRENT_DATE,CURRENT_ROLE,CURRENT_SCHEMA,CURRENT_TIME,CURRENT_TIMESTAMP,CURRENT_USER,DEFAULT,DEFERRABLE,DESC,DISTINCT,DO,ELSE,END,EXCEPT,FALSE,FETCH,FOR,FOREIGN,FREEZE,FROM,FULL,GRANT,GROUP,HAVING,ILIKE,IN,INITIALLY,INNER,INTERSECT,INTO,IS,ISNULL,JOIN,LATERAL,LEADING,LEFT,LIKE,LIMIT,LOCALTIME,LOCALTIMESTAMP,NATURAL,NOT,NOTNULL,NULL,OFFSET,ON,ONLY,OR,ORDER,OUTER,OVERLAPS,PLACING,PRIMARY,REFERENCES,RETURNING,RIGHT,SELECT,SESSION_USER,SIMILAR,SOME,SYMMETRIC,TABLE,TABLESAMPLE,THEN,TO,TRAILING,TRUE,UNION,UNIQUE,USER,USING,VARIADIC,VERBOSE,WHEN,WHERE,WINDOW,WITH"
local IS_PG_KEYWORDS = utils.from_entries(utils.map(split(PG_KEYWORDS, ","), function(e)
  return { e, true }
end))
local DEFAULT_STRING_MAXLENGTH = 255
local non_merge_names = { sql = true, fields = true, field_names = true, extends = true, mixins = true, __index = true,
  admin = true }
local function model_ready_for_sql(model)
  return model.table_name and model.field_names and model.fields
end



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

local ModelSql = {}
-- do
--   ModelSql = class({
--     __call = model_new,
--     base_model = base_model,
--     make_field_from_json = make_field_from_json,


-- proxy methods
function ModelSql.raw(cls)
  return cls.sql:new {}:raw()
end

function ModelSql.count(cls, ...)
  return cls.sql:new {}:count(...)
end

function ModelSql.commit(cls, bool)
  return cls.sql:new {}:commit(bool)
end

function ModelSql.with_values(cls, name, rows)
  return cls.sql:new {}:with_values(name, rows)
end

function ModelSql.upsert(cls, rows, key, columns)
  return cls.sql:new {}:upsert(rows, key, columns)
end

function ModelSql.merge(cls, rows, key, columns)
  return cls.sql:new {}:merge(rows, key, columns)
end

function ModelSql.updates(cls, rows, key, columns)
  return cls.sql:new {}:updates(rows, key, columns)
end

function ModelSql.gets(cls, keys, columns)
  return cls.sql:new {}:gets(keys, columns)
end

function ModelSql.merge_gets(cls, rows, keys)
  return cls.sql:new {}:merge_gets(rows, keys)
end

function ModelSql.filter(cls, kwargs)
  return cls.sql:new {}:filter(kwargs)
end

function ModelSql.get(cls, ...)
  return cls.sql:new {}:get(...)
end

function ModelSql.get_or_create(cls, ...)
  return cls.sql:new {}:get_or_create(...)
end

function ModelSql.insert(cls, ...)
  return cls.sql:new {}:insert(...)
end

function ModelSql.update(cls, ...)
  return cls.sql:new {}:update(...)
end

function ModelSql.load_fk(cls, ...)
  return cls.sql:new {}:load_fk(...)
end

function ModelSql.compact(cls)
  return cls.sql:new {}:compact()
end

function ModelSql.flat(cls, depth)
  return cls.sql:new {}:flat(depth)
end

function ModelSql.with(cls, ...)
  return cls.sql:new {}:with(...)
end

function ModelSql.as(cls, name)
  return cls.sql:new {}:as(name)
end

function ModelSql.delete(cls, ...)
  return cls.sql:new {}:delete(...)
end

function ModelSql.using(cls, ...)
  return cls.sql:new {}:using(...)
end

function ModelSql.select(cls, ...)
  return cls.sql:new {}:select(...)
end

function ModelSql.from(cls, ...)
  return cls.sql:new {}:from(...)
end

function ModelSql.returning(cls, ...)
  return cls.sql:new {}:returning(...)
end

function ModelSql.join(cls, ...)
  return cls.sql:new {}:join(...)
end

function ModelSql.left_join(cls, ...)
  return cls.sql:new {}:left_join(...)
end

function ModelSql.right_join(cls, ...)
  return cls.sql:new {}:right_join(...)
end

function ModelSql.full_join(cls, ...)
  return cls.sql:new {}:full_join(...)
end

function ModelSql.group(cls, ...)
  return cls.sql:new {}:group(...)
end

function ModelSql.group_by(cls, ...)
  return cls.sql:new {}:group_by(...)
end

function ModelSql.order(cls, ...)
  return cls.sql:new {}:order(...)
end

function ModelSql.order_by(cls, ...)
  return cls.sql:new {}:order_by(...)
end

function ModelSql.limit(cls, n)
  return cls.sql:new {}:limit(n)
end

function ModelSql.offset(cls, n)
  return cls.sql:new {}:offset(n)
end

function ModelSql.where(cls, ...)
  return cls.sql:new {}:where(...)
end

function ModelSql.where_or(cls, ...)
  return cls.sql:new {}:where_or(...)
end

function ModelSql.or_where_or(cls, ...)
  return cls.sql:new {}:or_where_or(...)
end

function ModelSql.where_not(cls, ...)
  return cls.sql:new {}:where_not(...)
end

function ModelSql.where_exists(cls, builder)
  return cls.sql:new {}:where_exists(builder)
end

function ModelSql.where_not_exists(cls, builder)
  return cls.sql:new {}:where_not_exists(builder)
end

function ModelSql.where_in(cls, cols, range)
  return cls.sql:new {}:where_in(cols, range)
end

function ModelSql.where_not_in(cls, cols, range)
  return cls.sql:new {}:where_not_in(cols, range)
end

function ModelSql.where_null(cls, col)
  return cls.sql:new {}:where_null(col)
end

function ModelSql.where_not_null(cls, col)
  return cls.sql:new {}:where_not_null(col)
end

function ModelSql.where_between(cls, col, low, high)
  return cls.sql:new {}:where_between(col, low, high)
end

function ModelSql.where_not_between(cls, col, low, high)
  return cls.sql:new {}:where_not_between(col, low, high)
end

function ModelSql.where_raw(cls, token)
  return cls.sql:new {}:where_raw(token)
end

function ModelSql.or_where(cls, ...)
  return cls.sql:new {}:or_where(...)
end

function ModelSql.or_where_not(cls, ...)
  return cls.sql:new {}:or_where_not(...)
end

function ModelSql.or_where_exists(cls, builder)
  return cls.sql:new {}:or_where_exists(builder)
end

function ModelSql.or_where_not_exists(cls, builder)
  return cls.sql:new {}:or_where_not_exists(builder)
end

function ModelSql.or_where_in(cls, cols, range)
  return cls.sql:new {}:or_where_in(cols, range)
end

function ModelSql.or_where_not_in(cls, cols, range)
  return cls.sql:new {}:or_where_not_in(cols, range)
end

function ModelSql.or_where_null(cls, col)
  return cls.sql:new {}:or_where_null(col)
end

function ModelSql.or_where_not_null(cls, col)
  return cls.sql:new {}:or_where_not_null(col)
end

function ModelSql.or_where_between(cls, col, low, high)
  return cls.sql:new {}:or_where_between(col, low, high)
end

function ModelSql.or_where_not_between(cls, col, low, high)
  return cls.sql:new {}:or_where_not_between(col, low, high)
end

function ModelSql.or_where_raw(cls, token)
  return cls.sql:new {}:or_where_raw(token)
end

function ModelSql.having(cls, ...)
  return cls.sql:new {}:having(...)
end

function ModelSql.having_not(cls, ...)
  return cls.sql:new {}:having_not(...)
end

function ModelSql.having_exists(cls, builder)
  return cls.sql:new {}:having_exists(builder)
end

function ModelSql.having_not_exists(cls, builder)
  return cls.sql:new {}:having_not_exists(builder)
end

function ModelSql.having_in(cls, cols, range)
  return cls.sql:new {}:having_in(cols, range)
end

function ModelSql.having_not_in(cls, cols, range)
  return cls.sql:new {}:having_not_in(cols, range)
end

function ModelSql.having_null(cls, col)
  return cls.sql:new {}:having_null(col)
end

function ModelSql.having_not_null(cls, col)
  return cls.sql:new {}:having_not_null(col)
end

function ModelSql.having_between(cls, col, low, high)
  return cls.sql:new {}:having_between(col, low, high)
end

function ModelSql.having_not_between(cls, col, low, high)
  return cls.sql:new {}:having_not_between(col, low, high)
end

function ModelSql.having_raw(cls, token)
  return cls.sql:new {}:having_raw(token)
end

function ModelSql.or_having(cls, ...)
  return cls.sql:new {}:or_having(...)
end

function ModelSql.or_having_not(cls, ...)
  return cls.sql:new {}:or_having_not(...)
end

function ModelSql.or_having_exists(cls, builder)
  return cls.sql:new {}:or_having_exists(builder)
end

function ModelSql.or_having_not_exists(cls, builder)
  return cls.sql:new {}:or_having_not_exists(builder)
end

function ModelSql.or_having_in(cls, cols, range)
  return cls.sql:new {}:or_having_in(cols, range)
end

function ModelSql.or_having_not_in(cls, cols, range)
  return cls.sql:new {}:or_having_not_in(cols, range)
end

function ModelSql.or_having_null(cls, col)
  return cls.sql:new {}:or_having_null(col)
end

function ModelSql.or_having_not_null(cls, col)
  return cls.sql:new {}:or_having_not_null(col)
end

function ModelSql.or_having_between(cls, col, low, high)
  return cls.sql:new {}:or_having_between(col, low, high)
end

function ModelSql.or_having_not_between(cls, col, low, high)
  return cls.sql:new {}:or_having_not_between(col, low, high)
end

function ModelSql.or_having_raw(cls, token)
  return cls.sql:new {}:or_having_raw(token)
end

return ModelSql
