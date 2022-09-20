local sql = require "mvc.sql"
-- model.table_name|sql|query|path_table maybe defined at app
local utils = require "mvc.utils"
local modelsql = require "mvc.modelsql"
local FieldClasses = require "mvc.field"
local array = require "mvc.array"
local object = require "mvc.object"
local clone = require "table.clone"
local nkeys = require "table.nkeys"

local class = utils.class
local match = ngx.re.match

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





local ModelSql = {}
-- do
--   ModelSql = class({
--     __call = model_new,
--     base_model = base_model,
--     make_field_from_json = make_field_from_json,




return ModelSql
