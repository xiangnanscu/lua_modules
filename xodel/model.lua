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
local non_merge_names = { sql = true, fields = true, field_names = true, extends = true, mixins = true, __index = true, admin = true }
local function model_ready_for_sql(model)
  return model.table_name and model.field_names and model.fields
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
  local fcls = FieldClasses[options.type]
  if not fcls then
    error("invalid field type:" .. tostring(options.type))
  end
  return fcls(options)
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
  local instance_meta = class {
    __call = function(self, data)
      for k, v in pairs(data) do
        self[k] = v
      end
      return self
    end,
    delete = function(self, key)
      key = key or model.primary_key
      return cls.delete(model, { [key] = self[key] }):exec()
    end,

    save = function(self, names, key)
      return cls.save(model, self, names, key)
    end,

    save_create = function(self, names, key)
      return cls.save_create(model, self, names, key)
    end,

    save_update = function(self, names, key)
      return cls.save_update(model, self, names, key)
    end,

    save_from = function(self, key)
      return cls.save_from(model, self, key)
    end,

    create_from = function(self, key)
      return cls.create_from(model, self, key)
    end,

    update_from = function(self, key)
      return cls.update_from(model, self, key)
    end,

    validate = function(self, names, key)
      return cls.validate(model, self, names, key)
    end,

    validate_update = function(self, names)
      return cls.validate_update(model, self, names)
    end,

    validate_create = function(self, names)
      return cls.validate_create(model, self, names)
    end,
  }
  return setmetatable(instance_meta, model)
end

local ModelClass
do
  ModelClass = class({
    __call = model_new,
    base_model = base_model,
    make_field_from_json = make_field_from_json,
    make_class = function(cls, options)
      -- foreign_keys, label_to_name, name_to_label, primary_key, disable_auto_primary_key
      -- abstract, sql, query, table_name, field_names, fields, extends, mixins
      return cls:make_model_class(cls:normalize(options))
    end,

    normalize = function(cls, options)
      assert(type(options) == "table", "model must be a table")
      -- **或更详细的empty判断逻辑(即检测是否定义了任一值: extends, mixins, able_name, field_names, fields等)
      assert(next(options), "model must not be empty")
      -- **是否考虑确保parent一定是一个ModelClass
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
    end,

    make_model_class = function(cls, model)
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
        model.fields[pk_name] = FieldClasses.integer { name = pk_name, primary_key = true, serial = true }
        table.insert(model.field_names, 1, pk_name)
      end
      -- sql
      if not_abstract and not model.sql and model_ready_for_sql(model) then
        model.sql = modelsql:make_class { model = model, table_name = model.table_name }
      end
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
        if field.db_type == FieldClasses.basefield.NOT_DEFIEND then
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
    end,

    mix_with_base = function(cls, ...)
      return cls:mix(base_model, ...)
    end,

    mix = function(cls, ...)
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
    end,

    merge_model_fn = function(a, b)
      return ModelClass:merge_model(a, b)
    end,

    merge_models = function(cls, models)
      return array(models):reduce(cls.merge_model_fn)
    end,

    merge_model = function(cls, a, b)
      local A = a.__normalized__ and a or cls:normalize(a)
      local B = b.__normalized__ and b or cls:normalize(b)
      local C = {}
      local field_names = (A.field_names + B.field_names):uniq()
      local fields = {}
      for i, name in ipairs(field_names) do
        local a_field = A.fields[name]
        local b_field = B.fields[name]
        if a_field and b_field then
          fields[name] = ModelClass:merge_field(a_field, b_field)
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
    end,

    merge_field = function(cls, a, b)
      local aopts = a.__is_field_class__ and a:get_options() or clone(a)
      local bopts = b.__is_field_class__ and b:get_options() or clone(b)
      local options = utils.dict(aopts, bopts)
      if aopts.model and bopts.model then
        options.model = cls:merge_model(aopts.model, bopts.model)
      end
      return make_field_from_json(options)
    end,

    new = function(cls, attrs)
      return setmetatable(attrs or {}, cls.instance_meta)
    end,

    all = function(cls)
      local records = assert(cls.query("SELECT * FROM " .. cls.table_name))
      for i = 1, #records do
        records[i] = cls:load(records[i])
      end
      return setmetatable(records, jsobject)
    end,

    save = function(cls, input, names, key)
      key = key or cls.primary_key
      if rawget(input, key) ~= nil then
        return cls:save_update(input, names, key)
      else
        return cls:save_create(input, names, key)
      end
    end,

    save_create = function(cls, input, names, key)
      local data, err = cls:validate_create(input, names)
      if err then
        return nil, err
      else
        return cls:create_from(data, key)
      end
    end,

    save_update = function(cls, input, names, key)
      local data, err = cls:validate_update(input, names)
      if err then
        return nil, err
      else
        key = key or cls.primary_key
        data[key] = input[key] -- ensure key is in
        return cls:update_from(data, key)
      end
    end,

    save_from = function(cls, data, key)
      key = key or cls.primary_key
      if rawget(data, key) ~= nil then
        return cls:update_from(data, key)
      else
        return cls:create_from(data, key)
      end
    end,

    create_from = function(cls, data, key)
      key = key or cls.primary_key
      local prepared, err = cls:prepare_for_db(data)
      if prepared == nil then
        return nil, err
      end
      local created = sql.insert(cls.sql:new {}, prepared):returning(key):execr()
      data[key] = created[1][key]
      return cls:new(data)
    end,

    update_from = function(cls, data, key)
      key = key or cls.primary_key
      local prepared, err = cls:prepare_for_db(data, nil, true)
      if prepared == nil then
        return nil, err
      end
      local look_value = assert(data[key], "no key provided for update")
      local ok, res = pcall(function()
        return sql.update(cls.sql:new {}, prepared):where { [key] = look_value }:execr()
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
    end,

    prepare_for_db = function(cls, data, columns, is_update)
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
    end,
    skip_validate = function(cls, bool)
      if bool == nil then
        bool = true
      end
      return cls.sql:new():skip_validate(not not bool)
    end,

    validate = function(cls, input, names, key)
      if rawget(input, key or cls.primary_key) ~= nil then
        return cls:validate_update(input, names)
      else
        return cls:validate_create(input, names)
      end
    end,

    validate_create = function(cls, input, names)
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
    end,

    validate_update = function(cls, input, names)
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
    end,

    validate_create_data = function(cls, rows, columns)
      local err_obj, cleaned
      columns = columns or cls.sql:_get_keys(rows)
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
    end,

    validate_update_data = function(cls, rows, columns)
      local err_obj, cleaned
      columns = columns or cls.sql:_get_keys(rows)
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
    end,

    validate_create_rows = function(cls, rows, key, columns)
      rows, key = check_upsert_key(rows, key or cls.primary_key)
      if rows == nil then
        return nil, key
      end
      rows, columns = cls:validate_create_data(rows, columns)
      if rows == nil then
        return nil, columns
      end
      return rows, key, columns
    end,

    validate_update_rows = function(cls, rows, key, columns)
      rows, key = check_upsert_key(rows, key or cls.primary_key)
      if rows == nil then
        return nil, key
      end
      rows, columns = cls:validate_update_data(rows, columns)
      if rows == nil then
        return nil, columns
      end
      return rows, key, columns
    end,

    prepare_db_rows = function(cls, rows, columns, is_update)
      local err, cleaned
      columns = columns or cls.sql:_get_keys(rows)
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
    end,

    parse_error_message = function(cls, err)
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
    end,

    load = function(cls, data)
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
    end,

    -- proxy methods
    raw = function(cls)
      return cls.sql:new {}:raw()
    end,

    count = function(cls, ...)
      return cls.sql:new {}:count(...)
    end,

    commit = function(cls, bool)
      return cls.sql:new {}:commit(bool)
    end,

    with_values = function(cls, name, rows)
      return cls.sql:new {}:with_values(name, rows)
    end,

    upsert = function(cls, rows, key, columns)
      return cls.sql:new {}:upsert(rows, key, columns)
    end,

    merge = function(cls, rows, key, columns)
      return cls.sql:new {}:merge(rows, key, columns)
    end,

    updates = function(cls, rows, key, columns)
      return cls.sql:new {}:updates(rows, key, columns)
    end,

    gets = function(cls, keys, columns)
      return cls.sql:new {}:gets(keys, columns)
    end,

    merge_gets = function(cls, rows, keys)
      return cls.sql:new {}:merge_gets(rows, keys)
    end,

    filter = function(cls, kwargs)
      return cls.sql:new {}:filter(kwargs)
    end,

    get = function(cls, ...)
      return cls.sql:new {}:get(...)
    end,

    get_or_create = function(cls, ...)
      return cls.sql:new {}:get_or_create(...)
    end,

    insert = function(cls, ...)
      return cls.sql:new {}:insert(...)
    end,

    update = function(cls, ...)
      return cls.sql:new {}:update(...)
    end,

    load_fk = function(cls, ...)
      return cls.sql:new {}:load_fk(...)
    end,

    compact = function(cls)
      return cls.sql:new {}:compact()
    end,

    flat = function(cls, depth)
      return cls.sql:new {}:flat(depth)
    end,

    with = function(cls, ...)
      return cls.sql:new {}:with(...)
    end,

    as = function(cls, name)
      return cls.sql:new {}:as(name)
    end,

    delete = function(cls, ...)
      return cls.sql:new {}:delete(...)
    end,

    using = function(cls, ...)
      return cls.sql:new {}:using(...)
    end,

    select = function(cls, ...)
      return cls.sql:new {}:select(...)
    end,

    from = function(cls, ...)
      return cls.sql:new {}:from(...)
    end,

    returning = function(cls, ...)
      return cls.sql:new {}:returning(...)
    end,

    join = function(cls, ...)
      return cls.sql:new {}:join(...)
    end,

    left_join = function(cls, ...)
      return cls.sql:new {}:left_join(...)
    end,

    right_join = function(cls, ...)
      return cls.sql:new {}:right_join(...)
    end,

    full_join = function(cls, ...)
      return cls.sql:new {}:full_join(...)
    end,

    group = function(cls, ...)
      return cls.sql:new {}:group(...)
    end,

    group_by = function(cls, ...)
      return cls.sql:new {}:group_by(...)
    end,

    order = function(cls, ...)
      return cls.sql:new {}:order(...)
    end,

    order_by = function(cls, ...)
      return cls.sql:new {}:order_by(...)
    end,

    limit = function(cls, n)
      return cls.sql:new {}:limit(n)
    end,

    offset = function(cls, n)
      return cls.sql:new {}:offset(n)
    end,

    where = function(cls, ...)
      return cls.sql:new {}:where(...)
    end,

    where_or = function(cls, ...)
      return cls.sql:new {}:where_or(...)
    end,

    or_where_or = function(cls, ...)
      return cls.sql:new {}:or_where_or(...)
    end,

    where_not = function(cls, ...)
      return cls.sql:new {}:where_not(...)
    end,

    where_exists = function(cls, builder)
      return cls.sql:new {}:where_exists(builder)
    end,

    where_not_exists = function(cls, builder)
      return cls.sql:new {}:where_not_exists(builder)
    end,

    where_in = function(cls, cols, range)
      return cls.sql:new {}:where_in(cols, range)
    end,

    where_not_in = function(cls, cols, range)
      return cls.sql:new {}:where_not_in(cols, range)
    end,

    where_null = function(cls, col)
      return cls.sql:new {}:where_null(col)
    end,

    where_not_null = function(cls, col)
      return cls.sql:new {}:where_not_null(col)
    end,

    where_between = function(cls, col, low, high)
      return cls.sql:new {}:where_between(col, low, high)
    end,

    where_not_between = function(cls, col, low, high)
      return cls.sql:new {}:where_not_between(col, low, high)
    end,

    where_raw = function(cls, token)
      return cls.sql:new {}:where_raw(token)
    end,

    or_where = function(cls, ...)
      return cls.sql:new {}:or_where(...)
    end,

    or_where_not = function(cls, ...)
      return cls.sql:new {}:or_where_not(...)
    end,

    or_where_exists = function(cls, builder)
      return cls.sql:new {}:or_where_exists(builder)
    end,

    or_where_not_exists = function(cls, builder)
      return cls.sql:new {}:or_where_not_exists(builder)
    end,

    or_where_in = function(cls, cols, range)
      return cls.sql:new {}:or_where_in(cols, range)
    end,

    or_where_not_in = function(cls, cols, range)
      return cls.sql:new {}:or_where_not_in(cols, range)
    end,

    or_where_null = function(cls, col)
      return cls.sql:new {}:or_where_null(col)
    end,

    or_where_not_null = function(cls, col)
      return cls.sql:new {}:or_where_not_null(col)
    end,

    or_where_between = function(cls, col, low, high)
      return cls.sql:new {}:or_where_between(col, low, high)
    end,

    or_where_not_between = function(cls, col, low, high)
      return cls.sql:new {}:or_where_not_between(col, low, high)
    end,

    or_where_raw = function(cls, token)
      return cls.sql:new {}:or_where_raw(token)
    end,

    having = function(cls, ...)
      return cls.sql:new {}:having(...)
    end,

    having_not = function(cls, ...)
      return cls.sql:new {}:having_not(...)
    end,

    having_exists = function(cls, builder)
      return cls.sql:new {}:having_exists(builder)
    end,

    having_not_exists = function(cls, builder)
      return cls.sql:new {}:having_not_exists(builder)
    end,

    having_in = function(cls, cols, range)
      return cls.sql:new {}:having_in(cols, range)
    end,

    having_not_in = function(cls, cols, range)
      return cls.sql:new {}:having_not_in(cols, range)
    end,

    having_null = function(cls, col)
      return cls.sql:new {}:having_null(col)
    end,

    having_not_null = function(cls, col)
      return cls.sql:new {}:having_not_null(col)
    end,

    having_between = function(cls, col, low, high)
      return cls.sql:new {}:having_between(col, low, high)
    end,

    having_not_between = function(cls, col, low, high)
      return cls.sql:new {}:having_not_between(col, low, high)
    end,

    having_raw = function(cls, token)
      return cls.sql:new {}:having_raw(token)
    end,

    or_having = function(cls, ...)
      return cls.sql:new {}:or_having(...)
    end,

    or_having_not = function(cls, ...)
      return cls.sql:new {}:or_having_not(...)
    end,

    or_having_exists = function(cls, builder)
      return cls.sql:new {}:or_having_exists(builder)
    end,

    or_having_not_exists = function(cls, builder)
      return cls.sql:new {}:or_having_not_exists(builder)
    end,

    or_having_in = function(cls, cols, range)
      return cls.sql:new {}:or_having_in(cols, range)
    end,

    or_having_not_in = function(cls, cols, range)
      return cls.sql:new {}:or_having_not_in(cols, range)
    end,

    or_having_null = function(cls, col)
      return cls.sql:new {}:or_having_null(col)
    end,

    or_having_not_null = function(cls, col)
      return cls.sql:new {}:or_having_not_null(col)
    end,

    or_having_between = function(cls, col, low, high)
      return cls.sql:new {}:or_having_between(col, low, high)
    end,

    or_having_not_between = function(cls, col, low, high)
      return cls.sql:new {}:or_having_not_between(col, low, high)
    end,

    or_having_raw = function(cls, token)
      return cls.sql:new {}:or_having_raw(token)
    end,
  }, { __call = model_caller })
end
if select("#", ...) == 0 then
  local bank = ModelClass {
    table_name = "bank",
    fields = { amount = { label = "余额", type = "float" }, addr = { label = "地址" } }
  }
  local usr = ModelClass {
    table_name = "usr",
    fields = { bank_id = { label = "银行", reference = bank }, name = { label = "姓名" }, age = { label = "年龄" } }
  }
  local info = ModelClass {
    table_name = "info",
    fields = { code = { label = "身份证号", unique = true }, sex = { label = "性别" } }
  }
  local profile = ModelClass {
    table_name = "profile",
    fields = {
      usr_id = { label = "用户", reference = usr },
      info_id = { label = "信息", reference = info, reference_column = "code" },
      name = { label = "姓名" }
    }
  }
  print(profile:where_not { usr_id = "a" }:statement())
  print(profile:where { usr_id__bank_id__amount__gt = 100, usr_id__bank_id__addr__contains = "wall" }:statement())
  print(profile:where("id", 1):or_where({ id = 2 }):select("id"):statement())
  print(profile:where { usr_id__name__contains = "a", usr_id__name = "b" }:statement())
  print(profile:where {
    usr_id__name__contains = "a",
    usr_id__bank_id__amount__gt = 100,
    usr_id__bank_id__addr__contains = "wall"
  }:statement())

  print(profile:where { usr_id__name__contains = "a", usr_id__bank_id__addr__contains = "wall" }:or_where_not {
    usr_id__bank_id__amount__gt = 100
  }:statement())
  print(profile:where_in("name", { "foo", "bar" }):statement())
  print(profile:where_in({ "id", "name" }, usr:select("id", "name")):statement())
  print(profile:where_exists(usr:where("id=1")):statement())
  print(profile:where("name", "in", { "foo", "bar" }):statement())
  print(profile:where_null("name"):or_where_not { name__null = false }:statement())
  print(profile:where_null("name"):or_where_not { name__in = { "foo", "bar" } }:statement())
  print(profile:where_null("name"):where_not { name__notin = { "foo", "bar" } }:statement())
  print(profile:load_fk("usr_id", "name", "age"):load_fk("info_id", "sex"):statement())
  print(profile:select { "id", "name" }:select("usr_id as u"):statement())
  print(profile:select { "id", "name" }:select("usr_id"):statement())
  print(profile:where { name = "a", id = 1, foo = 2 }:statement())
  print(profile:where("name", "a"):statement())
  print(profile:where("name", "like", "a"):statement())
  print(usr:where_in("name", { "foo", "bar" }):statement())
  print(usr:where_in("names", { "foo", "bar" }):statement())
  print(usr:where_null("name"):or_where_between("age", 1, 10):statement())
  print(usr:where_exists(profile:where("name", "bar")):statement())
  print(profile:where_or({
    usr_id__bank_id__amount__gt = 10,
    usr_id__bank_id__amount__lte = 20,
    info_id__code__startswith = "a"
  }):statement())
  local cb1 = function(sql)
    return sql:where { a = 1, b = "where" }
  end

  local cb2 = function(sql)
    return sql:where_or { a = 1, b = "where_or" }
  end
  local cb3 = function(sql)
    return sql:or_where { a = 1, b = "or_where" }
  end
  local cb4 = function(sql)
    return sql:or_where_not { a = 1, b = "or_where_not" }
  end
  local cb5 = function(sql)
    return sql:where_not { a = 1, b = "where_not" }
  end
  print(profile:where(cb1):where(cb2):where(cb3):where(cb4):where(cb5):statement())
  print(profile:select(true, false, true):where_not { name = "a", id = 1, foo = true }:statement())
  print(profile:insert({ name = '1' }):returning('name'):statement())
end
return ModelClass
