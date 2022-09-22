local Validator = require "xodel.validator"
local utils = require "xodel.utils"
local lua_array = require "xodel.array"
local cjson_encode = require "cjson.safe".encode
local cjson_decode = require "cjson.safe".decode
local encode_base64 = ngx.encode_base64
local hmac_sha1 = ngx.hmac_sha1
local string_format = string.format
local table_concat = table.concat
local table_insert = table.insert
local ipairs = ipairs
local setmetatable = setmetatable
local type = type
local rawset = rawset
local ngx_localtime = ngx.localtime
local list = utils.list
local make_class = utils.make_class
local class = utils.class
local clone = require("table.clone")
-- local valid_id = utils.valid_id

local TABLE_MAX_ROWS = 1
local CHOICES_ERROR_DISPLAY_COUNT = 30
local ERROR_MESSAGES = { required = "此项必填", choices = "无效选项" }

-- local PRIMITIVES = {
--   string = true,
--   number = true,
--   boolean = true,
--   table = true,
-- }
local NULL = ngx.null

local NOT_DEFIEND = {}

local function clean_choice(c)
  local v
  if c.value ~= nil then
    v = c.value
  else
    v = c[1]
  end
  assert(v ~= nil, "you must provide a value for a choice")
  local l
  if c.label ~= nil then
    l = c.label
  elseif c[2] ~= nil then
    l = c[2]
  else
    l = v
  end
  return v, l, (c.hint or c[3])
end

local function get_choices(raw_choices)
  local choices = lua_array {}
  for i, c in ipairs(raw_choices) do
    if type(c) == "string" or type(c) == "number" then
      c = { value = c, label = c }
    elseif type(c) == "table" then
      local value, label, hint = clean_choice(c)
      c = { value = value, label = label, hint = hint }
    else
      error("invalid choice type:" .. type(c))
    end
    choices[#choices + 1] = c
  end
  return choices
end

local function serialize_choice(choice)
  return tostring(choice.value)
end

local function get_choices_error_message(choices)
  local valid_choices = table_concat(utils.map(choices, serialize_choice), "，")
  return string_format("限下列选项：%s", valid_choices)
end

local function get_choices_validator(choices, message)
  if #choices <= CHOICES_ERROR_DISPLAY_COUNT then
    message = string_format("%s，%s", message, get_choices_error_message(choices))
  end
  local is_choice = {}
  for _, c in ipairs(choices) do
    is_choice[c.value] = true
  end
  local function choices_validator(value)
    if not is_choice[value] then
      return nil, message
    else
      return value
    end
  end

  return choices_validator
end

local database_option_names = { 'primary_key', 'null', 'unique', 'index', 'db_type' }
local base_option_names = utils.list(
  { 'required', 'label', 'choices', 'strict', 'error_messages', 'default', 'hint', 'tag', 'choices_module_name',
    'columns', 'verify_url', 'post_names', 'code_lifetime' },
  database_option_names)
local basefield = class {
  __is_field_class__ = true,
  NOT_DEFIEND = NOT_DEFIEND,
  required = false,
  new = function(cls, options)
    local self = setmetatable({}, cls)
    self:constructor(clone(options))
    self.final_validators = self:get_validators(clone(options.validators or {}))
    return self
  end,
  constructor = function(self, options)
    self.name = options.name or options[1]
    for _, name in ipairs(self:get_option_names()) do
      if options[name] ~= nil then
        self[name] = options[name]
      end
    end
    if self.db_type == nil then
      self.db_type = self.type
    end
    if self.label == nil then
      self.label = self.name
    end
    if self.null == nil then
      if not self.required and self.type ~= 'string' then
        self.null = true
      else
        self.null = false
      end
    end
    if self.choices then
      if self.strict == nil then
        self.strict = true
      end
      self.choices = get_choices(self.choices)
    end
    self.error_messages = utils.dict(ERROR_MESSAGES, self.error_messages)
    return self
  end,
  get_option_names = function(self)
    return utils.list(base_option_names, self.option_names)
  end,
  get_options = function(self)
    local options = {
      name = self.name,
      type = self.type,
      validators = self.validators,
    }
    for _, name in ipairs(self:get_option_names()) do
      options[name] = self[name]
    end
    return options
  end,
  get_validators = function(self, validators)
    if self.required then
      table_insert(validators, 1, Validator.required(self.error_messages.required))
    else
      table_insert(validators, 1, Validator.not_required)
    end
    if self.choices and self.strict then
      table_insert(validators, get_choices_validator(self.choices, self.error_messages.choices))
    end
    return validators
  end,
  json = function(self)
    local json = self:get_options()
    json.error_messages = nil
    if type(json.default) == 'function' then
      json.default = nil
    end
    if not json.tag then
      if json.choices and #json.choices > 0 and not json.autocomplete then
        json.tag = "select"
      else
        json.tag = "input"
      end
    end
    if json.tag == "input" and json.lazy == nil then
      json.lazy = true
    end
    if type(json.choices) == "function" then
      json.choices = utils.repr.symbol("function_choices__" .. tostring(json.name or json.key or ""))
    end
    return json
  end,
  widget_attrs = function(self, extra_attrs)
    return utils.dict({ required = self.required, readonly = self.disabled }, extra_attrs)
  end,
  validate = function(self, value, ctx)
    if type(value) == 'function' then
      return value
    end
    local err
    for _, validator in ipairs(self.final_validators) do
      value, err = validator(value, ctx)
      if value ~= nil then
        if err == nil then
        elseif value == err then
          -- 代表保持原值,跳过此阶段的所有验证
          return value
        else
          return nil, err
        end
      elseif err ~= nil then
        return nil, err
      else
        -- not-required validator, skip the rest validations
        return nil
      end
    end
    return value
  end,
  get_default = function(self, ctx)
    if type(self.default) ~= "function" then
      return self.default
    else
      return self.default(ctx)
    end
  end,
}
local function get_max_choice_length(choices)
  local n = 0
  for _, c in ipairs(choices) do
    local value = c.value
    local n1 = utils.utf8len(value)
    if n1 > n then
      n = n1
    end
  end
  return n
end

local string_option_names = { 'compact', 'trim', 'pattern', "length", "minlength", "maxlength", "sfzh" }
local string = class({
  type = "string",
  db_type = "varchar",
  compact = true,
  pattern = nil,
  trim = true,
  option_names = string_option_names,
  constructor = function(self, options)
    if not options.choices and not options.length and not options.maxlength and not options.sfzh then
      error(string_format("field %s must define maxlength or choices or length", options.name))
    end
    basefield.constructor(self, options)
    if self.compact == nil then
      self.compact = true
    end
    if self.sfzh then
      self.length = 18
    end
    if self.default == nil and not self.primary_key and not self.unique then
      self.default = ""
    end
    if self.choices and #self.choices > 0 then
      local n = get_max_choice_length(self.choices)
      assert(n > 0, "invalid string choices(empty choices or zero length value):" .. self.name)
      local m = self.length or self.maxlength
      if not m or n > m then
        self.maxlength = n
      end
    end
    return self
  end,
  get_options = function(self)
    local options = basefield.get_options(self)
    return options
  end,
  get_validators = function(self, validators)
    if self.sfzh then
      table_insert(validators, 1, Validator.sfzh)
    end
    if self.compact then
      table_insert(validators, 1, Validator.delete_spaces)
    elseif self.trim then
      table_insert(validators, 1, Validator.trim)
    end
    for _, e in ipairs { "pattern", "length", "minlength", "maxlength" } do
      if self[e] then
        table_insert(validators, 1, Validator[e](self[e], self.error_messages[e]))
      end
    end
    table_insert(validators, 1, Validator.string)
    return basefield.get_validators(self, validators)
  end,
  json = function(self)
    local json = basefield.json(self)
    return json
  end,
  widget_attrs = function(self, extra_attrs)
    local attrs = {
      -- maxlength = self.maxlength,
      minlength = self.minlength
      -- pattern = self.pattern,
    }
    return utils.dict(basefield.widget_attrs(self), attrs, extra_attrs)
  end,
}, basefield)

local sfzh = class({
  type = "sfzh",
  db_type = "varchar",
  constructor = function(self, options)
    options.sfzh = true
    string.constructor(self, options)
    return self
  end,
  -- get_validators = function(self, validators)
  --   table_insert(validators, 1, Validator.sfzh)
  --   return string.get_validators(self, validators)
  -- end,
}, string)

local integer_option_names = { "min", "max", "serial" }
local interger_validator_names = { "min", "max" }
local integer = class({
  type = "integer",
  db_type = "integer",
  option_names = integer_option_names,
  add_min_or_max_validators = function(self, validators)
    for _, e in ipairs(interger_validator_names) do
      if self[e] then
        table_insert(validators, 1, Validator[e](self[e], self.error_messages[e]))
      end
    end
  end,
  get_validators = function(self, validators)
    self:add_min_or_max_validators(validators)
    table_insert(validators, 1, Validator.integer)
    return basefield.get_validators(self, validators)
  end,
  json = function(self)
    local json = basefield.json(self)
    if json.primary_key and json.disabled == nil then
      json.disabled = true
    end
    return json
  end,
  prepare_for_db = function(self, value, data)
    if value == "" or value == nil then
      return NULL
    else
      return value
    end
  end
}, basefield)


local text = class({ type = "text", db_type = "text" }, basefield)

local float_validator_names = { "min", "max" }
local float_option_names = { "min", "max", "precision" }
local float = class({
  type = "float",
  db_type = "float",
  -- precision = 0,
  option_names = float_option_names,
  add_min_or_max_validators = function(self, validators)
    for _, e in ipairs(float_validator_names) do
      if self[e] then
        table_insert(validators, 1, Validator[e](self[e], self.error_messages[e]))
      end
    end
  end,
  get_validators = function(self, validators)
    self:add_min_or_max_validators(validators)
    table_insert(validators, 1, Validator.number)
    return basefield.get_validators(self, validators)
  end,
  prepare_for_db = function(self, value, data)
    if value == "" or value == nil then
      return NULL
    else
      return value
    end
  end,
}, basefield)


local DEFAULT_BOOLEAN_CHOICES = { { label = '是', value = true }, { label = '否', value = false } }
local boolean_option_names = { 'cn' }
local boolean = class({
  type = "boolean",
  db_type = "boolean",
  option_names = boolean_option_names,
  constructor = function(self, options)
    basefield.constructor(self, options)
    if self.choices == nil then
      self.choices = DEFAULT_BOOLEAN_CHOICES
    end
    return self
  end,
  get_validators = function(self, validators)
    if self.cn then
      table_insert(validators, 1, Validator.boolean_cn)
    else
      table_insert(validators, 1, Validator.boolean)
    end
    return basefield.get_validators(self, validators)
  end,
  prepare_for_db = function(self, value, data)
    if value == "" or value == nil then
      return NULL
    else
      return value
    end
  end,
}, basefield)

local json = class({
  type = "json",
  db_type = "jsonb",
  json = function(self)
    local json = basefield.json(self)
    json.tag = "textarea"
    return json
  end,
  prepare_for_db = function(self, value, data)
    if value == "" or value == nil then
      return NULL
    else
      return Validator.encode(value)
    end
  end,
}, basefield)

local function skip_validate_when_string(v)
  if type(v) == "string" then
    return v, v
  else
    return v
  end
end

local function check_array_type(v)
  if type(v) ~= "table" then
    return nil, "array field must be a table"
  else
    return v
  end
end

local function non_empty_array_required(message)
  message = message or "此项必填"
  local function array_validator(v)
    if #v == 0 then
      return nil, message
    else
      return v
    end
  end

  return array_validator
end

local array = class({
  type = "array",
  db_type = "jsonb",
  get_validators = function(self, validators)
    if self.required then
      table_insert(validators, 1, non_empty_array_required(self.error_messages.required))
    end
    table_insert(validators, 1, check_array_type)
    table_insert(validators, Validator.encode_as_array)
    table_insert(validators, 1, skip_validate_when_string)
    return json.get_validators(self, validators)
  end,
  get_empty_value_to_update = function()
    return utils.array()
  end
}, json)

local function make_empty_array()
  return utils.array()
end

local table_option_names = { 'model', 'subfields', 'max_rows', 'uploadable' }
local table = class({
  type = "table",
  max_rows = TABLE_MAX_ROWS,
  option_names = table_option_names,
  constructor = function(self, options)
    array.constructor(self, options)
    if self.subfields then
      local model = { field_names = lua_array {}, fields = {} }
      for i, field in ipairs(self.subfields) do
        if not field.__is_field_class__ then
          field = require("xodel.model").make_field_from_json(field)
        end
        table_insert(model.field_names, field.name)
        model.fields[field.name] = field
      end
      self.model = model
    end
    if not self.model.__is_model_class__ then
      self.model = require("xodel.model"):make_class(self.model)
    end
    if not self.default or self.default == "" then
      self.default = make_empty_array
    end
    return self
  end,
  get_validators = function(self, validators)
    local function validate_by_each_field(rows)
      local err
      for i, row in ipairs(rows) do
        assert(type(row) == "table", "elements of table field must be table")
        row, err = self.model:validate_create(row)
        if row == nil then
          err.index = i
          return nil, err
        end
        rows[i] = row
      end
      return rows
    end

    table_insert(validators, 1, validate_by_each_field)
    return array.get_validators(self, validators)
  end,
  json = function(self)
    local ret = array.json(self)
    local subfields = {}
    for i, name in ipairs(self.model.field_names) do
      local field = self.model.fields[name]
      table_insert(subfields, field:json())
    end
    ret.model = nil
    ret.subfields = subfields
    return ret
  end,
  get_subfields = function(self)
    return self.model.field_names:map(function(name)
      return self.model.fields[name]
    end)
  end,
  load = function(self, rows)
    if type(rows) ~= 'table' then
      error('value of table field must be table, not ' .. type(rows))
    end
    for i = 1, #rows do
      rows[i] = self.model:load(rows[i])
    end
    return lua_array(rows)
  end,
}, array)


local datetime = class({
  type = "datetime",
  db_type = "timestamp",
  precision = 0,
  timezone = true,
  option_names = { 'auto_now_add', 'auto_now', 'precision', 'timezone' },
  constructor = function(self, options)
    basefield.constructor(self, options)
    if self.auto_now_add then
      self.default = ngx_localtime
    end
    return self
  end,
  get_validators = function(self, validators)
    table_insert(validators, 1, Validator.datetime)
    return basefield.get_validators(self, validators)
  end,
  json = function(self)
    local ret = basefield.json(self)
    if ret.disabled == nil and (ret.auto_now or ret.auto_now_add) then
      ret.disabled = true
    end
    return ret
  end,
  prepare_for_db = function(self, value, data)
    if self.auto_now then
      return ngx_localtime()
    elseif value == "" or value == nil then
      return NULL
    else
      return value
    end
  end,
}, basefield)

local date = class({
  type = "date",
  db_type = "date",
  get_validators = function(self, validators)
    table_insert(validators, 1, Validator.date)
    return basefield.get_validators(self, validators)
  end,
  prepare_for_db = function(self, value, data)
    if value == "" or value == nil then
      return NULL
    else
      return value
    end
  end,
}, basefield)


local time = class({
  type = "time",
  db_type = "time",
  precision = 0,
  timezone = true,
  option_names = { 'precision', 'timezone' },
  get_validators = function(self, validators)
    table_insert(validators, 1, Validator.time)
    return basefield.get_validators(self, validators)
  end,
  prepare_for_db = function(self, value, data)
    if value == "" or value == nil then
      return NULL
    else
      return value
    end
  end,
}, basefield)


local VALID_FOREIGN_KEY_TYPES = {
  foreignkey = tostring,
  string = tostring,
  sfzh = tostring,
  integer = Validator.integer,
  float = tonumber,
  datetime = Validator.datetime,
  date = Validator.date,
  time = Validator.time
}
-- **默认的外键转换函数为字符串, 外键self功能导致,待完善
local foreignkey_option_names = { 'reference', 'reference_column', 'realtime', 'keywordQueryName', 'limitQueryName',
  'autocomplete', 'url' }
local foreignkey = class({
  type = "foreignkey",
  convert = tostring,
  option_names = foreignkey_option_names,
  constructor = function(self, options)
    if options.db_type == nil then
      options.db_type = NOT_DEFIEND
    end
    basefield.constructor(self, options)
    local fk_model = self.reference
    if fk_model == "self" then
      -- ** 这里跳过? 或者应该在model初始化完成后再自检.todo
      -- if self.db_type == NOT_DEFIEND then
      --   self.db_type = self.type
      -- end
      return self
    end
    assert(type(fk_model) == "table",
      string_format("a foreignkey must define reference model. not %s(type: %s)", fk_model, type(fk_model)))
    local rc = self.reference_column
    if not rc then
      local pk = fk_model.primary_key or "id"
      rc = pk
      self.reference_column = pk
    end
    local fk = fk_model.fields[rc]
    assert(fk, string_format("invalid foreignkey name %s for foreign model %s", rc,
      fk_model.table_name or "[TABLE NAME NOT DEFINED YET]"))
    self.convert = assert(VALID_FOREIGN_KEY_TYPES[fk.type],
      string_format("invalid foreignkey (name:%s, type:%s)", fk.name, fk.type))
    assert(fk.primary_key or fk.unique, "foreignkey must be a primary key or unique key")
    if self.db_type == NOT_DEFIEND then
      self.db_type = fk.db_type or fk.type
    end
    return self
  end,
  get_validators = function(self, validators)
    local fk_name = self.reference_column
    local convert = self.convert
    local function foreignkey_validator(v)
      local err
      if type(v) == "table" then
        v = v[fk_name]
      end
      v, err = convert(v)
      if err then
        return nil, "error when converting foreign key:" .. tostring(err)
      end
      return v
    end

    table_insert(validators, 1, foreignkey_validator)
    return basefield.get_validators(self, validators)
  end,
  load = function(self, value)
    local fk_name = self.reference_column
    local fk_model = self.reference
    local function __index(t, key)
      if fk_model[key] then
        -- perform sql only when key is in fields:
        return fk_model[key]
      elseif fk_model.fields[key] then
        local pk = rawget(t, fk_name)
        if not pk then
          return nil
        end
        local res = fk_model:get { [fk_name] = pk }
        if not res then
          return nil
        end
        for k, v in pairs(res) do
          rawset(t, k, v)
        end
        -- become an instance of fk_model
        fk_model(t)
        return t[key]
      else
        return nil
      end
    end

    return setmetatable({ [fk_name] = value }, { __index = __index })
  end,
  prepare_for_db = function(self, value, data)
    if value == "" or value == nil then
      return NULL
    else
      return value
    end
  end,
  json = function(self)
    local app = require("xodel.app")
    local ret = basefield.json(self)
    ret.reference = self.reference.table_name
    ret.autocomplete = true
    if ret.realtime == nil then
      ret.realtime = true
    end
    if ret.keywordQueryName == nil then
      ret.keywordQueryName = "__keyword"
    end
    if ret.limitQueryName == nil then
      ret.limitQueryName = "__limit"
    end
    if ret.url == nil then
      ret.url = string_format([[/%s/%s/foreignkey/%s?__name=%s]], app.admin_url_name, app.models_url_name, ret.table_name
        ,
        self.name)
    end
    return ret
  end,
}, basefield)

-- local OSS_URL = utils.get_env("OSS_URL")
-- local OSS_ACCESS_KEY_ID = utils.get_env("OSS_ACCESS_KEY_ID")
-- local OSS_ACCESS_KEY_SECRET = utils.get_env("OSS_ACCESS_KEY_SECRET")
-- local OSS_BUCKET = utils.get_env("OSS_BUCKET")
-- local OSS_REGION = utils.get_env("OSS_REGION")
-- -- Bytes
-- local OSS_SIZE = utils.byte_size_parser(utils.get_env("OSS_SIZE") or "7MB")
-- local OSS_EXPIRATION_DAYS = tonumber(utils.get_env("OSS_EXPIRATION_DAYS") or 180)
-- -- https://help.aliyun.com/document_detail/31988.html?spm=5176.doc32074.6.868.KQbmQM#title-5go-s2f-dnw
-- local function get_policy_time(seconds)
--   return os.date("%Y-%m-%d %H:%M:%S", os.time() + seconds):sub(1, 10) .. "T12:00:00.000Z"
-- end

-- local POLICY = {
--   expiration = get_policy_time(3600 * 24 * OSS_EXPIRATION_DAYS),
--   conditions = { { "content-length-range", 1, OSS_SIZE } }
-- }
-- local function copy(obj)
--   return assert(cjson_decode(cjson_encode(obj)))
-- end


-- local function get_policy(policy, self)
--   policy = utils.dict(utils.jcopy(POLICY), utils.jcopy(policy))
--   local size = utils.byte_size_parser(policy.size or OSS_SIZE)
--   policy.size = nil -- size is not a valid policy key, so delete it
--   if not policy.conditions then
--     policy.conditions = {}
--   end
--   local modified = nil
--   for _, e in ipairs(policy.conditions) do
--     if type(e) == "table" and e[1] == "content-length-range" then
--       e[3] = size
--       modified = true
--     end
--   end
--   if not modified then
--     table_insert(policy.conditions, { "content-length-range", 0, size })
--   end
--   if policy.conditions[-1] then
--     error("invalid policy index -1, field name:"..self.name)
--   end
--   return policy
-- end

-- local function get_payload(kwargs)
--   -- https://github.com/ali-sdk/ali-oss/blob/master/lib/client.js#L134
--   -- https://github.com/bungle/lua-resty-nettle/blame/master/README.md#L136
--   kwargs = kwargs or {}
--   local data = {}
--   local policy = get_policy(kwargs.policy, kwargs.self)
--   data.policy = encode_base64(cjson_encode(policy))
--   data.signature = encode_base64(hmac_sha1(kwargs.key_secret or OSS_ACCESS_KEY_SECRET, data.policy))
--   data.OSSAccessKeyId = kwargs.key_id or OSS_ACCESS_KEY_ID
--   data.success_action_status = 200
--   return data
-- end

-- local alioss_option_names = { 'size', 'policy', 'sizeArg', 'times', 'payload', 'url', 'input_type', 'image', 'maxlength',
--   'width', 'prefix', 'hash' }
-- local alioss = class({
--   type = "alioss",
--   db_type = "varchar",
--   payload = get_payload(),
--   get_payload = get_payload,
--   get_policy = get_policy,
--   option_names = alioss_option_names,
--   constructor = function(self, options)
--     if options.maxlength == nil then
--       options.maxlength = 300
--     end
--     string.constructor(self, options)
--     self.key_secret = options.key_secret
--     self.key_id = options.key_id
--     if options.size then
--       self.policy = options.policy or {}
--       self.sizeArg = options.size
--       self.size = utils.byte_size_parser(options.size)
--       self.policy.size = self.size
--     end
--     if options.times then
--       self.policy.expiration = get_policy_time(utils.time_parser(options.times))
--     end
--     self.payload = get_payload { key = self.key_secret, policy = self.policy, id = self.key_id, self = self }
--     self.url = string_format("//%s.%s.aliyuncs.com/", options.bucket or OSS_BUCKET, options.region or OSS_REGION)
--     self.policy = nil
--     return self
--   end,
--   get_validators = function(self, validators)
--     table_insert(validators, 1, Validator.url)
--     return string.get_validators(self, validators)
--   end,
--   json = function(self)
--     local ret = string.json(self)
--     if ret.input_type == nil then
--       ret.input_type = "file"
--     end
--     if ret.image then
--       ret.type = "alioss_image"
--     end
--     return ret
--   end,
-- }, string)



return {
  basefield = basefield,
  string = string,
  text = text,
  integer = integer,
  float = float,
  datetime = datetime,
  date = date,
  time = time,
  json = json,
  array = array,
  table = table,
  foreignkey = foreignkey,
  boolean = boolean,
  alioss = alioss,
  sfzh = sfzh
}
