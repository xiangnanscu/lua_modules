local type = type
local pairs = pairs
-- local next = next
local ipairs = ipairs
local table_sort = table.sort
local table_concat = table.concat
local table_insert = table.insert
local string_format = string.format
local cat = table.concat
local sub = string.sub
local rep = string.rep
local select = select
local error = error
local math_floor = math.floor
local lua_array = require("xodel.array")
local ngx_re_gsub, ngx_time, warn, table_clone
if ngx then
  table_clone = require("table.clone")
  ngx_re_gsub = ngx.re.gsub
  ngx_time = ngx.time
  function warn(s)
    ngx.log(ngx.WARN, s)
  end
else
  function warn(s)
    print(s)
  end
end
-- local version = '1.21'

local cjson_safe, repr, cjson, lfs, enc, ENCODE_AS_ARRAY
do
  local ok
  ok, cjson_safe = pcall(require, "cjson.safe")
  if not ok then
    warn("cjson.safe module not found")
  end
  enc = ok and cjson_safe.encode or function()
    return nil, "Lua cJSON encoder not found"
  end
  ok, lfs = pcall(require, "syscall.lfs")
  if not ok then
    ok, lfs = pcall(require, "lfs")
  end
  if not ok then
    warn("lfs module not found")
  end
  ok, repr = pcall(require, "mvc.repr")
  if not ok then
    warn("mvc.repr module not found")
  end
  ok, cjson = pcall(require, "cjson")
  if not ok then
    warn("cjson module not found")
  else
    ENCODE_AS_ARRAY = cjson.empty_array_mt
  end
end

-- ** why require "cjson_safe.safe".empty_array_mt not work

local is_windows = package.config:sub(1, 1) == "\\"
local NULL = ngx.null
local function writefile(s, name)
  name = name or string.format("debug/%s.js", os.date("%Y%m%d%H%M%S", os.time()))
  assert(io.open(name, "a+")):write(s):close()
end

local function debuger(...)
  local res = {}
  for k, v in pairs({ ... }) do
    if type(v) == "string" then
      v = repr.symbol(v)
    end
    res[#res + 1] = repr(v, { max_depth = 3 })
  end
  local fc = ngx and writefile or print
  fc(table.concat(res, "\n/*************************************/\n") .. "\n")
end

local loger = setmetatable({
  s = function(e, name)
    return writefile(repr(repr.symbol(e)) .. "\n", name)
  end
}, {
  __call = function(_, ...)
    return debuger(...)
  end
})
local function logsql(sql)
  if sql:sub(-1) ~= ';' then
    sql = sql .. ';'
  end
  return writefile(sql, string.format("debug/%s.sql", os.date("%Y%m%d%H%M%S", os.time())))
end

local JSON_TYPE = { table = true, string = true, number = true, boolean = true }
local function copy(o, opt)
  if not opt then
    local function simple_deepcopy(v)
      if type(v) == 'table' then
        local v_copy = {}
        for key, value in pairs(v) do
          v_copy[key] = simple_deepcopy(value)
        end
        return v_copy
      else
        return v
      end
    end

    return simple_deepcopy(o)
  else
    local visited = {}
    local function recursive_copy(v)
      local v_type = type(v)
      if v_type == "table" then
        if visited[v] then
          return visited[v]
        end
        local v_copy = {}
        visited[v] = v_copy
        for key, value in pairs(v) do
          v_copy[recursive_copy(key)] = recursive_copy(value)
        end
        if opt.json then
          return v_copy
        end
        local mt = getmetatable(v)
        if not mt then
          return v_copy
        end
        if opt.copy_metatable then
          setmetatable(v_copy, recursive_copy(mt))
        else
          setmetatable(v_copy, mt)
        end
        return v_copy
      elseif JSON_TYPE[v_type] or not opt.json then
        return v
      else
        return nil
      end
    end

    return recursive_copy(o)
  end
end

local JCOPY_OPT = { json = true, copy_metatable = false }
local function jcopy(o)
  return copy(o, JCOPY_OPT)
end

local DEEPCOPY_OPT = { json = false, copy_metatable = true }
local function deepcopy(o)
  return copy(o, DEEPCOPY_OPT)
end

local function array(t)
  return setmetatable(t or {}, ENCODE_AS_ARRAY)
end

local function map(tbl, func)
  local res = lua_array()
  for i = 1, #tbl do
    res[i] = func(tbl[i])
  end
  return res
end

local function filter(tbl, func)
  local res = lua_array()
  for i = 1, #tbl do
    local v = tbl[i]
    if func(v) then
      res[#res + 1] = v
    end
  end
  return res
end

local function find(tbl, func)
  for i = 1, #tbl do
    local v = tbl[i]
    if func(v) then
      return v, i
    end
  end
end

local function mapkv(tbl, func)
  local res = {}
  for k, v in pairs(tbl) do
    k, v = func(k, v)
    res[k] = v
  end
  return res
end

local function filterkv(tbl, func)
  local res = {}
  for k, v in pairs(tbl) do
    if func(k, v) then
      res[k] = v
    end
  end
  return res
end

local function list(...)
  local t = lua_array()
  for _, a in pairs { ... } do
    for _, v in ipairs(a) do
      t[#t + 1] = v
    end
  end
  return t
end

local function list_extend(t, ...)
  for _, a in pairs { ... } do
    for _, v in ipairs(a) do
      t[#t + 1] = v
    end
  end
  return t
end

local function list_has(t, e)
  for i, v in ipairs(t) do
    if v == e then
      return i
    end
  end
end

local function list_unique_insert(t, name)
  for i, k in ipairs(t) do
    if k == name then
      return false
    end
  end
  table_insert(t, name)
  return true
end

local function clone(t)
  return table_clone(t)
end

local function dict(...)
  local t = {}
  for _, d in pairs { ... } do
    for k, v in pairs(d) do
      t[k] = v
    end
  end
  return t
end

local function dict_update(t, ...)
  for _, a in pairs { ... } do
    for k, v in pairs(a) do
      t[k] = v
    end
  end
  return t
end

local function dict_has(t, e)
  for k, v in pairs(t) do
    if v == e then
      return true, k
    end
  end
  return false
end

local function strip(value)
  return (ngx_re_gsub(value, [[^\s*(.+)\s*$]], "$1", "josu"))
end

local function empty(value)
  return value == nil or value == "" or value == NULL
end

local function to_html_attrs(tbl)
  local attrs = {}
  local bools = {}
  for k, v in pairs(tbl) do
    if v == true then
      bools[#bools + 1] = " " .. k
    elseif v == false then
    elseif type(v) == "table" then
      attrs[#attrs + 1] = string_format(' %s="%s"', k, table_concat(v, " "))
    else
      attrs[#attrs + 1] = string_format(' %s="%s"', k, v)
    end
  end
  return table_concat(attrs, "") .. table_concat(bools, "")
end

local function reversed_inherited_chain(self)
  local res = { self }
  local cls = getmetatable(self)
  while cls do
    table.insert(res, 1, cls)
    self = cls
    cls = getmetatable(self)
  end
  return res
end

local function inherited_chain(self)
  local res = { self }
  local cls = getmetatable(self)
  while cls do
    res[#res + 1] = cls
    self = cls
    cls = getmetatable(self)
  end
  return res
end

local function sorted(t, func)
  local keys = {}
  for k, v in pairs(t) do
    keys[#keys + 1] = k
  end
  table_sort(keys, func)
  local i = 0
  return function()
    i = i + 1
    local key = keys[i]
    return key, t[key]
  end
end

local function curry(func, kwargs)
  local function _curry(morekwargs)
    return func(dict(kwargs, morekwargs))
  end

  return _curry
end

local function serialize_basetype(v)
  -- string.format("%q", '\r') 会被转义成\13, 导致浏览器渲染成13
  if type(v) == "string" then
    return '"' .. v:gsub("\\", "\\\\"):gsub('"', '\\"') .. '"'
  else
    return tostring(v)
  end
end

local function serialize_attrs(attrs, table_name)
  -- {a=1, b='bar'} -> `foo`.`a` = 1, `foo`.`b` = "bar"
  -- {a=1, b='bar'} -> a = 1, b = "bar"
  local res = {}
  if table_name then
    for k, v in pairs(attrs) do
      res[#res + 1] = string_format("%s = %s", string_format("`%s`.`%s`", table_name, k), serialize_basetype(v))
    end
  else
    for k, v in pairs(attrs) do
      res[#res + 1] = string_format("%s = %s", k, serialize_basetype(v))
    end
  end
  return table_concat(res, ", ")
end

local function split(s, sep)
  sep = sep or " "
  local i = 1
  local a, b
  local stop
  local function split_iter()
    if stop then
      return
    end
    a, b = s:find(sep, i, true)
    if a then
      local e = s:sub(i, a - 1)
      i = b + 1
      return e
    else
      stop = true
      return s:sub(i)
    end
  end

  return split_iter
end

local function splits(s, sep)
  local res = lua_array {}
  for e in split(s, sep) do
    res[#res + 1] = e
  end
  return res
end

local unit_table = { s = 1, m = 60, h = 3600, d = 3600 * 24, w = 3600 * 24 * 7, M = 3600 * 24 * 30, y = 3600 * 24 * 365 }
local function time_parser(t)
  if type(t) == "string" then
    local unit = string.sub(t, -1, -1)
    local secs = unit_table[unit]
    assert(secs, "invalid time unit: " .. unit)
    local ts = string.sub(t, 1, -2)
    local num = tonumber(ts)
    assert(num, "can't convert '" .. ts .. "' to a number")
    return num * secs
  elseif type(t) == "number" then
    return t
  else
    return 0
  end
end

local size_table = {
  k = 1024,
  m = 1024 * 1024,
  g = 1024 * 1024 * 1024,
  kb = 1024,
  mb = 1024 * 1024,
  gb = 1024 * 1024 * 1024
}
local function byte_size_parser(t)
  if type(t) == "string" then
    local unit = t:gsub("^(%d+)([^%d]+)$", "%2"):lower()
    local ts = t:gsub("^(%d+)([^%d]+)$", "%1"):lower()
    local bytes = size_table[unit]
    assert(bytes, "invalid size unit: " .. unit)
    local num = tonumber(ts)
    assert(num, "can't convert `" .. ts .. "` to a number")
    return num * bytes
  elseif type(t) == "number" then
    return t
  else
    return 0
  end
end

local function cache(f, arg)
  local result, err
  local function _cache()
    if result == nil then
      result, err = f(arg)
    end
    return result, err
  end

  return _cache
end

local function cache_by_key(f)
  local results = {}
  local function _cache(key)
    if results[key] == nil then
      local res, err = f(key)
      if err then
        return nil, err
      end
      results[key] = res
    end
    return results[key]
  end

  return _cache
end

local function cache_by_time(f, cache_time)
  local result, err, cache_gen_time
  cache_time = time_parser(cache_time)
  if cache_time == 0 then
    return f
  end
  local function _cache()
    if result == nil or ngx_time() - cache_gen_time > cache_time then
      result, err = f()
      cache_gen_time = ngx_time()
    end
    return result, err
  end

  return _cache
end

local get_dirs
if is_windows then
  function get_dirs(directory)
    local t, popen = {}, io.popen
    local pfile = popen('dir "' .. directory .. '" /b /ad')
    for filename in pfile:lines() do
      if not filename:find("__") then
        t[#t + 1] = filename
      end
    end
    pfile:close()
    return t
  end
else
  function get_dirs(directory)
    local t = {}
    local pfile = io.popen('ls -l "' .. directory .. '" | grep ^d')
    for filename in pfile:lines() do
      t[#t + 1] = filename:match("%d%d:%d%d (.+)$")
    end
    pfile:close()
    return t
  end
end
local function locals()
  local variables = {}
  local idx = 1
  while true do
    local ln, lv = debug.getlocal(2, idx)
    if ln ~= nil then
      variables[ln] = lv
    else
      break
    end
    idx = 1 + idx
  end
  return variables
end

local function upvalues()
  local variables = {}
  local idx = 1
  local func = debug.getinfo(2, "f").func
  while true do
    local ln, lv = debug.getupvalue(func, idx)
    if ln ~= nil then
      variables[ln] = lv
    else
      break
    end
    idx = 1 + idx
  end
  return variables
end

local function zfill(s, n, c)
  local len = string.len(s)
  n = n or len
  c = c or " "
  for _ = 1, n - len do
    s = s .. c
  end
  return s
end

local function debugger(e)
  return debug.traceback() .. e
end

local function jsonlize(tbl)
  -- 确保t里面的值符合json规范
  local visited = {}
  local function f(obj)
    local e = type(obj)
    if e == "table" then
      if visited[obj] then
        return obj
      else
        visited[obj] = true
        local t = {}
        for k, v in pairs(obj) do
          if tostring(k):sub(1, 1) ~= "_" then
            t[k] = f(v)
          end
        end
        return t
      end
    elseif JSON_TYPE[e] then
      return obj
    end
  end

  return f(tbl)
end

local function pjson(dt, lf, id, ac, ec)
  assert(type(dt) == "table")
  dt = jsonlize(dt)
  local s, e = (ec or enc)(dt)
  if not s then
    return s, e
  end
  lf, id, ac = lf or "\n", id or "\t", ac or " "
  local i, j, k, n, r, p, q = 1, 0, 0, #s, {}, nil, nil
  local al = sub(ac, -1) == "\n"
  for x = 1, n do
    local c = sub(s, x, x)
    if not q and (c == "{" or c == "[") then
      r[i] = p == ":" and cat { c, lf } or cat { rep(id, j), c, lf }
      j = j + 1
    elseif not q and (c == "}" or c == "]") then
      j = j - 1
      if p == "{" or p == "[" then
        i = i - 1
        r[i] = cat { rep(id, j), p, c }
      else
        r[i] = cat { lf, rep(id, j), c }
      end
    elseif not q and c == "," then
      r[i] = cat { c, lf }
      k = -1
    elseif not q and c == ":" then
      r[i] = cat { c, ac }
      if al then
        i = i + 1
        r[i] = rep(id, j)
      end
    else
      if c == '"' and p ~= "\\" then
        q = not q and true or nil
      end
      if j ~= k then
        r[i] = rep(id, j)
        i, k = i + 1, j
      end
      r[i] = c
    end
    p, i = c, i + 1
  end
  return cat(r)
end

local function compose_funcs(f, g)
  local function inner(v)
    local err
    v, err = f(v)
    if err ~= nil then
      return nil, err
    else
      return g(v)
    end
  end

  return inner
end

local function utf8len(s)
  local _, cnt = s:gsub("[^\128-\193]", "")
  return cnt
end

local Chars = {}
for Loop = 0, 255 do
  Chars[Loop + 1] = string.char(Loop)
end
local String = table.concat(Chars)

local Built = { ["."] = Chars }

local AddLookup = function(CharSet)
  local Substitute = string.gsub(String, "[^" .. CharSet .. "]", "")
  local Lookup = {}
  for Loop = 1, string.len(Substitute) do
    Lookup[Loop] = string.sub(Substitute, Loop, Loop)
  end
  Built[CharSet] = Lookup

  return Lookup
end

local function random_string(Length, CharSet)
  -- Length (number)
  -- CharSet (string, optional); e.g. %l%d for lower case letters and digits

  CharSet = CharSet or "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

  if CharSet == "" then
    return ""
  else
    local Result = {}
    local Lookup = Built[CharSet] or AddLookup(CharSet)
    local Range = #Lookup

    for Loop = 1, Length do
      Result[Loop] = Lookup[math.random(1, Range)]
    end

    return table.concat(Result)
  end
end

local function slice(t, from, to)
  if from then
    if from < 1 then
      from = #t + from + 1
    end
  else
    from = 1
  end
  if to then
    if to < 1 then
      to = #t + to + 1
    end
  else
    to = #t
  end
  local r = {}
  for i = from, to do
    r[#r + 1] = t[i]
  end
  return r
end

local function callable(f)
  return type(f) == "function" or (type(f) == "table" and getmetatable(f) and callable(getmetatable(f).__call))
end

local function dir_exists(path)
  if (lfs.attributes(path, "mode") == "directory") then
    return true
  end
  return false
end

local function files(path, depth, level, ret)
  ret = ret or {}
  depth = depth or false
  level = level or 0
  if not dir_exists(path) then
    return ret
  end
  for file in lfs.dir(path) do
    local p = path .. '/' .. file
    local t = lfs.attributes(p, "mode")
    if t == "file" then
      ret[#ret + 1] = p
    elseif t == "directory" and file ~= '.' and file ~= '..' then
      if not depth or level < depth then
        files(p, depth, level + 1, ret)
      end
    end
  end
  return ret
end

local function files2(path, option)
  local f = io.popen(string_format("find %s -type f %s", path, option or ""))
  assert(f)
  local ret = {}
  for line in f:lines() do
    ret[#ret + 1] = line
  end
  f:close()
  return ret
end

local function folders(path, depth, level, ret)
  ret = ret or {}
  depth = depth or false
  level = level or 0
  for file in lfs.dir(path) do
    local p = path .. "/" .. file
    local t = lfs.attributes(p, "mode")
    if t == "file" then
    elseif t == "directory" and file ~= "." and file ~= ".." then
      ret[#ret + 1] = p
      if not depth or level < depth then
        folders(p, depth, level + 1, ret)
      end
    end
  end
  return ret
end

local function log(s)
  return ngx.log(ngx.ERR, s)
end

local READONLY_TABLE = setmetatable({}, {
  __newindex = function()
    error("this table is readonly")
  end
})
local function array_to_set(a)
  local d = {}
  for i, k in ipairs(a) do
    d[k] = true
  end
  return d
end

local function class_new(cls, self)
  return setmetatable(self or {}, cls)
end

local function class__call(cls, ...)
  return cls.new(cls, ...)
end

local function make_subclass(...)
  local n = select("#", ...)
  local subclass = dict(...)
  if subclass.new == nil then
    subclass.new = class_new
  end
  if subclass.__call == nil then
    subclass.__call = class__call
  end
  subclass.__index = subclass
  local pclass = n > 1 and select(n - 1, ...) or nil
  -- make_subclass(a, b, c, d) then pclass is c
  if pclass then
    setmetatable(subclass, pclass)
    -- if rawget(pclass, "__index") == nil then
    --   pclass.__index = pclass
    -- end
  end
  return subclass
end

local metamethods = {
  __add = true,
  __sub = true,
  __mul = true,
  __div = true,
  __mod = true,
  __pow = true,
  __unm = true,
  __concat = true,
  __len = true,
  __eq = true,
  __lt = true,
  __le = true,
  __index = true,
  __newindex = true,
  __call = true,
  __tostring = true
}
local function make_class2(...)
  local pclass = {}
  local class = {}
  for i, t in ipairs({ ... }) do
    for name, method in pairs(t) do
      if metamethods[name] then
        pclass[name] = method
      else
        class[name] = method
      end
    end
  end
  class.__index = class
  setmetatable(class, pclass)
  if class.new == nil then
    class.new = class_new
  end
  return class
end

local function make_class(...)
  local pclass = dict(...)
  local class = dict(...)
  pclass.__index = pclass
  class.__index = class
  setmetatable(class, pclass)
  if class.new == nil then
    class.new = class_new
  end
  return class
end

local function trunk(a, n)
  n = n or 1
  local res = {}
  local unit = {}
  for i, e in ipairs(a) do
    if #unit == n then
      res[#res + 1] = unit
      unit = { e }
    else
      unit[#unit + 1] = e
    end
  end
  res[#res + 1] = unit
  return res
end

local function set(a)
  local s = {}
  for i, e in ipairs(a) do
    s[e] = true
  end
  return s
end

local function table_keys(t)
  local keys = lua_array()
  for k, v in pairs(t) do
    keys[#keys + 1] = k
  end
  return keys
end

local object = {
  contains = function(self, a, b)
    for k, v in pairs(b) do
      if not self:same(a[k], v) then
        return false
      end
    end
    return true
  end,
  same = function(self, a, b)
    if type(a) ~= type(b) then
      return false
    end
    if type(a) == "table" then
      if #table_keys(a) == #table_keys(b) then
        return self:contains(a, b)
      else
        return false
      end
    else
      return a == b
    end
  end
}
local function can_read_file(name)
  local f = io.open(name, "r")
  if f ~= nil then
    io.close(f)
    return true
  else
    return false
  end
end

local function combine(a, n)
  if #a == n then
    return { a }
  elseif n == 1 then
    return map(a, function(e)
      return { e }
    end)
  elseif #a > n then
    local head = a[1]
    local rest = slice(a, 2)
    return list(combine(rest, n), map(combine(rest, n - 1), function(e)
      return { head, unpack(e) }
    end))
  else
    return {}
  end
end

local function from_entries(a)
  local ret = {}
  for i, e in ipairs(a) do
    ret[e[1]] = e[2]
  end
  return ret
end

local function entries(a)
  local ret = {}
  for k, v in pairs(a) do
    ret[#ret + 1] = { k, v }
  end
  return ret
end

local function values(a)
  local ret = {}
  for k, v in pairs(a) do
    ret[#ret + 1] = v
  end
  return ret
end

local function load_json(fn)
  local file, json
  file = assert(io.open(fn))
  json = assert(file:read("a*"))
  file:close()
  return cjson_safe.decode(json)
end

local function make_get_env()
  local env = load_json(".env-cmdrc.json")
  local function get_env(name)
    for k, v in pairs(env) do
      for k2, v2 in pairs(v) do
        if k2 == name then
          return v2
        end
      end
    end
    return
  end

  return get_env
end

local function write_json(fn, obj)
  local file, json, res, err
  file, err = io.open(fn, "w")
  if not file then
    return nil, err
  end
  json, err = pjson(obj)
  if not json then
    return nil, err
  end
  res, err = file:write(json)
  if not res then
    return nil, err
  end
  return file:close()
end

local function valid_id(id)
  id = tonumber(id)
  if not id or id ~= math_floor(id) then
    return
  else
    return id
  end
end

local function eval(token, context)
  local f = loadstring(string_format("return %s", token))
  setfenv(f, dict(_G, context))
  return f()
end

local function assert_nil(...)
  if select(1, ...) == nil then
    error(select(2, ...))
  else
    return ...
  end
end

local function require_cd(name)
  local p = debug.getinfo(2, "S").source:sub(2)
  local cd = p:gsub("[^/\\]+$", "")
  local find, mod = pcall(require, cd .. name)
  if not find then
    -- print('no cd module found, try normal path')
    return require(name)
  else
    return mod
  end
end

local function f()
  local i = 0
  local p
  while true do
    local s = debug.getinfo(i)
    if not s then
      break
    else
      p = s.source:sub(2)
    end
    i = i + 1
  end
  return p
end

local function get_mvc_modules()
  local res = {}
  for i, file in ipairs(files("lualib/mvc")) do
    local path = file:gsub("/", "."):match("lualib.mvc.(.+).lua")
    if path then
      res[path] = require("mvc." .. path)
    end
  end
  return res
end

local function to_query_string(t)
  local res = {}
  for k, v in pairs(t) do
    res[#res + 1] = k .. "=" .. v
  end
  return table_concat(res, "&")
end

local localtime = ngx.localtime
local function get_age(sfzh, now)
  now = now or localtime()
  local month_diff = tonumber(now:sub(6, 7)) - tonumber(sfzh:sub(11, 12))
  local year_diff = tonumber(now:sub(1, 4)) - tonumber(sfzh:sub(7, 10))
  if month_diff < 0 then
    return year_diff - 1
  elseif month_diff == 0 then
    local day_diff = tonumber(now:sub(9, 10)) - tonumber(sfzh:sub(13, 14))
    if day_diff < 0 then
      return year_diff - 1
    else
      return year_diff
    end
  else
    return year_diff
  end
end

local function get_xb(sfzh)
  local n = tonumber(sfzh:sub(-2, -2)) or 1
  if n % 2 == 0 then
    return "女"
  else
    return "男"
  end
end

local function class(cls, parent)
  if parent then
    if parent.__index == nil then
      parent.__index = parent
    end
    setmetatable(cls, parent)
  end
  cls.__index = cls
  cls.new = cls.new or class_new
  cls.__call = cls.__call or class__call
  return cls
end

return {
  class = class,
  get_xb = get_xb,
  get_age = get_age,
  dir_exists = dir_exists,
  NULL = NULL,
  clone = clone,
  table_keys = table_keys,
  list_unique_insert = list_unique_insert,
  to_query_string = to_query_string,
  get_mvc_modules = get_mvc_modules,
  require = require_cd,
  assert_nil = assert_nil,
  eval = eval,
  valid_id = valid_id,
  write_json = write_json,
  load_json = load_json,
  values = values,
  entries = entries,
  from_entries = from_entries,
  copy_as_ref = copy_as_ref,
  combine = combine,
  object = object,
  set = set,
  trunk = trunk,
  make_subclass = make_subclass,
  make_class = make_class,
  array_to_set = array_to_set,
  slice = slice,
  array = array,
  map = map,
  filter = filter,
  mapkv = mapkv,
  filterkv = filterkv,
  dict = dict,
  list = list,
  dict_has = dict_has,
  list_has = list_has,
  to_html_attrs = to_html_attrs,
  strip = strip,
  empty = empty,
  dict_update = dict_update,
  list_extend = list_extend,
  reversed_inherited_chain = reversed_inherited_chain,
  inherited_chain = inherited_chain,
  sorted = sorted,
  curry = curry,
  serialize_basetype = serialize_basetype,
  serialize_attrs = serialize_attrs,
  split = split,
  splits = splits,
  cache = cache,
  cache_by_key = cache_by_key,
  time_parser = time_parser,
  get_dirs = get_dirs,
  locals = locals,
  upvalues = upvalues,
  zfill = zfill,
  repr = repr,
  loger = loger,
  debugger = debugger,
  pjson = pjson,
  compose_funcs = compose_funcs,
  utf8len = utf8len,
  random_string = random_string,
  callable = callable,
  cache_by_time = cache_by_time,
  files = files,
  folders = folders,
  byte_size_parser = byte_size_parser,
  READONLY_TABLE = READONLY_TABLE,
  can_read_file = can_read_file,
  log = log,
  copy = copy,
  jcopy = jcopy,
  deepcopy = deepcopy,
  JSON_TYPE = JSON_TYPE,
  jsonlize = jsonlize,
  -- get_env = make_get_env(),
  find = find,
  logsql = logsql
}
