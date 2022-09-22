local Model = require "xodel.xodel"
local repr = require "xodel.repr"

local User = Model:create_model {
  table_name = 'usr',
  fields = {
    { name = 'id', type = 'integer', primary_key = true },
    { name = 'name', maxlength = 20 },
  }
}

print(repr(User:where_null("id"):select("name"):statement()))