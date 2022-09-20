---@alias toker fun(): string
---@alias dbvalue string|number|boolean|table|toker
---@param is_literal boolean escape as literal or not
---@param is_bracket boolean surrounding with () or not
---@return fun(value:dbvalue):string
local function _escape_factory(is_literal, is_bracket)
  
end