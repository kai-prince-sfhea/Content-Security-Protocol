-- Attempt to obtain project root / output dir. Quarto normally sets
-- QUARTO_PROJECT_ROOT and QUARTO_PROJECT_OUTPUT_DIR for filters. However, when
-- this extension is used outside a full project render (e.g. ad-hoc pandoc
-- invocation or certain preview contexts) these may be absent. Provide a
-- graceful fallback that searches upward for _quarto.yml.
local function file_exists(p)
  local f = io.open(p, 'r'); if f then f:close(); return true end; return false
end
local function detect_project_root()
  local env = os.getenv('QUARTO_PROJECT_ROOT')
  if env and #env > 0 then return env, false end
  -- Search current directory and a few parents for _quarto.yml / _quarto.yaml
  local candidates = {'.','..','../..','../../..','../../../..'}
  for _,c in ipairs(candidates) do
    local yml = pandoc.path.normalize(pandoc.path.join({c,'_quarto.yml'}))
    local yaml = pandoc.path.normalize(pandoc.path.join({c,'_quarto.yaml'}))
    if file_exists(yml) or file_exists(yaml) then
      return pandoc.path.normalize(c), true
    end
  end
  -- Fallback: current directory
  return pandoc.path.normalize('.'), true
end
local InputDir, fallback_root = detect_project_root()
local function detect_output_dir(input_root)
  local env = os.getenv('QUARTO_PROJECT_OUTPUT_DIR')
  if env and #env > 0 then return env, false end
  -- Assume conventional _site when not provided.
  return pandoc.path.join({input_root,'_site'}), true
end
local OutputDir, fallback_output = detect_output_dir(InputDir)
local MathDir = pandoc.path.join({InputDir,'_schema'})
local CSP = dofile(pandoc.path.join({InputDir,'_extensions','Content-Security-Protocol','CSP.lua'}))

-- Lightweight pretty JSON helper (fallback) if schema.lua unavailable
local pretty
local schema_path = pandoc.path.join({InputDir,'_extensions','schema','schema.lua'})
local ok_schema, schema_mod = pcall(function() return dofile(schema_path) end)
if ok_schema and schema_mod and schema_mod.pretty_json then
  pretty = schema_mod.pretty_json
else
  pretty = function(s) return s end
end

-- Load Directories.json if present (optional)
local Dir = {}
local f = io.open(pandoc.path.join({MathDir,'Directories.json'}),'r')
if f then local txt=f:read('a'); f:close(); pcall(function() Dir = pandoc.json.decode(txt) end) end

-- Load existing CSP.json if present
local CSPTrack = {}
-- Read CSP.json from project root now instead of _schema
local cf = io.open(pandoc.path.join({InputDir,'CSP.json'}),'r')
if cf then local txt=cf:read('a'); cf:close(); pcall(function() CSPTrack = pandoc.json.decode(txt) end) end

_G.CSP_CTX = {
  InputDir=InputDir, OutputDir=OutputDir, MathDir=MathDir, CSP=CSP, Dir=Dir, CSPTrack=CSPTrack,
  site_union={}, site_intersection={}, file_scores={}, first_file=true,
  SRI_REPORT={ files = {}, remote_candidates = {} }, NONCE_NORMALISE_PATTERN = "'nonce%-[A-Za-z0-9]+'",
  pretty = pretty,
  fallback_root_used = fallback_root,
  fallback_output_used = fallback_output,
  Config = {}
}

if fallback_root or fallback_output then
  io.stderr:write('[CSP] Warning: environment variables missing. Using detected InputDir='..InputDir..' OutputDir='..OutputDir..'\n')
end

local function meta_list_to_lua(v)
  if type(v) ~= 'table' or not v[1] then return nil end
  local out = {}
  for _,item in ipairs(v) do
    if type(item) == 'string' then out[#out+1]=item
    elseif type(item) == 'table' and item.text then out[#out+1]=item.text
    elseif type(item) == 'table' and item.c and pandoc.utils.stringify then out[#out+1]=pandoc.utils.stringify(item) end
  end
  return out
end

return { { Meta = function(m)
  -- Expect under top-level key: content-security-protocol or csp_protocol
  local cfg = m['content-security-protocol'] or m['csp_protocol'] or pandoc.MetaMap({})
  local function get_bool(key, def)
    local v = cfg[key]
    if v == nil then return def end
    if v == true or (type(v)=='table' and v.t=='MetaBool' and v.text=='true') then return true end
    if v == false then return false end
    if type(v)=='string' then v=v:lower(); if v=='true' or v=='yes' or v=='1' then return true elseif v=='false' or v=='no' or v=='0' then return false end end
    return def
  end
  local function get_list(key)
    local v = cfg[key]
    if not v then return {} end
    local list = meta_list_to_lua(v)
    if list then return list end
    if type(v)=='string' then return {v} end
    return {}
  end
  local function get_string(key)
    local v = cfg[key]
    if not v then return nil end
    if type(v)=='string' then return v end
    if pandoc.utils and pandoc.utils.stringify then return pandoc.utils.stringify(v) end
    return nil
  end
  local Conf = {
    allow_jsdelivr = get_bool('allow_jsdelivr', true),
    allow_google_fonts = get_bool('allow_google_fonts', true),
  -- (legacy position removed; defaults moved below)
    additional_script_src = get_list('additional_script_src'),
    additional_style_src = get_list('additional_style_src'),
    additional_connect_src = get_list('additional_connect_src'),
    enable_trusted_types = get_bool('enable_trusted_types', false),
    trusted_types_policies = get_list('trusted_types_policies'),
    require_trusted_types_for_script = get_bool('require_trusted_types_for_script', false),
  auto_strict_dynamic = get_bool('auto_strict_dynamic', true),
    force_remove_unsafe_hashes = get_bool('force_remove_unsafe_hashes', true),
  disable_sri = get_bool('disable_sri', false),
  prefer_hashes = get_bool('prefer_hashes', false),
  prefer_hashes_strict = get_bool('prefer_hashes_strict', false),
  retain_style_inline_dynamic = get_bool('retain_style_inline_dynamic', true),
  dev_allow_ws = get_bool('dev_allow_ws', true),
  allow_cdnjs = get_bool('allow_cdnjs', true)
  }
  _G.CSP_CTX.Config = Conf
  return m
end } }
