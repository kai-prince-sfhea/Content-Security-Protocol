-- Self-contained CSP core (decoupled from former schema extension)

local M = {}

-- Pretty Print JSON
M.pretty_json = function(json_str)
    indent = "  "
    local level = 0
    local formatted = ""
    local in_str = false
    local char = ""
    local prev_char = ""

    for i = 1, #json_str do
        char = json_str:sub(i, i)
        if char == '"' and prev_char ~= '\\' then
            in_str = not in_str
        end
        if not in_str then
            if char == '{' or char == '[' then
                level = level + 1
                formatted = formatted .. char .. "\n" .. string.rep(indent, level)
            elseif char == '}' or char == ']' then
                level = level - 1
                formatted = formatted .. "\n" .. string.rep(indent, level) .. char
            elseif char == ',' then
                formatted = formatted .. char .. "\n" .. string.rep(indent, level)
            elseif char == ':' then
                formatted = formatted .. ": "
            else
                formatted = formatted .. char
            end
        else
            formatted = formatted .. char
        end
        prev_char = char
    end
    return formatted
end

M.json_encode = function(table)
    local output_string = ""
    if quarto and quarto.json then
        output_string = quarto.json.encode(table)
    else
        output_string = pandoc.json.encode(table)
    end
    output_string = M.pretty_json(output_string)
    return output_string
end

-- Random nonce (16 chars base62)
function M.random_nonce()
  local chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  local t = {}
  for i=1,16 do local idx = math.random(#chars); t[i]=chars:sub(idx,idx) end
  return table.concat(t)
end

-- SHA-256 + Base64 (for hashes & SRI)
local function rotr(x,n) return ((x >> n) | (x << (32-n))) & 0xffffffff end
local function shr(x,n) return (x >> n) & 0xffffffff end
local function Ch(x,y,z) return (x & y) ~ ((~x) & z) end
local function Maj(x,y,z) return (x & z) ~ (y & (x ~ z)) end
local function Sigma0(x) return rotr(x,2) ~ rotr(x,13) ~ rotr(x,22) end
local function Sigma1(x) return rotr(x,6) ~ rotr(x,11) ~ rotr(x,25) end
local function sigma0(x) return rotr(x,7) ~ rotr(x,18) ~ shr(x,3) end
local function sigma1(x) return rotr(x,17) ~ rotr(x,19) ~ shr(x,10) end
local K = {0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2}
local function to_bytes(str) local t={} for i=1,#str do t[i]=str:byte(i) end return t end
function M.sha256(str)
  local bytes=to_bytes(str); local bitlen=#bytes*8; bytes[#bytes+1]=0x80; while (#bytes % 64)~=56 do bytes[#bytes+1]=0 end
  for i=7,0,-1 do bytes[#bytes+1]=(bitlen >> (i*8)) & 0xff end
  local h0,h1,h2,h3,h4,h5,h6,h7=0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
  local w={}
  for i=1,#bytes,64 do
    for t=0,15 do local j=i+t*4; w[t]=((bytes[j]<<24)|(bytes[j+1]<<16)|(bytes[j+2]<<8)|(bytes[j+3])) & 0xffffffff end
    for t=16,63 do w[t]=(sigma1(w[t-2])+w[t-7]+sigma0(w[t-15])+w[t-16]) & 0xffffffff end
    local a,b,c,d,e,f,g,h=h0,h1,h2,h3,h4,h5,h6,h7
    for t=0,63 do local T1=(h+Sigma1(e)+Ch(e,f,g)+K[t+1]+w[t]) & 0xffffffff; local T2=(Sigma0(a)+Maj(a,b,c)) & 0xffffffff; h=g; g=f; f=e; e=(d+T1)&0xffffffff; d=c; c=b; b=a; a=(T1+T2)&0xffffffff end
    h0=(h0+a)&0xffffffff; h1=(h1+b)&0xffffffff; h2=(h2+c)&0xffffffff; h3=(h3+d)&0xffffffff; h4=(h4+e)&0xffffffff; h5=(h5+f)&0xffffffff; h6=(h6+g)&0xffffffff; h7=(h7+h)&0xffffffff
  end
  local function hex32(x) return string.format('%08x',x) end
  local digest_hex=hex32(h0)..hex32(h1)..hex32(h2)..hex32(h3)..hex32(h4)..hex32(h5)..hex32(h6)..hex32(h7)
  local raw={}; for i=1,#digest_hex,2 do raw[#raw+1]=tonumber(digest_hex:sub(i,i+1),16) end
  local b64chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  local out=''; local i=1
  while i<=#raw do local b1=raw[i]; local b2=raw[i+1]; local b3=raw[i+2]; local n=(b1<<16)|((b2 or 0)<<8)|(b3 or 0); local c1=(n>>18)&63; local c2=(n>>12)&63; local c3=(n>>6)&63; local c4=n&63; out=out..b64chars:sub(c1+1,c1+1)..b64chars:sub(c2+1,c2+1)..(b2 and b64chars:sub(c3+1,c3+1) or '=')..(b3 and b64chars:sub(c4+1,c4+1) or '='); i=i+3 end
  return out
end

-- Assemble header from map (priority first)
function M.assemble_header(map)
  local priority={'default-src','script-src','style-src','img-src','font-src','object-src'}
  local used,parts={},{}
  for _,k in ipairs(priority) do local v=map[k]; if v then parts[#parts+1]=k..' '..table.concat(v,' '); used[k]=true end end
  local remaining={}; for k,_ in pairs(map) do if not used[k] then remaining[#remaining+1]=k end end; table.sort(remaining)
  for _,k in ipairs(remaining) do if k=='upgrade-insecure-requests' or k=='block-all-mixed-content' then parts[#parts+1]=k else parts[#parts+1]=k..' '..table.concat(map[k],' ') end end
  return table.concat(parts,'; ')
end

-- Build CSP from directives + nonce map
function M.build_csp(directives, nonces_by_type)
  local map={ ['default-src']={"'self'"} }
  local script={'"'=='' and '' or ''}; script={'"'=='' and '' or ''} -- placeholder to keep structure; reassign below
  script={"'self'"}
  for _,n in ipairs(nonces_by_type.scripts or {}) do script[#script+1]="'nonce-"..n.."'" end
  if directives['strict-dynamic'] then script[#script+1]="'strict-dynamic'" end
  if directives['unsafe-eval'] then script[#script+1]="'unsafe-eval'" end
  if directives['unsafe-hashes'] then script[#script+1]="'unsafe-hashes'" end
  map['script-src']=script
  local style={"'self'"}
  for _,n in ipairs(nonces_by_type.styles or {}) do style[#style+1]="'nonce-"..n.."'" end
  if directives['inline-styles-required'] then style[#style+1]="'unsafe-inline'" end
  map['style-src']=style
  if directives['style-src-attr-inline'] then map['style-src-attr']={"'self'","'unsafe-inline'"} end
  local function assign_or_default(name,value,default) if value then map[name]={value} else map[name]=default end end
  assign_or_default('img-src', directives['img-src'], {"'self'","data:"})
  assign_or_default('font-src', directives['font-src'], {"'self'"})
  map['object-src']={directives['allow-object'] and "'self'" or "'none'"}
  local function auto_none(name, explicit, auto_flag)
    if explicit then map[name]={explicit} elseif directives[auto_flag] then map[name]={"'self'"} else map[name]={"'none'"} end
  end
  auto_none('media-src', directives['media-src'], 'auto-media-self')
  auto_none('frame-src', directives['frame-src'], 'auto-frame-self')
  auto_none('worker-src', directives['worker-src'], 'auto-worker-self')
  auto_none('manifest-src', directives['manifest-src'], 'auto-manifest-self')
  assign_or_default('connect-src', directives['connect-src'], {"'self'"})
  map['frame-ancestors']={"'self'"}
  if directives['report-to'] then map['report-to']={directives['report-to']} end
  if directives['report-uri'] then map['report-uri']={directives['report-uri']} end
  if directives['trusted-types'] then map['trusted-types']={directives['trusted-types']} end
  if directives['require-trusted-types-for'] then map['require-trusted-types-for']={directives['require-trusted-types-for']} end
  if directives['upgrade-insecure-requests'] then map['upgrade-insecure-requests']={'(flag)'} end
  if directives['block-all-mixed-content'] then map['block-all-mixed-content']={'(flag)'} end
  map['base-uri']={"'self'"}; map['form-action']={"'self'"}
  return M.assemble_header(map), map
end

-- Score CSP
function M.score_csp(csp_string)
  local breakdown={}; local score=100
  local function penalize(cond, pts, label) if cond then score=score-pts; breakdown[label]=-pts else breakdown[label]=0 end end
  penalize(csp_string:match('unsafe%-inline'),12,'unsafe-inline')
  penalize(csp_string:match('unsafe%-eval'),15,'unsafe-eval')
  penalize(csp_string:match('unsafe%-hashes'),8,'unsafe-hashes')
  penalize(not csp_string:match("object%-src 'none'"),8,'object-src-not-none')
  penalize(not csp_string:match("default%-src 'self'"),15,'default-src-missing-self')
  penalize(not csp_string:match("script%-src 'self'"),10,'script-src-missing-self')
  penalize(not csp_string:match('upgrade%-insecure%-requests'),5,'no-upgrade-insecure-requests')
  penalize(not csp_string:match("form%-action 'self'"),5,'form-action-missing-self')
  penalize(not csp_string:match("base%-uri 'self'"),5,'base-uri-missing-self')
  if csp_string:match('strict%-dynamic') and csp_string:match('nonce%-') then breakdown['strict-dynamic-bonus']=5; score=math.min(100,score+5) end
  return score, breakdown
end

M.BASELINE = {
  ['default-src']="'self'", ['script-src']="'self' nonce", ['style-src']="'self' nonce", ['img-src']="'self' data:", ['font-src']="'self'", ['object-src']="'none'", ['media-src']="'none'", ['frame-src']="'none'", ['worker-src']="'none'", ['manifest-src']="'none'", ['connect-src']="'self'", ['frame-ancestors']="'self'", ['base-uri']="'self'", ['form-action']="'self'"
}

M.DETECTIONS = {
  { name='unsafe-eval', pattern='[%c%p%s]eval%s*%(', test=function(content) return content:match('[%c%p%s]eval%s*%(') end, apply=function(d) d['unsafe-eval']=true end, override='script-src' },
  -- inline-events: no longer auto-add unsafe-hashes; we handle via rewrite + post-clean
  { name='inline-events', pattern='<[^>]-on%w+%s*=', test=function(content) return content:match('<[^>]-on%w+%s*=') end, apply=function(d) d.__inline_events_detected=true end, override='script-src' },
  { name='inline-styles', pattern='<[^>]-style%s*=', test=function(content) return content:match('<[^>]-style%s*=') end, apply=function(d) d['inline-styles-required']=true end, override='style-src' },
}

return M
