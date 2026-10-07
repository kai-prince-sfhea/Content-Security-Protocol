local ctx = _G.CSP_CTX
if not ctx then
  -- Fallback: reconstruct minimal context (pre filter may have been skipped in certain pipelines)
  local function file_exists(p) local f=io.open(p,'r'); if f then f:close(); return true end return false end
  local root = os.getenv('QUARTO_PROJECT_ROOT') or '.'
  if root == '.' then
    -- Try to detect project root by locating _quarto.yml up to a few levels
    local candidates={'.','..','../..','../../..'}
    for _,c in ipairs(candidates) do if file_exists(pandoc.path.join({c,'_quarto.yml'})) or file_exists(pandoc.path.join({c,'_quarto.yaml'})) then root=pandoc.path.normalize(c); break end end
  end
  local out = os.getenv('QUARTO_PROJECT_OUTPUT_DIR') or pandoc.path.join({root,'_site'})
  local mathdir = pandoc.path.join({root,'_schema'})
  local CSP = dofile(pandoc.path.join({root,'_extensions','Content-Security-Protocol','CSP.lua'}))
  local Dir = {}
  local df = io.open(pandoc.path.join({mathdir,'Directories.json'}),'r'); if df then local txt=df:read('a'); df:close(); pcall(function() Dir=pandoc.json.decode(txt) end) end
  local Track = {}
  local cf = io.open(pandoc.path.join({mathdir,'CSP.json'}),'r'); if cf then local txt=cf:read('a'); cf:close(); pcall(function() Track=pandoc.json.decode(txt) end) end
  ctx = {
    InputDir=root, OutputDir=out, MathDir=mathdir, CSP=CSP, Dir=Dir, CSPTrack=Track,
    site_union={}, site_intersection={}, file_scores={}, first_file=true,
    SRI_REPORT={ files = {}, remote_candidates = {} }, NONCE_NORMALISE_PATTERN = "'nonce%-[A-Za-z0-9]+'",
    pretty = function(s) return s end,
    fallback_post_init = true
  }
  _G.CSP_CTX = ctx
  io.stderr:write('[CSP] Post filter fallback context initialized (pre stage missing)\n')
end
local CSP = ctx.CSP
local pretty = ctx.pretty or function(s) return s end
-- Prefer CSP.json_encode (introduced in CSP.lua) if available for consistent pretty formatting
local json_encode = (CSP and CSP.json_encode) and CSP.json_encode or function(tbl)
  local raw
  if quarto and quarto.json then raw = quarto.json.encode(tbl) else raw = pandoc.json.encode(tbl) end
  return pretty(raw)
end

-- If no files were processed during filter stage (likely because HTML did not yet exist),
-- perform a full post-render scan now. This allows reliable CSP injection and change tracking.
if #ctx.file_scores == 0 then
  local OutputDir = ctx.OutputDir
  local function scan_html_files()
    local files = {}
    local cmd = 'dir /s /b "'..OutputDir..'\\*.html"'
    local p = io.popen(cmd)
    if p then
      for abs in p:lines() do files[#files+1] = abs end
      p:close()
    end
    return files
  end
  local function rel_from_abs(abs)
    local esc = OutputDir:gsub('([%^%$%(%)%%%.%[%]%*%+%-%?])','%%%1')..'[\\/]'
    return abs:gsub(esc,'')
  end
    local NONCE_NORMALISE_PATTERN = ctx.NONCE_NORMALISE_PATTERN or "'nonce%-[A-Za-z0-9]+'"
    local DETECTIONS = CSP.DETECTIONS
    local Conf = ctx.Config or {}
  local function ensure(list, value) for _,v in ipairs(list) do if v==value then return end end list[#list+1]=value end
  ctx.CSPTrack = ctx.CSPTrack or {}
  for _,abs in ipairs(scan_html_files()) do
    local fh = io.open(abs,'r')
    if fh then
      local content = fh:read('a'); fh:close()
      local rel = rel_from_abs(abs)
      local dir_key = rel:match('^(.*)\\[^\\]+$') or ''
      local file = rel:match('([^\\]+)$')
      ctx.CSPTrack[dir_key] = ctx.CSPTrack[dir_key] or { hashes = {}, report = {}, changed = { html = {} }, files = {} }
      local dirTrack = ctx.CSPTrack[dir_key]
      local oldHash = dirTrack.hashes[file]
      local function content_hash(str) return CSP.sha256(str) end
      local newHash = content_hash(content)
      local changed = (oldHash ~= newHash)
      dirTrack.hashes[file] = newHash
      dirTrack.changed.html[file] = changed
      dirTrack.files[file] = true
      local dir_directives = { ['upgrade-insecure-requests']=true, ['block-all-mixed-content']=true }
      local overrides = {}
      -- Detection
      local has_inline_events = false
      for _,det in ipairs(DETECTIONS) do if det.test(content) then if det.name=='inline-events' then has_inline_events=true end; if not overrides[det.override] then det.apply(dir_directives) end end end
      -- Rewrite inline events
      if has_inline_events and not overrides['preserve-inline-events'] then
        local injections, idx = {}, 0
        content = content:gsub("<([%w%-]+)([^>]-)on(%a[%w%-]*)%s*=(['\"])()", function(tag, attrs, evt, q, js)
          local allowed={click=true,load=true,submit=true,change=true,input=true,keydown=true,keyup=true,keypress=true,mouseover=true,mouseout=true,mouseenter=true,mouseleave=true,mousedown=true,mouseup=true,contextmenu=true,focus=true,blur=true,dragstart=true,dragover=true,drop=true,touchstart=true,touchend=true,touchmove=true,touchcancel=true}
          evt = evt:lower(); if not allowed[evt] then return nil end
          idx=idx+1; local marker='data-csp-evt-'..idx
          local cleaned=attrs:gsub('on'..evt.."%s*=(['\"])()",' ')
          injections[#injections+1]={marker=marker,evt=evt,body=js}
          return string.format('<%s%s %s="1"', tag, cleaned, marker)
        end)
        if #injections>0 and content:match('</body>') then
          local out={'(function(){'}
          for _,h in ipairs(injections) do out[#out+1]=string.format("var el=document.querySelector('[%s]'); if(el){el.removeAttribute('%s'); el.addEventListener('%s', function(event){%s});}",h.marker,h.marker,h.evt,h.body) end
          out[#out+1]='})();'
          content = content:gsub('</body>', '<script>'..table.concat(out)..'</script></body>')
          has_inline_events = false
        end
      end
      local nonces_by_type = { scripts = {}, styles = {} }
      local hash_only = dir_directives['hash-only-csp'] or false
      local hash_inline = dir_directives['hash-inline'] or overrides['hash-inline']
      content = content:gsub('<script(.-)>(.-)</script>', function(attrs, body)
        if attrs:match('src=') then return '<script'..attrs..'>'..body..'</script>' end
        if not hash_only then local n=CSP.random_nonce(); nonces_by_type.scripts[#nonces_by_type.scripts+1]=n; if not attrs:match('nonce=') then attrs=attrs.." nonce='"..n.."'" end end
        if hash_inline then local digest=CSP.sha256(body); dir_directives.__script_hashes=dir_directives.__script_hashes or {}; dir_directives.__script_hashes[#dir_directives.__script_hashes+1]="'sha256-"..digest.."'" end
        return '<script'..attrs..'>'..body..'</script>'
      end)
      content = content:gsub('<style(.-)>(.-)</style>', function(attrs, body)
        if not hash_only then local n=CSP.random_nonce(); nonces_by_type.styles[#nonces_by_type.styles+1]=n; if not attrs:match('nonce=') then attrs=attrs.." nonce='"..n.."'" end end
        if hash_inline then local digest=CSP.sha256(body); dir_directives.__style_hashes=dir_directives.__style_hashes or {}; dir_directives.__style_hashes[#dir_directives.__style_hashes+1]="'sha256-"..digest.."'" end
        return '<style'..attrs..'>'..body..'</style>'
      end)
      if not overrides['preserve-inline-events'] then if not content:match('<[^>]-on%w+%s*=') then dir_directives['unsafe-hashes']=false end end
      -- Heuristics
      if content:match('tippy%.umd') or content:match('popper%.min') then dir_directives['style-src-attr-inline']=true end
  local mathjax_usage = content:match('[Mm]athjax%-config%.js') or content:match('window%.MathJax') or content:match('cdn%.jsdelivr%.net')
  if mathjax_usage then dir_directives['allow-cdn-jsdelivr']=true end
  if content:match('cdnjs%.cloudflare%.com') then dir_directives['allow-cdn-cdnjs']=true end
      dir_directives['upgrade-insecure-requests']=true; dir_directives['block-all-mixed-content']=true
      local csp_header, directive_map = CSP.build_csp(dir_directives, nonces_by_type)
      if dir_directives.__script_hashes then for _,h in ipairs(dir_directives.__script_hashes) do directive_map['script-src'][#directive_map['script-src']+1]=h end end
      if dir_directives.__style_hashes then for _,h in ipairs(dir_directives.__style_hashes) do directive_map['style-src'][#directive_map['style-src']+1]=h end end
      if dir_directives.__script_hashes or dir_directives.__style_hashes then csp_header = CSP.assemble_header(directive_map) end
      -- Websocket dev allowance detection
      if Conf.dev_allow_ws then
        ensure(directive_map['connect-src'], "ws://127.0.0.1:*")
        ensure(directive_map['connect-src'], "ws://localhost:*")
      end
      -- External host allowances
      if not directive_map['font-src'] then directive_map['font-src']={"'self'"} end
  if Conf.allow_jsdelivr ~= false then
        ensure(directive_map['script-src'], 'https://cdn.jsdelivr.net')
        ensure(directive_map['font-src'], 'https://cdn.jsdelivr.net')
      end
      if Conf.allow_cdnjs or dir_directives['allow-cdn-cdnjs'] then
        ensure(directive_map['script-src'],'https://cdnjs.cloudflare.com')
      end
      if Conf.allow_google_fonts ~= false then
        ensure(directive_map['style-src'], 'https://fonts.googleapis.com')
        ensure(directive_map['font-src'], 'https://fonts.gstatic.com')
      end
      ensure(directive_map['font-src'],'data:')
      for _,h in ipairs(Conf.additional_script_src or {}) do ensure(directive_map['script-src'], h) end
      for _,h in ipairs(Conf.additional_style_src or {}) do ensure(directive_map['style-src'], h) end
      -- Ensure connect-src initialized to self if absent so we can append ws endpoints
      if not directive_map['connect-src'] then directive_map['connect-src']={"'self'"} end
      if directive_map['connect-src'] then for _,h in ipairs(Conf.additional_connect_src or {}) do ensure(directive_map['connect-src'], h) end end
      if Conf.enable_trusted_types then
        local policies = Conf.trusted_types_policies or {}
        local policy_str = (#policies>0) and table.concat(policies,' ') or "'none'"
        directive_map['trusted-types']={policy_str}
        if Conf.require_trusted_types_for_script then directive_map['require-trusted-types-for']={'script'} end
      end
      if Conf.auto_strict_dynamic then
        local sc = directive_map['script-src'] or {}
        local has_nonce=false; local has_sd=false
        for _,v in ipairs(sc) do if v:match("^'nonce%-") then has_nonce=true elseif v=="'strict-dynamic'" then has_sd=true end end
        if has_nonce and not has_sd then sc[#sc+1]="'strict-dynamic'" end
      end
      -- Ensure style-src-attr exists; if retain_style_inline_dynamic, force unsafe-inline for runtime adjustments
  -- meta_map will be rebuilt below; defer style-src-attr add until after meta_map created
  if mathjax_usage and not directive_map['worker-src'] then directive_map['worker-src']={"'self'","blob:"}; csp_header=CSP.assemble_header(directive_map) end
  if dir_directives['unsafe-hashes']==false or Conf.force_remove_unsafe_hashes then local list=directive_map['script-src'] or {}; for i=#list,1,-1 do if list[i]=="'unsafe-hashes'" then table.remove(list,i) end end; csp_header=CSP.assemble_header(directive_map) end
  if hash_only then for _,lst in pairs(directive_map) do for i=#lst,1,-1 do if lst[i]:match("^'nonce%-") then table.remove(lst,i) end end end; csp_header=CSP.assemble_header(directive_map) end
  if Conf.disable_sri then dir_directives['disable-sri']=true end
      local score, breakdown = CSP.score_csp(csp_header)
      ctx.file_scores[#ctx.file_scores+1] = { file = (dir_key=='' and file or (dir_key..'/'..file)), score = score }
      for d,arr in pairs(directive_map) do
        local values={}; for _,v in ipairs(arr) do values[#values+1]=v:gsub(NONCE_NORMALISE_PATTERN, "'nonce'") end
        ctx.site_union[d]=ctx.site_union[d] or {}; for _,v in ipairs(values) do ctx.site_union[d][v]=true end
        if ctx.first_file then ctx.site_intersection[d]={}; for _,v in ipairs(values) do ctx.site_intersection[d][v]=true end else local current=ctx.site_intersection[d]; if current then for existing,_ in pairs(current) do local keep=false; for _,v in ipairs(values) do if v==existing then keep=true break end end; if not keep then current[existing]=nil end end end end
      end
      ctx.first_file=false
      -- Inject meta tag (strip frame-ancestors) if not already there
      local meta_map = {}
      if Conf.retain_style_inline_dynamic and not directive_map['style-src-attr'] then
        directive_map['style-src-attr']={"'self'","'unsafe-inline'"}
      end
  for d,v in pairs(directive_map) do if d~='frame-ancestors' then meta_map[d]={table.unpack(v)} end end
      -- Re-run strict-dynamic enforcement after any script-src changes above
      if Conf.auto_strict_dynamic then
        local sc = directive_map['script-src'] or {}
        local has_nonce=false; local has_sd=false
        for _,v in ipairs(sc) do if v:match("^'nonce%-") then has_nonce=true elseif v=="'strict-dynamic'" then has_sd=true end end
        if has_nonce and not has_sd then sc[#sc+1]="'strict-dynamic'" end
      end
      -- Inline style attribute remediation
      if content:match('style="[^"]+"') and not dir_directives['inline-styles-required'] then
        local style_rules = {}
        local idx=0
        local function esc_css(s) return (s:gsub('[\n\r]',' ')) end
        content = content:gsub('(<[%w:%-]+)([^>]-)style="([^"]+)"', function(start, attrs, css)
          idx=idx+1
            local cls='csp-i'..idx
            style_rules[#style_rules+1]='.'..cls..'{'..esc_css(css)..'}'
            if attrs:match('class=') then
              attrs=attrs:gsub('class="([^"]*)"','class="%1 '..cls..'"')
            else
              attrs=attrs..' class="'..cls..'"'
            end
            return start..attrs
        end)
        if #style_rules>0 then
          local style_nonce
          for _,v in ipairs(directive_map['style-src'] or {}) do local n=v:match("'nonce%-([A-Za-z0-9]+)'"); if n then style_nonce=n break end end
          if not style_nonce then
            style_nonce = CSP.random_nonce()
            ensure(directive_map['style-src'],"'nonce-"..style_nonce.."'")
          end
          local injected = '<style nonce="'..style_nonce..'">'..table.concat(style_rules,'')..'</style>'
          content = content:gsub('</head>', injected.."\n</head>")
          meta_map = {}; for d,v in pairs(directive_map) do if d~='frame-ancestors' then meta_map[d]={table.unpack(v)} end end
        end
      end
      -- Remove 'unsafe-inline' from style-src-attr if we supplied a nonce and remediated inline styles
      if directive_map['style-src-attr'] then
        local has_nonce=false
        for _,v in ipairs(directive_map['style-src'] or {}) do if v:match("'nonce%-") then has_nonce=true break end end
        if has_nonce and not Conf.retain_style_inline_dynamic then
          local cleaned={}
          for _,v in ipairs(directive_map['style-src-attr']) do if v~="'unsafe-inline'" then cleaned[#cleaned+1]=v end end
          if #cleaned>0 then directive_map['style-src-attr']=cleaned end
          meta_map['style-src-attr']=cleaned
        elseif Conf.retain_style_inline_dynamic then
          local has_unsafe=false
          for _,v in ipairs(directive_map['style-src-attr']) do if v=="'unsafe-inline'" then has_unsafe=true break end end
          if not has_unsafe then directive_map['style-src-attr'][#directive_map['style-src-attr']+1]="'unsafe-inline'" end
          meta_map['style-src-attr']={table.unpack(directive_map['style-src-attr'])}
        end
      end
      local meta_csp = CSP.assemble_header(meta_map)
      if content:match('<meta[^>]-http%-equiv="Content%-Security%-Policy"') then
        content = content:gsub('<meta[^>]-http%-equiv="Content%-Security%-Policy".-/>','<meta http-equiv="Content-Security-Policy" content="'..meta_csp..'" />')
      else
        content = content:gsub('<head>','<head>\n<meta http-equiv="Content-Security-Policy" content="'..meta_csp..'" />')
      end
      local wf = io.open(abs,'w'); if wf then wf:write(content); wf:close() end
      dirTrack.report[file] = { header=csp_header, score=score, breakdown=breakdown, directives=directive_map, baseline=CSP.BASELINE, hash_only=hash_only }
    end
  end
end

local function set_to_array(set) local arr={} for v,_ in pairs(set) do arr[#arr+1]=v end table.sort(arr) return arr end

local file_scores = ctx.file_scores; table.sort(file_scores,function(a,b) return a.score < b.score end)
local site_summary = { union = {}, intersection = {}, worst = {}, recommended_header = nil, warnings = {} }
for d,set in pairs(ctx.site_union) do site_summary.union[d]=set_to_array(set) end
for d,set in pairs(ctx.site_intersection) do site_summary.intersection[d]=set_to_array(set) end
for _,entry in ipairs(file_scores) do site_summary.worst[#site_summary.worst+1]=entry end
local intersection_map = {}
for d,arr in pairs(site_summary.intersection) do if #arr==0 then site_summary.warnings[#site_summary.warnings+1]='Empty intersection for '..d else intersection_map[d]=arr end end
if next(intersection_map) then
  local priority={'default-src','script-src','style-src','img-src','font-src','object-src'}
  local used,parts={},{}
  for _,k in ipairs(priority) do if intersection_map[k] then parts[#parts+1]=k..' '..table.concat(intersection_map[k],' '); used[k]=true end end
  local remaining={}; for k,_ in pairs(intersection_map) do if not used[k] then remaining[#remaining+1]=k end end; table.sort(remaining)
  for _,k in ipairs(remaining) do if k=='upgrade-insecure-requests' or k=='block-all-mixed-content' then parts[#parts+1]=k else parts[#parts+1]=k..' '..table.concat(intersection_map[k],' ') end end
  site_summary.recommended_header = table.concat(parts,'; ')
end
-- SRI summary
local local_sri_count=0; for _ in pairs(ctx.SRI_REPORT.files) do local_sri_count=local_sri_count+1 end
local remote_list={}; for k,_ in pairs(ctx.SRI_REPORT.remote_candidates) do remote_list[#remote_list+1]=k end; table.sort(remote_list)
site_summary.sri={ local_assets=local_sri_count, remote_candidates=remote_list }
ctx.CSPTrack = ctx.CSPTrack or {}
ctx.CSPTrack['csp_default'] = { baseline = CSP.BASELINE, site = site_summary }
-- Persist JSON
-- Write CSP.json at project root
local csp_json_path = pandoc.path.join({ctx.InputDir,'CSP.json'})
local f = io.open(csp_json_path,'w'); if f then f:write(json_encode(ctx.CSPTrack)); f:close() end
-- SRI report
local local_files={}; for path,data in pairs(ctx.SRI_REPORT.files) do local_files[#local_files+1]={ file=path, integrity=data.integrity, rel=data.rel, tag=data.tag } end
table.sort(local_files,function(a,b) return a.rel < b.rel end)
local sri_json={ local_files=local_files, remote_candidates=remote_list }
-- Keep SRI report under _schema for now (could also relocate if desired)
local sf=io.open(pandoc.path.join({ctx.MathDir,'sri-report.json'}),'w'); if sf then sf:write(json_encode(sri_json)); sf:close() end
-- headers.txt
local hf=io.open(pandoc.path.join({ctx.OutputDir,'headers.txt'}),'w')
if hf then hf:write('# Suggested Security Headers\n'); hf:write('Content-Security-Policy: '..(site_summary.recommended_header or 'N/A')..'\n'); hf:write('Referrer-Policy: no-referrer\n'); hf:write('X-Content-Type-Options: nosniff\n'); hf:write('X-Frame-Options: SAMEORIGIN\n'); hf:write('Permissions-Policy: accelerometer=(), camera=(), geolocation=(), microphone=()\n'); hf:write('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n'); hf:close() end
print('CSP Score Summary (lowest first):')
local worst_count = math.min(10,#file_scores)
local total, min_score, max_score = 0, 101, -1
local penalty_totals = {}
for i,entry in ipairs(file_scores) do
  total = total + entry.score
  if entry.score < min_score then min_score = entry.score end
  if entry.score > max_score then max_score = entry.score end
end
for i=1, worst_count do
  local e = file_scores[i]
  -- Locate breakdown from ctx.CSPTrack
  local dir, fname = e.file:match('^(.*)/([^/]+)$')
  dir = dir or ''
  local breakdown
  if ctx.CSPTrack and ctx.CSPTrack[dir] and ctx.CSPTrack[dir].report and ctx.CSPTrack[dir].report[fname] then
    breakdown = ctx.CSPTrack[dir].report[fname].breakdown
  end
  local penalty_fragments = {}
  if breakdown then
    for label,delta in pairs(breakdown) do
      if delta < 0 then
        penalty_fragments[#penalty_fragments+1] = label..'('..delta..')'
        penalty_totals[label] = (penalty_totals[label] or 0) + 1
      elseif label == 'strict-dynamic-bonus' then
        penalty_fragments[#penalty_fragments+1] = label..'(+5)'
      end
    end
  end
  table.sort(penalty_fragments)
  print(string.format('  %2d. %-40s %3d  %s', i, e.file, e.score, table.concat(penalty_fragments, ' ')))
end
local avg = (#file_scores>0) and (total / #file_scores) or 0
print(string.format('Overall CSP Score Stats: pages=%d min=%d max=%d avg=%.1f', #file_scores, min_score==101 and 0 or min_score, max_score, avg))
if next(penalty_totals) then
  local labels = {}
  for k,_ in pairs(penalty_totals) do labels[#labels+1]=k end
  table.sort(labels)
  print('Penalty occurrence counts:')
  for _,k in ipairs(labels) do print(string.format('  %-30s %d', k, penalty_totals[k])) end
end
print('Content-Security-Protocol extension complete')
return { { Pandoc = function(doc) return doc end } }
