local ctx = _G.CSP_CTX or error('CSP_CTX missing (pre filter must run)')
local CSP = ctx.CSP
local Conf = ctx.Config or {}

-- Helper
local function ensure(list, value) for _,v in ipairs(list) do if v==value then return end end list[#list+1]=value end

-- Fallback changed file detection: if Dir empty or no ChangedFiles, scan _site
local function list_site_html()
  -- Returns mapping: dir_key -> { files = {file1, file2,...}} where dir_key '' is root
  local site_root = ctx.OutputDir or (ctx.InputDir..'/_site')
  local map = {}
  local pattern = site_root .. '\\*.html'
  local esc_root = site_root:gsub('([%^%$%(%)%%%.%[%]%*%+%-%?])','%%%1') .. '[\\/]'
  local cmd = 'dir /s /b "'..pattern..'"'
  local p = io.popen(cmd)
  if p then
    for abs in p:lines() do
      -- Ensure .html
      if abs:match('%.html$') then
        local rel = abs:gsub(esc_root,'')
        local dir_key = rel:match('^(.*)\\[^\\]+$') or ''
        map[dir_key] = map[dir_key] or { files = {} }
        table.insert(map[dir_key].files, rel:match('[^\\]+$'))
      end
    end
    p:close()
  end
  return map
end

-- Simple content hash (reuse sha256 to keep consistency)
local function content_hash(str)
  return CSP.sha256(str)
end

local function process_directory(dir_key, dir_meta, stats)
  local OutputDir = ctx.OutputDir
  local RenderDir = pandoc.path.join({OutputDir, dir_key})
  local changed_html = (dir_meta.ChangedFiles and dir_meta.ChangedFiles.html) or {}
  local csp_info = dir_meta.CSP
  local tracking = ctx.CSPTrack[dir_key]
  -- Process even if no explicit CSP metadata so we can still generate site summary
  if not (csp_info or tracking) then
    csp_info = { directives = { ['upgrade-insecure-requests']=true, ['block-all-mixed-content']=true }, overrides = {}, files = changed_html }
  end
  local dir_directives = (csp_info and csp_info.directives) or {}
  local overrides = (csp_info and csp_info.overrides) or {}
  local report_only = dir_directives['report-only'] or false
  -- If there are no changed_html entries, scan this directory for html files (initial/full build)
  if next(changed_html) == nil then
    local scan_cmd = 'dir /b "'..RenderDir..'"'
    local p = io.popen(scan_cmd)
    if p then
      for name in p:lines() do
        if name:match('%.html$') then changed_html[name] = true end
      end
      p:close()
    end
  end
  for file,_ in pairs(changed_html) do
    if (csp_info and csp_info.files and csp_info.files[file]) or (tracking and tracking.files and tracking.files[file]) then
      local filepath = pandoc.path.join({RenderDir,file})
      local fh = io.open(filepath,'r')
      if fh then
        local content = fh:read('a'); fh:close()
        -- Track file content hash & detect changes compared to previous run
        ctx.CSPTrack[dir_key] = ctx.CSPTrack[dir_key] or { files = {}, hashes = {}, report = {} }
        local dirTrack = ctx.CSPTrack[dir_key]
        dirTrack.hashes = dirTrack.hashes or {}
        local newHash = content_hash(content)
        local oldHash = dirTrack.hashes[file]
        local fileChanged = (oldHash ~= newHash)
        dirTrack.hashes[file] = newHash
        -- Maintain a ChangedFiles-style table for this directory under CSP tracking
        dirTrack.changed = dirTrack.changed or { html = {} }
        dirTrack.changed.html[file] = fileChanged
        local nonces_by_type = { scripts = {}, styles = {} }
        -- Prefer hashes configuration
        if (Conf.prefer_hashes or Conf.prefer_hashes_strict) and not overrides['disable-prefer-hashes'] then
          dir_directives['hash-inline'] = true
          if Conf.prefer_hashes_strict then dir_directives['hash-only-csp'] = true end
        end
        local hash_only = dir_directives['hash-only-csp'] or false
        local has_inline_events = false
        for _,det in ipairs(CSP.DETECTIONS) do
          if det.test(content) then
            if det.name=='inline-events' then has_inline_events=true end
            if not overrides[det.override] then det.apply(dir_directives) end
          end
        end
        if has_inline_events and not overrides['preserve-inline-events'] then
          local injections, idx = {}, 0
          content = content:gsub("<([%w%-]+)([^>]-)on(%a[%w%-]*)%s*=(['\"])()", function(tag, attrs, evt, q, js)
            local allowed={click=true,load=true,submit=true,change=true,input=true,keydown=true,keyup=true,keypress=true,mouseover=true,mouseout=true,mouseenter=true,mouseleave=true,mousedown=true,mouseup=true,contextmenu=true,focus=true,blur=true,dragstart=true,dragover=true,drop=true,touchstart=true,touchend=true,touchmove=true,touchcancel=true}
            evt=evt:lower(); if not allowed[evt] then return nil end
            idx=idx+1; local marker='data-csp-evt-'..idx; local cleaned=attrs:gsub('on'..evt.."%s*=(['\"])()",' ')
            injections[#injections+1]={marker=marker,evt=evt,body=js}; return string.format('<%s%s %s=\'1\'',tag,cleaned,marker)
          end)
          if #injections>0 and content:match('</body>') then
            local out={'(function(){'}
            for _,h in ipairs(injections) do out[#out+1]=string.format("var el=document.querySelector('[%s]'); if(el){el.removeAttribute('%s'); el.addEventListener('%s', function(event){%s});}",h.marker,h.marker,h.evt,h.body) end
            out[#out+1]='})();'; content=content:gsub('</body>','<script>'..table.concat(out)..'</script></body>')
            has_inline_events=false
          end
        end
  local hash_inline = dir_directives['hash-inline'] or overrides['hash-inline']
        content = content:gsub('<script(.-)>(.-)</script>', function(attrs, body)
          if attrs:match('src=') then return '<script'..attrs..'>'..body..'</script>' end
          if not hash_only then local n=CSP.random_nonce(); nonces_by_type.scripts[#nonces_by_type.scripts+1]=n; if not attrs:match('nonce=') then attrs=attrs.." nonce='"..n.."'" end end
          if hash_inline then local digest=CSP.sha256(body); dir_directives.__script_hashes=dir_directives.__script_hashes or {}; dir_directives.__script_hashes[#dir_directives.__script_hashes+1]="'sha256-"..digest.."'" end
          return '<script'..attrs..'>'..body..'</script>' end)
        content = content:gsub('<style(.-)>(.-)</style>', function(attrs, body)
          if not hash_only then local n=CSP.random_nonce(); nonces_by_type.styles[#nonces_by_type.styles+1]=n; if not attrs:match('nonce=') then attrs=attrs.." nonce='"..n.."'" end end
          if hash_inline then local digest=CSP.sha256(body); dir_directives.__style_hashes=dir_directives.__style_hashes or {}; dir_directives.__style_hashes[#dir_directives.__style_hashes+1]="'sha256-"..digest.."'" end
          return '<style'..attrs..'>'..body..'</style>' end)
        if not overrides['preserve-inline-events'] then if not content:match('<[^>]-on%w+%s*=') then dir_directives['unsafe-hashes']=false end end
        local dynamic_style_nonce=nil; if not hash_only then dynamic_style_nonce=CSP.random_nonce(); nonces_by_type.styles[#nonces_by_type.styles+1]=dynamic_style_nonce end
        local media_detected = content:match('<%s*audio') or content:match('<%s*video')
        local frame_detected = content:match('<%s*iframe') or content:match('<%s*frame')
        local worker_detected = content:match('new%s+Worker%(')
        local manifest_detected = content:match('rel="manifest"')
        if overrides['media-src'] then dir_directives['media-src']=overrides['media-src'] elseif media_detected then dir_directives['auto-media-self']=true end
        if overrides['frame-src'] then dir_directives['frame-src']=overrides['frame-src'] elseif frame_detected then dir_directives['auto-frame-self']=true end
        if overrides['worker-src'] then dir_directives['worker-src']=overrides['worker-src'] elseif worker_detected then dir_directives['auto-worker-self']=true end
        if overrides['manifest-src'] then dir_directives['manifest-src']=overrides['manifest-src'] elseif manifest_detected then dir_directives['auto-manifest-self']=true end
        if overrides['style-src'] then dir_directives['inline-styles-required']=false end
        dir_directives['upgrade-insecure-requests']=true; dir_directives['block-all-mixed-content']=true
        local mathjax_usage = (dir_meta.RenderMathJax == true) or content:match('[Mm]athjax%-config%.js') or content:match('window%.MathJax') or content:match('cdn%.jsdelivr%.net')
  if mathjax_usage then dir_directives['allow-cdn-jsdelivr']=true end
  -- Detect cdnjs polyfill / mathjax usage and mark for allowance
  if content:match('cdnjs%.cloudflare%.com') then dir_directives['allow-cdn-cdnjs']=true end
        if (content:match('tippy%.umd') or content:match('popper%.min')) and not overrides['style-src'] then dir_directives['style-src-attr-inline']=true end
  local csp_header, directive_map = CSP.build_csp(dir_directives, nonces_by_type)
        local function add_sri(tag)
          local pattern = tag=='script' and "<script([^>]-)src=['\"][^:'\"]-['\"]([^>]*)>" or "<link([^>]-)href=['\"][^:'\"]-['\"]([^>]*)>"
          content = content:gsub(pattern,function(pre,post)
            if dir_directives['disable-sri'] or overrides['disable-sri'] then return nil end
            local full=pre..post; if full:match('integrity=') then return nil end
            local path = full:match(tag=='script' and "src=['\"]([^'\"]+)" or "href=['\"]([^'\"]+)")
            if not path or path:match('^https?://') or path:match('^//') then return nil end
            local physical
            if path:sub(1,1)=='/' then physical=pandoc.path.join({ctx.OutputDir,path:sub(2)}) else physical=pandoc.path.join({RenderDir,path}) end
            local f2=io.open(physical,'rb'); if not f2 then return nil end; local bytes=f2:read('a'); f2:close()
            local digest=CSP.sha256(bytes); local integrity='sha256-'..digest
            ctx.SRI_REPORT.files[physical]={ integrity=integrity, rel=path, tag=tag }
            if tag=='script' then return string.format('<script%ssrc="%s"%s integrity="%s" crossorigin="anonymous">',pre,path,post,integrity) else return string.format('<link%shref="%s"%s integrity="%s" crossorigin="anonymous">',pre,path,post,integrity) end
          end)
        end
        add_sri('script'); add_sri('link')
        for s in content:gmatch('<script[^>]-src=["\"](https?://[^"\']+)["\"]') do ctx.SRI_REPORT.remote_candidates[s]=true end
        for l in content:gmatch('<link[^>]-href=["\"](https?://[^"\']+)["\"]') do ctx.SRI_REPORT.remote_candidates[l]=true end
        -- Host allowance toggles
        if not directive_map['font-src'] then directive_map['font-src']={"'self'"} end
        if Conf.allow_jsdelivr then
          ensure(directive_map['script-src'], 'https://cdn.jsdelivr.net')
          ensure(directive_map['font-src'], 'https://cdn.jsdelivr.net')
        end
        if Conf.allow_cdnjs or dir_directives['allow-cdn-cdnjs'] then
          ensure(directive_map['script-src'],'https://cdnjs.cloudflare.com')
        end
        if Conf.allow_google_fonts then
          ensure(directive_map['style-src'], 'https://fonts.googleapis.com')
          ensure(directive_map['font-src'], 'https://fonts.gstatic.com')
        end
        if not directive_map['font-src'] then directive_map['font-src']={"'self'"} end
        ensure(directive_map['font-src'],'data:')
        -- Additional user-specified hosts
        for _,h in ipairs(Conf.additional_script_src or {}) do ensure(directive_map['script-src'], h) end
        for _,h in ipairs(Conf.additional_style_src or {}) do ensure(directive_map['style-src'], h) end
        if directive_map['connect-src'] then
          for _,h in ipairs(Conf.additional_connect_src or {}) do ensure(directive_map['connect-src'], h) end
        end
        -- Trusted Types directives
        if Conf.enable_trusted_types then
          local policies = Conf.trusted_types_policies or {}
          local policy_str = (#policies>0) and table.concat(policies, ' ') or "'none'"
          directive_map['trusted-types'] = { policy_str }
          if Conf.require_trusted_types_for_script then
            directive_map['require-trusted-types-for'] = { 'script' }
          end
        end
        -- Auto strict-dynamic
        -- Always enable strict-dynamic if a nonce present (default on in config)
        if Conf.auto_strict_dynamic then
          local sc = directive_map['script-src'] or {}
          local has_nonce=false; local has_strict=false
          for _,v in ipairs(sc) do if v:match("^'nonce%-") then has_nonce=true elseif v=="'strict-dynamic'" then has_strict=true end end
          if has_nonce and not has_strict then sc[#sc+1]="'strict-dynamic'" end
        end
        if not directive_map['connect-src'] then directive_map['connect-src']={"'self'"} end
        -- Always allow localhost websockets when dev_allow_ws true (no detection needed)
        if Conf.dev_allow_ws then
          ensure(directive_map['connect-src'],'ws://127.0.0.1:*')
          ensure(directive_map['connect-src'],'ws://localhost:*')
        end
        if mathjax_usage then ensure(directive_map['connect-src'],'https://cdn.jsdelivr.net') end
        csp_header = CSP.assemble_header(directive_map)
        if dir_directives.__script_hashes then for _,h in ipairs(dir_directives.__script_hashes) do directive_map['script-src'][#directive_map['script-src']+1]=h end end
        if dir_directives.__style_hashes then for _,h in ipairs(dir_directives.__style_hashes) do directive_map['style-src'][#directive_map['style-src']+1]=h end end
        if dir_directives.__script_hashes or dir_directives.__style_hashes then csp_header = CSP.assemble_header(directive_map) end
        if mathjax_usage and not overrides['worker-src'] then directive_map['worker-src']={"'self'","blob:"}; csp_header=CSP.assemble_header(directive_map) end
        if (dir_directives['worker-no-blob'] or overrides['worker-no-blob']) and directive_map['worker-src'] then local ws=directive_map['worker-src']; for i=#ws,1,-1 do if ws[i]=='blob:' then table.remove(ws,i) end end; csp_header=CSP.assemble_header(directive_map) end
        if dir_directives['unsafe-hashes']==false or Conf.force_remove_unsafe_hashes then
          local list=directive_map['script-src'] or {}; for i=#list,1,-1 do if list[i]=="'unsafe-hashes'" then table.remove(list,i) end end; csp_header=CSP.assemble_header(directive_map)
        else
          if not content:match('<[^>]-on%w+%s*=') and Conf.force_remove_unsafe_hashes then
            local list=directive_map['script-src'] or {}; for i=#list,1,-1 do if list[i]=="'unsafe-hashes'" then table.remove(list,i) end end; csp_header=CSP.assemble_header(directive_map)
          end
          if (not overrides['force-unsafe-hashes']) and (not overrides['preserve-inline-events']) and Conf.force_remove_unsafe_hashes then
            local list=directive_map['script-src'] or {}; for i=#list,1,-1 do if list[i]=="'unsafe-hashes'" then table.remove(list,i) end end; csp_header=CSP.assemble_header(directive_map)
          end
        end
        if hash_only then
          for _,lst in pairs(directive_map) do for i=#lst,1,-1 do if lst[i]:match("^'nonce%-") then table.remove(lst,i) end end end
          csp_header=CSP.assemble_header(directive_map)
        end
        -- Sanitize script-src: remove data: and 'unsafe-inline'
        if directive_map['script-src'] then
          local changed=false
          for i=#directive_map['script-src'],1,-1 do
            local v=directive_map['script-src'][i]
            if v=='data:' or v=="'unsafe-inline'" then table.remove(directive_map['script-src'],i); changed=true end
          end
          if changed then csp_header=CSP.assemble_header(directive_map) end
        end
        -- Enforce object-src 'none'
        if directive_map['object-src'] then
          local enforce={'\'none\''}
          directive_map['object-src']={"'none'"}
          csp_header=CSP.assemble_header(directive_map)
        end
  -- Apply SRI disable flag after potential modifications
  if Conf.disable_sri then dir_directives['disable-sri'] = true end
        local score, breakdown = CSP.score_csp(csp_header)
        ctx.file_scores[#ctx.file_scores+1] = { file = pandoc.path.join({dir_key,file}), score = score }
        for d,arr in pairs(directive_map) do
          local values={}; for _,v in ipairs(arr) do values[#values+1]=v:gsub(ctx.NONCE_NORMALISE_PATTERN, "'nonce'") end
          ctx.site_union[d]=ctx.site_union[d] or {}; for _,v in ipairs(values) do ctx.site_union[d][v]=true end
          if ctx.first_file then ctx.site_intersection[d]={}; for _,v in ipairs(values) do ctx.site_intersection[d][v]=true end else local current=ctx.site_intersection[d]; if current then for existing,_ in pairs(current) do local keep=false; for _,v in ipairs(values) do if v==existing then keep=true break end end; if not keep then current[existing]=nil end end end end
        end
        ctx.first_file=false
        local meta_tag_name = report_only and 'Content-Security-Policy-Report-Only' or 'Content-Security-Policy'
        local meta_map={}; for d,v in pairs(directive_map) do if d~='frame-ancestors' then meta_map[d]={table.unpack(v)} end end
        -- Inline style attribute remediation: convert style="..." to class + nonce style block (no unsafe-inline needed)
        if content:match('style="[^"]+"') and not (dir_directives['inline-styles-required']) then
          local style_block = {}
          local used = {}
          local function css_escape(s) return (s:gsub('[\n\r]',' ')) end
          local idx=0
          content = content:gsub('(<[%w:%-]+)([^>]-)style="([^"]+)"', function(start, attrs, css)
            idx=idx+1
            local cls='csp-i'..idx
            style_block[#style_block+1]='.'..cls..'{'..css_escape(css)..'}'
            if attrs:match('class=') then
              attrs = attrs:gsub('class="([^"]*)"','class="%1 '..cls..'"')
            else
              attrs = attrs..' class="'..cls..'"'
            end
            return start..attrs
          end)
          if #style_block>0 then
            local nonce_style
            if directive_map['style-src'] then
              for _,v in ipairs(directive_map['style-src']) do local n=v:match("'nonce%-([A-Za-z0-9]+)'") if n then nonce_style=n break end end
            end
            if not nonce_style then
              local new_nonce=CSP.random_nonce()
              ensure(directive_map['style-src'],"'nonce-"..new_nonce.."'")
              nonce_style=new_nonce
            end
            local inject = '<style nonce="'..nonce_style..'">'..table.concat(style_block,'')..'</style>'
            content = content:gsub('</head>', inject..'\n</head>')
            meta_map = {}; for d,v in pairs(directive_map) do if d~='frame-ancestors' then meta_map[d]={table.unpack(v)} end end
          end
        end
        -- If dynamic inline styles at runtime are required, optionally retain 'unsafe-inline' for style-src-attr
        if Conf.retain_style_inline_dynamic then
          directive_map['style-src-attr'] = directive_map['style-src-attr'] or {"'self'"}
          local has_unsafe=false
          for _,v in ipairs(directive_map['style-src-attr']) do if v=="'unsafe-inline'" then has_unsafe=true break end end
          if not has_unsafe then directive_map['style-src-attr'][#directive_map['style-src-attr']+1] = "'unsafe-inline'" end
          meta_map['style-src-attr'] = {table.unpack(directive_map['style-src-attr'])}
        end
        local meta_csp = CSP.assemble_header(meta_map)
        local breakdown_json = pandoc.json.encode({score=score, breakdown=breakdown})
        if content:match('<meta[^>]-http%-equiv="'..meta_tag_name..'"') then content=content:gsub('<meta[^>]-http%-equiv="'..meta_tag_name..'".-/>','<meta http-equiv="'..meta_tag_name..'" content="'..meta_csp..'" />') else content=content:gsub('<head>','<head>\n<meta http-equiv="'..meta_tag_name..'" content="'..meta_csp..'" />\n<meta name="csp-score" content="'..score..'" />\n<meta name="csp-breakdown" content="'..breakdown_json:gsub('"','&quot;')..'" />') end
        if dynamic_style_nonce and not content:match('id="csp%-style%-nonce%-patch"') then local patch=[[<script id="csp-style-nonce-patch">(function(n){try{var apply=function(el){if(el&&el.tagName==="STYLE"&&!el.nonce){el.setAttribute("nonce",n);}return el;};var AP=Element.prototype.appendChild, IB=Element.prototype.insertBefore;Element.prototype.appendChild=function(c){return AP.call(this,apply(c));};Element.prototype.insertBefore=function(c,r){return IB.call(this,apply(c),r);};var mo=new MutationObserver(function(ms){for(var i=0;i<ms.length;i++){var a=ms[i].addedNodes||[];for(var j=0;j<a.length;j++){var node=a[j];if(node.tagName==="STYLE"&&!node.nonce){node.setAttribute("nonce",n);}}}});mo.observe(document.documentElement,{subtree:true,childList:true});}catch(e){try{console.warn("CSP style nonce patch failed",e);}catch(_){}}})("..dynamic_style_nonce..[[");</script>]]; content=content:gsub('<head>','<head>\n'..patch) end
        local wf=io.open(filepath,'w'); if wf then wf:write(content); wf:close() end
        ctx.CSPTrack[dir_key]=ctx.CSPTrack[dir_key] or { files = {}, hashes = {}, report = {}, changed = { html = {} } }
  ctx.CSPTrack[dir_key].report[file]={header=csp_header,score=score,breakdown=breakdown,directives=directive_map,baseline=CSP.BASELINE,hash_only=hash_only}
        if stats then stats.files = stats.files + 1 end
      end
    end
  end
end

local function run_all()
  local stats = { files = 0 }
  for key,value in pairs(ctx.Dir or {}) do process_directory(key,value, stats) end
  if stats.files == 0 then
    -- Fallback: recursively scan entire site output structure grouping by directory
    local map = list_site_html()
    for dir_key,info in pairs(map) do
      local pseudo = { ChangedFiles = { html = {} }, CSP = { directives = { ['upgrade-insecure-requests']=true, ['block-all-mixed-content']=true }, files = {} } }
      for _,fname in ipairs(info.files) do
        pseudo.ChangedFiles.html[fname] = true
        pseudo.CSP.files[fname] = true
      end
      process_directory(dir_key, pseudo, stats)
    end
  end
  if stats.files == 0 then
    io.stderr:write('[CSP] Warning: No HTML files processed for CSP analysis.\n')
  end
end

return { { Pandoc = function(doc) run_all(); return doc end } }
