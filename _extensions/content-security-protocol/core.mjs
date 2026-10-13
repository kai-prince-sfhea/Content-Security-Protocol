// Copyright 2026 Kai Prince. Experimental audit; no policy is installed here.
import {parse} from './vendor/html-parser.mjs';
export const VERSION='0.0.4';

export const DEFAULT_POLICY=Object.freeze({
  'default-src':["'none'"], 'base-uri':["'none'"], 'object-src':["'none'"],
  'frame-ancestors':["'none'"], 'form-action':["'none'"],
  'script-src':["'self'"], 'style-src':["'self'"], 'img-src':["'self'"],
  'font-src':["'self'"], 'media-src':["'self'"], 'connect-src':["'none'"],
  'frame-src':["'none'"], 'worker-src':["'none'"], 'manifest-src':["'self'"]
});
const directives=new Set(Object.keys(DEFAULT_POLICY));
const plain=v=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.getPrototypeOf(v)===Object.prototype;
export function fail(field,rule){throw new Error(`content-security-protocol: ${field}: ${rule}`);}
export function configuration(value){
  if(value===undefined||value===false)return null;
  if(!plain(value))fail('configuration','use a mapping with enabled: true, or false to disable');
  if(value.enabled===false)return null;
  for(const k of Object.keys(value))if(!['enabled','mode','policy','fail-on','publication'].includes(k))fail('configuration','unsupported option; use enabled, mode, policy, fail-on or publication');
  if(value.enabled!==true)fail('enabled','explicitly select true to audit, or false to disable');
  if(value.mode!==undefined&&value.mode!=='audit')fail('mode','only audit is implemented; no enforcement or report-only delivery is installed');
  const policy=structuredClone(DEFAULT_POLICY);
  if(value.policy!==undefined){
    if(!plain(value.policy))fail('policy','use a directive-to-source-list mapping');
    for(const [key,list]of Object.entries(value.policy)){
      if(!directives.has(key))fail('policy','unsupported directive; see the documented audit subset');
      if(!Array.isArray(list)||!list.length||list.length>128)fail('policy sources','use a nonempty bounded sequence');
      for(const source of list){
        if(typeof source!=='string'||source.length>256)fail('policy source','use a documented source string');
        let valid=["'none'","'self'"].includes(source);
        const h=/^'sha(256|384|512)-([A-Za-z0-9+/]+={0,2})'$/u.exec(source);
        if(h&&['script-src','style-src'].includes(key)){const length={256:32,384:48,512:64}[h[1]];try{valid=atob(h[2]).length===length&&btoa(atob(h[2]))===h[2];}catch{valid=false;}}
        if(!valid){try{const u=new URL(source),host=u.hostname;valid=u.protocol==='https:'&&u.origin===source&&!u.username&&!u.password&&!/^[0-9.]+$/u.test(host)&&host.length<=253&&host.split('.').every(label=>label.length<=63&&/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label));}catch{}}
        if(['data:','blob:'].includes(source)&&!['base-uri','object-src','frame-ancestors','form-action','script-src'].includes(key))valid=true;
        if(!valid)fail('policy source','use self/none keywords, a canonical HTTPS origin or a documented digest/scheme; wildcards, credentials, paths and unsafe tokens are unsupported');
      }
      if(list.includes("'none'")&&list.length!==1)fail('policy sources','none must be the only source');
      policy[key]=[...new Set(list)].sort();
    }
  }
  const failOn=value['fail-on']??'none';if(!['none','known','any'].includes(failOn))fail('fail-on','choose none, known or any');
  const publication=value.publication??{};if(!plain(publication)||Object.keys(publication).some(k=>!['forbidden-markers','forbidden-paths'].includes(k)))fail('publication','use forbidden-markers and forbidden-paths sequences');
  const markers=publication['forbidden-markers']??[],paths=publication['forbidden-paths']??[];
  for(const [name,items]of [['forbidden-markers',markers],['forbidden-paths',paths]]){
    if(!Array.isArray(items)||items.length>64||items.some(x=>typeof x!=='string'||!x.length||x.length>256||/[\u0000-\u001f]/u.test(x)))fail('publication '+name,'use up to 64 nonempty bounded text values');
  }
  if(paths.some(p=>p.startsWith('/')||p.includes('//')||p.includes('\\')||p.includes(':')||p.split('/').some(x=>x==='..'||x==='.')||p.includes('*')))fail('publication forbidden-paths','use exact relative output paths or trailing-slash prefixes, without empty components/traversal/wildcards');
  return {mode:'audit',policy:Object.fromEntries(Object.entries(policy).sort(([a],[b])=>a.localeCompare(b))),failOn,publication:{markers:[...markers],paths:[...paths]}};
}
export const serializePolicy=policy=>Object.entries(policy).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>k+' '+v.join(' ')).join('; ');
const bytes=s=>new TextEncoder().encode(s);
export async function digest(data,algorithm='SHA-256'){
  const buffer=await crypto.subtle.digest(algorithm,typeof data==='string'?bytes(data):data);
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}
export async function fileDigest(data){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',data)),n=>n.toString(16).padStart(2,'0')).join('');}
const text=n=>(n.childNodes||[]).map(c=>c.nodeName==='#text'?c.value:'').join('');
const acceptedClassic=new Set(['','module','text/javascript','application/javascript','application/ecmascript','text/ecmascript']);
function sourceDisposition(origin,directive,policy){
  const list=policy[directive]||policy['default-src'];
  if(list.includes("'none'"))return 'not-authorized';
  return list.includes(origin==='self'?"'self'":origin)?'authorized-by-declared-source':'not-authorized';
}
// URL bodies never leave this parser: report only credential-free origin/scheme.
function classify(value){
  try{
    const u=new URL(value,'https://audit.invalid/');
    if(u.protocol==='https:'||u.protocol==='http:')return {origin:! /^(?:[A-Za-z][A-Za-z0-9+.-]*:|\/\/)/u.test(value.trim())&&u.origin==='https://audit.invalid'?'self':u.origin,credentials:!!(u.username||u.password)};
    return {origin:u.protocol,credentials:false};
  }catch{return {origin:'unresolved',credentials:false};}
}
export async function analyzeHtml(input,{path='index.html',policy=DEFAULT_POLICY}={}){
  const findings=[],resources=[],inline=[],localReferences=[];
  const issue=(code,element,extra={})=>findings.push({code,element,...extra});
  const doc=parse(input,{sourceCodeLocationInfo:true,scriptingEnabled:true,onParseError:e=>issue('html-parse-error',0,{reason:e.code})});
  let element=0,base=false;
  function resource(value,directive,kind,n,index){
    const target=classify(value),entry={element:index,directive,kind,origin:target.origin,authorization:sourceDisposition(target.origin,directive,policy)};
    resources.push(entry);
    if(target.credentials)issue('url-credentials-omitted',index);
    if(target.origin!=='self')issue('external-or-special-resource',index,{directive,origin:target.origin});
    if(entry.authorization==='not-authorized')issue('resource-not-authorized',index,{directive});
    if(target.origin==='self')localReferences.push({element:index,value,kind,integrity:n.attrs?.find(a=>a.name==='integrity')?.value||''});
  }
  const pending=[];
  async function inlineEntry(n,kind,index){
    const content=text(n),hash="'sha256-"+await digest(content)+"'",list=policy[kind==='script'?'script-src':'style-src']||policy['default-src'];
    let matched=list.includes(hash)?hash:null;
    for(const strength of [384,512])if(!matched&&list.some(s=>s.startsWith("'sha"+strength+'-'))){
      const candidate="'sha"+strength+'-'+await digest(content,'SHA-'+strength)+"'";if(list.includes(candidate))matched=candidate;
    }
    inline.push({kind,hash,element:index,authorization:matched?'authorized-by-declared-hash':'not-authorized',...(matched?{matchedDeclaredHash:matched}:{})});
  }
  function walk(n,inert=false){
    if(n.tagName){
      const index=++element,a=Object.fromEntries(n.attrs.map(x=>[x.name,x.value])),tag=n.tagName;
      if(inert)issue('inert-template-content',index);
      for(const key of Object.keys(a)){
        if(key.startsWith('on'))issue('inline-event-handler',index);
        if(key==='style')issue('inline-style-attribute',index);
        if(key==='nonce')issue('existing-nonce-unverified',index);
      }
      for(const key of ['href','src','action','formaction','data','poster','xlink:href'])if(a[key]!==undefined&&/^[\u0000-\u0020]*javascript:/iu.test(a[key].replace(/[\t\n\r]/gu,'')))issue('executable-url',index);
      if(n.namespaceURI!=='http://www.w3.org/1999/xhtml')issue('foreign-content-unassessed',index);
      if(tag==='base'){base=true;issue('base-url-unassessed',index);}
      if(tag==='noscript')issue('noscript-content-unassessed',index);
      if(['a','area'].includes(tag)&&a.ping!==undefined)issue('hyperlink-ping-unassessed',index);
      if(tag==='script'){
        const type=(a.type||'').trim().toLowerCase();
        if(acceptedClassic.has(type)){
          issue('script-behavior-unassessed',index); // Includes dynamic imports/workers/eval/connect, not inferred absent.
          if(a.src!==undefined)resource(a.src,'script-src','script',n,index);
          else pending.push(inlineEntry(n,'script',index));
          if(type==='module')issue('module-dependencies-unassessed',index);
        }else if(['importmap','speculationrules'].includes(type))issue('browser-script-data-unassessed',index,{type});
        else if(!['application/json','application/ld+json'].includes(type))issue('script-type-unassessed',index);
      }
      if(tag==='style'){
        pending.push(inlineEntry(n,'style',index));
        issue('css-dependencies-unassessed',index);
      }
      if(tag==='link'&&a.href!==undefined){
        const rel=(a.rel||'').toLowerCase().split(/\s+/u);
        if(rel.includes('stylesheet'))resource(a.href,'style-src','stylesheet',n,index);
        else if(rel.includes('manifest'))resource(a.href,'manifest-src','manifest',n,index);
        else if(rel.some(x=>['icon','apple-touch-icon'].includes(x)))resource(a.href,'img-src','image',n,index);
        else if(rel.some(x=>['preload','modulepreload','prefetch','preconnect','dns-prefetch'].includes(x)))issue('resource-hint-unassessed',index);
      }
      if(['img','input'].includes(tag)&&a.src!==undefined)resource(a.src,'img-src','image',n,index);
      if(a.srcset!==undefined||a.imagesrcset!==undefined)issue('responsive-sources-unassessed',index);
      if(['audio','video','source','track'].includes(tag)&&a.src!==undefined)resource(a.src,'media-src','media',n,index);
      if(a.poster!==undefined)resource(a.poster,'img-src','image',n,index);
      if(['iframe','frame'].includes(tag)){if(a.src!==undefined)resource(a.src,'frame-src','frame',n,index);issue('frame-content-unassessed',index);}
      if(['object','embed'].includes(tag)){if(a.data||a.src)resource(a.data||a.src,'object-src','object',n,index);issue('embedded-content-unassessed',index);}
      if(tag==='form'){resource(a.action||'','form-action','form',n,index);issue('form-submission-unassessed',index);}
      if(tag==='meta'&&/content-security-policy|refresh/iu.test(a['http-equiv']||''))issue('existing-meta-control-unassessed',index);
    }
    for(const child of n.childNodes||[])walk(child,inert);
    if(n.content)walk(n.content,true);
  }
  walk(doc);await Promise.all(pending);inline.sort((a,b)=>a.element-b.element);
  for(const h of inline)if(h.authorization==='not-authorized')issue('inline-hash-not-authorized',h.element,{kind:h.kind});
  if(base){localReferences.length=0;for(const r of resources)r.authorization='unassessed-base-url';issue('local-reference-resolution-incomplete',0);}
  findings.sort((a,b)=>a.element-b.element||a.code.localeCompare(b.code));
  return {path,inline,resources,findings,localReferences,coverage:'static-html-only',dynamicBehavior:'unassessed'};
}
