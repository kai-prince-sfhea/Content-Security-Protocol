// Copyright 2026 Kai Prince. Private static-host preparation, never deployment.
import {lstat,mkdir,writeFile,rename,unlink,realpath} from 'node:fs/promises';
import {join,relative,resolve,isAbsolute,sep} from 'node:path';
import {configuration,serializePolicy,fileDigest,fail} from './core.mjs';
import {auditOutput} from './audit.mjs';
import {CAPABILITY_REVIEW_CODES} from './capabilities.mjs';

export const HEADER_LIMITS=Object.freeze({files:5000,pathBytes:1024,policyBytes:8192,artifactBytes:2*1024*1024});
// Acknowledgement is permission to proceed with an explicitly named uncertainty,
// not evidence that the uncertainty has been resolved. Known violations cannot be waived.
export const REVIEWABLE_CODES=Object.freeze([
  'browser-script-data-unassessed','css-dependencies-unassessed','embedded-content-unassessed',
  'external-or-special-resource','foreign-content-unassessed','form-submission-unassessed',
  'frame-content-unassessed','hyperlink-ping-unassessed','inert-template-content','module-dependencies-unassessed',
  'noscript-content-unassessed',
  'resource-hint-unassessed','responsive-sources-unassessed','script-behavior-unassessed','script-type-unassessed',...CAPABILITY_REVIEW_CODES
]);
const reviewable=new Set(REVIEWABLE_CODES),hex=/^[a-f0-9]{64}$/u;
const knownCodes=new Set([...REVIEWABLE_CODES,'html-parse-error','inline-event-handler','inline-style-attribute',
  'existing-nonce-unverified','executable-url','base-url-unassessed','local-reference-resolution-incomplete',
  'existing-meta-control-unassessed','url-credentials-omitted','resource-not-authorized',
  'inline-hash-not-authorized','local-reference-unresolved','local-resource-missing','local-integrity-unverified',
  'private-output-path','forbidden-marker','changed-unrendered-source','source-roster-removed','empty-html-inventory']);
const plain=value=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;
const size=value=>new TextEncoder().encode(value).length;
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function options(value){
  if(!plain(value)||Object.keys(value).some(k=>!['adapter','mode','review'].includes(k))||!['netlify','cloudflare-pages'].includes(value.adapter)||!['report-only','enforce'].includes(value.mode))fail('headers options','use adapter netlify or cloudflare-pages and mode report-only or enforce');
  let review=null;
  if(value.review!==undefined){
    const r=value.review;
    if(!plain(r)||Object.keys(r).some(k=>!['inventoryDigest','codes'].includes(k))||!hex.test(r.inventoryDigest)||!Array.isArray(r.codes)||r.codes.length>REVIEWABLE_CODES.length||r.codes.some(c=>!reviewable.has(c))||new Set(r.codes).size!==r.codes.length)fail('headers review','use the exact inventory digest and unique documented uncertainty codes; known violations cannot be waived');
    review={inventoryDigest:r.inventoryDigest,codes:[...r.codes].sort()};
  }
  return {adapter:value.adapter,mode:value.mode,review};
}
function validateReport(report){
  if(!plain(report)||report.schema!=='content-security-protocol-audit/v1'||report.mode!=='audit'||!hex.test(report.inventoryDigest)||!Array.isArray(report.files)||!report.files.length||report.files.length>HEADER_LIMITS.files||!Array.isArray(report.pages)||!report.pages.length||!Array.isArray(report.findings)||!plain(report.declaredPolicy))fail('headers report','use a complete current audit with an HTML inventory');
  if(report.findings.some(f=>!plain(f)||!knownCodes.has(f.code)))fail('headers findings','unsupported or malformed assessment codes require a separately reviewed adapter');
  const config=configuration({enabled:true,policy:report.declaredPolicy.directives}),policy=serializePolicy(config.policy);
  if(report.declaredPolicy.text!==policy||size(policy)>HEADER_LIMITS.policyBytes)fail('headers policy','use the canonical bounded declared policy; no discovered hash is promoted');
  const files=new Map();
  for(const file of report.files){
    if(!plain(file)||typeof file.path!=='string'||!Number.isSafeInteger(file.bytes)||file.bytes<0||!hex.test(file.sha256)||files.has(file.path))fail('headers inventory','use unique regular-file entries from a current audit');
    // This deliberately excludes URL escaping, route patterns and host-specific
    // normalization. Broader filename adapters need their own measured mapping.
    if(size(file.path)>HEADER_LIMITS.pathBytes||!file.path.split('/').every(part=>/^[A-Za-z0-9_-][A-Za-z0-9._-]*$/u.test(part))||file.path.split('/').some(part=>['.','..','_headers','_redirects','netlify.toml'].includes(part.toLowerCase())))fail('headers route','use bounded literal ASCII file paths without escapes, patterns, hidden or reserved components');
    files.set(file.path,file);
  }
  const pages=new Set();
  for(const page of report.pages){
    if(!plain(page)||typeof page.path!=='string'||!files.has(page.path)||pages.has(page.path)||page.fileSha256!==files.get(page.path).sha256||!page.path.endsWith('.html')||!Array.isArray(page.findings)||!Array.isArray(page.inline)||!Array.isArray(page.resources))fail('headers pages','use unique HTML pages bound to the complete inventory');
    if(page.findings.some(f=>!plain(f)||!knownCodes.has(f.code)))fail('headers findings','unsupported or malformed assessment codes require a separately reviewed adapter');
    pages.add(page.path);
  }
  if([...files.keys()].filter(p=>/\.html?$/iu.test(p)).some(p=>!pages.has(p)))fail('headers pages','every HTML file must have a current page assessment; only lowercase .html mapping is supported');
  return {files,policy,config};
}
function routesFor(files){
  const routes=new Map(),folded=new Map();
  function add(route,path){
    if((routes.has(route)&&routes.get(route)!==path)||(folded.has(route.toLowerCase())&&folded.get(route.toLowerCase())!==path))fail('headers route','ambiguous pretty-URL, index or case mappings are unsupported');
    routes.set(route,path);folded.set(route.toLowerCase(),path);
  }
  for(const path of [...files.keys()].sort()){
    if(path==='404.html'||path.endsWith('/404.html'))fail('headers route','custom 404 fallback routing requires a separately reviewed adapter');
    add('/'+path,path);
    if(path.endsWith('.html')){const stem='/'+path.slice(0,-5);add(stem,path);add(stem+'/',path);}
    if(path==='index.html')add('/',path);
    else if(path.endsWith('/index.html')){const stem='/'+path.slice(0,-'/index.html'.length);add(stem+'/',path);add(stem,path);}
  }
  return [...routes].sort(([a],[b])=>a<b?-1:a>b?1:0).map(([route,path])=>({route,path}));
}
/** Pure candidate generation. Does not verify filesystem freshness or deliver headers. */
export function generateHeaders(report,value){
  const selected=options(value),{files,policy}=validateReport(report),routes=selected.adapter==='cloudflare-pages'?[{route:'/*',path:null}]:routesFor(files);
  if(selected.review&&selected.review.inventoryDigest!==report.inventoryDigest)fail('headers review','the acknowledgement must bind this exact inventory digest');
  const codes=[...new Set([...report.findings,...report.pages.flatMap(p=>p.findings)].map(f=>f.code))].sort();
  if(selected.mode==='enforce'){
    // Independent dispositions prevent a missing finding from turning an explicitly
    // unapproved resource/hash into an approved policy.
    if(report.pages.some(p=>p.inline.some(i=>i.authorization!=='authorized-by-declared-hash')||p.resources.some(r=>r.authorization!=='authorized-by-declared-source')))fail('headers enforcement','unapproved inline content or resources require author migration or an explicit declared policy');
    if(codes.some(c=>!reviewable.has(c)))fail('headers enforcement','known violations, incomplete references or unsupported controls cannot be acknowledged away');
    const approved=new Set(selected.review?.codes||[]);
    if(codes.some(c=>!approved.has(c)))fail('headers enforcement','acknowledge each documented uncertainty against the exact inventory digest, or use report-only');
  }
  const header=selected.mode==='enforce'?'Content-Security-Policy':'Content-Security-Policy-Report-Only';
  if(selected.adapter==='cloudflare-pages'&&size('  '+header+': '+policy)>2000)fail('headers limits','Cloudflare Pages permits at most 2000 characters per complete header line; use a smaller explicitly reviewed policy or a different host adapter');
  const text='# Content-Security-Protocol: candidate only; headers are not delivered by this file in private state.\n'+
    '# Inventory SHA-256: '+report.inventoryDigest+'\n'+
    '# Review delivered headers, routing, native controls and accessibility before deployment.\n'+
    routes.map(({route})=>route+'\n  '+header+': '+policy+'\n').join('\n');
  if(size(text)>HEADER_LIMITS.artifactBytes)fail('headers limits','reduce the route inventory or use a separately reviewed adapter');
  return {schema:'content-security-protocol-headers/v1',adapter:selected.adapter,mode:selected.mode,header,
    inventoryDigest:report.inventoryDigest,declaredPolicy:policy,routes,text,
    ...(selected.adapter==='cloudflare-pages'?{routeScope:'all-static-response-paths',hostLimits:{rules:100,lineCharacters:2000},qualification:'One uniform policy covers static paths, including fallback paths. It does not cover Pages Functions or Workers; actual hosted delivery remains unverified.'}:{}),
    review:selected.review,findingsCodes:codes,headerOnlyControls:['frame-ancestors',...(selected.mode==='report-only'?['report-only delivery']:[])],
    verifiedInventory:false,delivered:false,deployed:false,
    limitations:[selected.adapter==='cloudflare-pages'?'Static asset responses only, including native alias and fallback paths under the uniform rule; Pages Functions, Workers and authored redirect/rewrite configuration are unsupported.':'Static origin-backed routes only; proxies, functions, rewrites and custom 404 fallback are unsupported.',
      'Existing host UI or inherited configuration is not inspected; actual delivered headers remain unverified.',
      'Report-only does not block content and no report endpoint or external report collection is installed.',
      'An uncertainty acknowledgement does not prove runtime behavior, security or accessibility.']};
}
async function absent(path){try{await lstat(path);return false;}catch(e){if(e.code==='ENOENT')return true;throw e;}}
async function noConflicts(root,output,adapter){
  try{if((await lstat(join(root,'netlify'))).isSymbolicLink())fail('headers conflict','linked host configuration paths require a separately reviewed manual integration');}catch(e){if(e.code!=='ENOENT')throw e;}
  if(adapter==='cloudflare-pages')for(const base of [root,output])for(const name of ['functions','_worker.js','_routes.json','wrangler.toml','wrangler.json','wrangler.jsonc'])if(!await absent(join(base,name)))fail('headers conflict','existing Pages Functions, Worker, routing or Wrangler configuration requires a separately reviewed manual integration');
  for(const path of new Set([join(root,'_headers'),join(root,'_redirects'),join(root,'netlify.toml'),join(output,'_headers'),join(output,'_redirects'),join(output,'netlify.toml'),join(root,'netlify','functions'),join(root,'netlify','edge-functions')]))if(!await absent(path))fail('headers conflict','existing host headers, redirects, configuration or functions need a separately reviewed manual integration');
}
async function privateDirectory(root){
  let at=root;
  for(const part of ['.quarto','content-security-protocol']){
    at=join(at,part);try{await mkdir(at);}catch(e){if(e.code!=='EEXIST')throw e;}
    const state=await lstat(at);if(state.isSymbolicLink()||!state.isDirectory())fail('headers private path','linked or non-directory components are unsupported');
  }
  return at;
}
/** Re-audit exact final bytes, then store a private, uninstalled candidate. */
async function prepare(projectRoot,outputDir,report,value){
  const selected=options(value),root=await realpath(projectRoot),output=resolve(root,outputDir);
  const rel=relative(root,output);if(!rel||isAbsolute(rel)||rel==='..'||rel.startsWith('..'+sep))fail('headers output','use a separate final-output directory within the project');
  validateReport(report);
  const fresh=await auditOutput(root,output,{enabled:true,policy:report.declaredPolicy.directives,'prepared-model-packs':report.scope?.preparedModelPacks??[]});
  await noConflicts(root,output,selected.adapter);
  if(!same(fresh.files,report.files)||fresh.inventoryDigest!==report.inventoryDigest||fresh.declaredPolicy.text!==report.declaredPolicy.text)fail('headers freshness','output differs from the audit; render and audit again before preparing headers');
  // Fresh parser assessments prevent edits from erasing newly discovered violations.
  // Preserve original findings too: redacted forbidden markers and source provenance
  // cannot be reconstructed from the declared policy alone. Root CLI separately
  // verifies authority/currentness of the original report against its saved binding.
  const candidateReport={...fresh,findings:[...fresh.findings,...report.findings,...report.pages.flatMap(p=>p.findings)]};
  const artifact=generateHeaders(candidateReport,selected.review?selected:{adapter:selected.adapter,mode:selected.mode});
  const dir=await privateDirectory(root),artifactName='headers-'+selected.adapter+'.txt',destination=join(dir,artifactName);
  try{const state=await lstat(destination);if(state.isSymbolicLink()||!state.isFile())fail('headers private path','linked or non-file destinations are unsupported');}catch(e){if(e.code!=='ENOENT')throw e;}
  const temporary=join(dir,'.headers-'+selected.adapter+'.'+crypto.randomUUID()+'.tmp');
  try{await writeFile(temporary,artifact.text,{flag:'wx'});await rename(temporary,destination);}finally{try{await unlink(temporary);}catch(e){if(e.code!=='ENOENT')throw e;}}
  return {...artifact,verifiedInventory:true,artifactPath:'.quarto/content-security-protocol/'+artifactName,sha256:await fileDigest(new TextEncoder().encode(artifact.text))};
}
export async function prepareHeaders(projectRoot,outputDir,report,value){
  try{return await prepare(projectRoot,outputDir,report,value);}
  catch(error){if(typeof error?.message==='string'&&error.message.startsWith('content-security-protocol:'))throw error;fail('headers filesystem','cannot inspect or store the bounded candidate; verify regular project/output/private directories and permissions');}
}
