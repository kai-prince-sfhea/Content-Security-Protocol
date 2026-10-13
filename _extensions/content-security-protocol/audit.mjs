// Read-only final-output inventory. Only private report files are written.
import {lstat,readdir,readFile,realpath,mkdir} from 'node:fs/promises';
import {join,relative,resolve,isAbsolute,sep} from 'node:path';
import {VERSION,configuration,analyzeHtml,fileDigest,digest,serializePolicy,fail} from './core.mjs';
import {cryptoInventory} from './review.mjs';

export const LIMITS=Object.freeze({files:5000,directories:5000,depth:64,totalBytes:128*1024*1024,fileBytes:32*1024*1024,htmlBytes:8*1024*1024});
export const inside=(root,p)=>{const r=relative(root,p);return r!==''&&!isAbsolute(r)&&r!=='..'&&!r.startsWith('..'+sep);};
export async function noLinks(root,path,{create=false}={}){
  const rel=relative(root,path);if(isAbsolute(rel)||rel==='..'||rel.startsWith('..'+sep)||resolve(root,rel)!==path)fail('path','must remain in the project');
  let at=root;for(const component of rel.split(sep).filter(Boolean)){
    at=join(at,component);let s;try{s=await lstat(at);}catch(e){if(e.code==='ENOENT'&&create){await mkdir(at);s=await lstat(at);}else throw e;}
    if(s.isSymbolicLink()||!s.isDirectory())fail('path','linked or non-directory components are unsupported');
  }
}
export async function inventory(output,limits=LIMITS,{retainBytes=true}={}){
  limits={...LIMITS,...limits};const files=[],data=new Map();let total=0,directories=0;
  async function walk(dir,depth=0){
    if(depth>limits.depth||++directories>limits.directories)fail('output limits','directory count/depth exceeds the bounded audit contract');
    const entries=(await readdir(dir,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name));
    for(const e of entries){
      const p=join(dir,e.name),s=await lstat(p),key=relative(output,p).split(sep).join('/');
      if(s.isSymbolicLink())fail('output','linked files or directories are unsupported; audit a regular final-output copy');
      if(s.isDirectory())await walk(p,depth+1);
      else{
        if(!s.isFile())fail('output','only regular files/directories are supported');
        if(files.length>=limits.files||s.size>limits.fileBytes||total+s.size>limits.totalBytes)fail('output limits','reduce the output inventory or use a separately reviewed larger adapter');
        const bytes=await readFile(p);if(bytes.length!==s.size)fail('output','changed during inventory; stop concurrent builds and retry');
        total+=bytes.length;files.push({path:key,bytes:bytes.length,sha256:await fileDigest(bytes)});if(retainBytes)data.set(key,bytes);
      }
    }
  }
  await walk(output);return {files,data};
}
function localPath(page,value){
  // Reject encoded separators/parents rather than normalize a possibly different host mapping.
  if(/%(?:2f|5c|2e|00)/iu.test(value)||value.includes('\\'))return null;
  try{
    const u=new URL(value,'https://audit.invalid/'+page);
    if(u.origin!=='https://audit.invalid')return null;
    const decoded=decodeURIComponent(u.pathname).slice(1);if(decoded.split('/').some(x=>x==='.'||x==='..'||x==='.git'||x==='.quarto'||x==='_extensions'))return null;
    return decoded;
  }catch{return null;}
}
async function integrityStatus(getDigest,value){
  const candidates=[];
  for(const token of value.replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/gu,'').split(/[\t\n\f\r ]+/u)){
    const m=/^sha(256|384|512)-([A-Za-z0-9+/_-]+={0,2})$/u.exec(token.split('?')[0]);if(m)candidates.push({strength:Number(m[1]),hash:m[2].replaceAll('-','+').replaceAll('_','/')});
  }
  if(!candidates.length)return 'unrecognized';
  const strongest=Math.max(...candidates.map(c=>c.strength)),expected=await getDigest('SHA-'+strongest);
  return candidates.some(c=>c.strength===strongest&&c.hash===expected)?'matching-strongest-local-bytes':'mismatch';
}
export async function auditOutput(projectRoot,outputDir,options,{limits=LIMITS}={}){
  const config=configuration(options);if(!config)return null;
  limits={...LIMITS,...limits};
  const root=await realpath(projectRoot),output=resolve(root,outputDir);
  if(!inside(root,output))fail('output directory','use a separate directory within the project; auditing the project root or an outside path is unsupported');
  const top=relative(root,output).split(sep)[0].toLowerCase();if(['.quarto','.git','_extensions'].includes(top))fail('output directory','must not overlap private state, Git or extension code');
  await noLinks(root,output);const original=await inventory(output,limits),pages=[];
  const fileHashes=new Map(original.files.map(f=>[f.path,f.sha256])),assetDigests=new Map();
  // Reuse digests only within this immutable in-memory inventory. Every audit
  // still reads/hashes the full tree twice; no mtime or cross-render cache.
  const assetDigest=(path,algorithm)=>{
    let hashes=assetDigests.get(path);if(!hashes){hashes=new Map();assetDigests.set(path,hashes);}
    if(!hashes.has(algorithm))hashes.set(algorithm,digest(original.data.get(path),algorithm));
    return hashes.get(algorithm);
  };
  for(const file of original.files.filter(f=>/\.html?$/iu.test(f.path))){
    if(file.bytes>limits.htmlBytes)fail('HTML limit','reduce a page or use a separately reviewed larger adapter');
    let html;try{html=new TextDecoder('utf-8',{fatal:true}).decode(original.data.get(file.path));}catch{fail('HTML encoding','UTF-8 final HTML is required');}
    const page=await analyzeHtml(html,{path:file.path,policy:config.policy});
    page.fileSha256=file.sha256;
    for(const ref of page.localReferences){
      const p=localPath(file.path,ref.value),bytes=p===null?undefined:original.data.get(p);
      const finding=code=>page.findings.push({code,element:ref.element});
      if(ref.kind==='form'){continue;} // Form targets are server behavior, not static assets.
      if(!bytes){finding(p===null?'local-reference-unresolved':'local-resource-missing');continue;}
      const item={element:ref.element,path:p,sha256:fileHashes.get(p)};
      if(['script','stylesheet'].includes(ref.kind)){
        item.sriCandidate='sha384-'+await assetDigest(p,'SHA-384');
        item.integrity=ref.integrity?await integrityStatus(algorithm=>assetDigest(p,algorithm),ref.integrity):'absent';
        if(item.integrity==='mismatch'||item.integrity==='unrecognized')finding('local-integrity-unverified');
      }
      (page.localAssets??=[]).push(item);
    }
    delete page.localReferences;
    page.findings.sort((a,b)=>a.element-b.element||a.code.localeCompare(b.code));pages.push(page);
  }
  const manifest=original.files;
  const publicationFindings=[];
  for(const file of manifest){
    if(/(?:^|\/)(?:\.git|\.quarto|_extensions|private|\.env(?:\.[^/]*)?)(?:\/|$)|\.(?:qmd|rmd|ipynb)$/iu.test(file.path)||config.publication.paths.some(p=>p.endsWith('/')?file.path.startsWith(p):file.path===p))publicationFindings.push({code:'private-output-path',path:file.path});
    if(config.publication.markers.length){const text=new TextDecoder().decode(original.data.get(file.path));for(let i=0;i<config.publication.markers.length;i++)if(text.includes(config.publication.markers[i]))publicationFindings.push({code:'forbidden-marker',path:file.path,markerIndex:i});}
  }
  const report={schema:'content-security-protocol-audit/v1',extensionVersion:VERSION,mode:'audit',enforcement:false,
    inventoryDigest:await fileDigest(new TextEncoder().encode(JSON.stringify(manifest))),
    scope:{kind:'retained-final-output-tree',inventoryComplete:true,sourceRebuildComplete:'unassessed',dynamicBehavior:'unassessed',network:'not-accessed',accessibility:'not-assessed',headers:'not-delivered-or-verified'},
    assessment:pages.length?'requires-review':'incomplete-no-html',
    declaredPolicy:{directives:config.policy,text:serializePolicy(config.policy),delivered:false,inlineCandidatesApproved:false},
    files:manifest,pages,
    findings:[...publicationFindings,...(pages.length?[]:[{code:'empty-html-inventory'}])],
    limitations:['Static inventory is not a security certificate or runtime dependency proof.','Full output-tree scans include retained/stale output; they do not prove all current sources rendered.','Inline hashes and SRI values are candidates, not authority; review before policy approval.','External resources are never fetched. CSS/JS dynamic dependencies and actual browser/host delivery remain unassessed.','Reports omit source bodies and URL query/fragment/credentials but output paths/origins can still be private.']};
  report.cryptography=cryptoInventory(report);
  // Detect changing files after parsing; reports must describe one stable tree.
  const after=await inventory(output,limits,{retainBytes:false});if(JSON.stringify(after.files)!==JSON.stringify(manifest))fail('output','changed during audit; stop concurrent builds and retry');
  return report;
}
export function markdown(report){
  const counts=new Map();for(const f of [...report.findings,...report.pages.flatMap(p=>p.findings)])counts.set(f.code,(counts.get(f.code)??0)+1);
  const summary=counts.size?'| Finding | Count |\n| --- | --- |\n'+[...counts].sort(([a],[b])=>a.localeCompare(b)).map(([code,n])=>'| '+code+' | '+n+' |').join('\n'):'No static findings observed; this is not a security pass.';
  return '# Content Security Protocol audit\n\nRead-only experimental inventory; no policy installed.\n\n'+
    `Assessment: ${report.assessment}. ${report.files.length} files; ${report.pages.length} HTML pages.\n\n`+
    'Scope: retained final output tree; current source rebuild, dynamic behavior, delivered headers and accessibility remain unassessed.\n\n'+
    'Inventory digest: '+report.inventoryDigest+'\n\n'+summary+'\n\n'+
    'Declared policy (undelivered):\n\n```text\n'+report.declaredPolicy.text+'\n```\n\n'+
    'Inline hashes and SRI are candidates only. Review JSON findings; no security score is assigned.\n\n'+
    report.limitations.map(x=>'- '+x).join('\n')+'\n';
}
