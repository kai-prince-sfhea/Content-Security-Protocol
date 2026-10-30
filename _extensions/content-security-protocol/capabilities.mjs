// Copyright 2026 Kai Prince. SPDX-License-Identifier: Apache-2.0
// Static, explicitly selected runtime declarations. Discovery never grants CSP
// permission, executes a runtime, fetches an asset or authenticates its author.
export const WASM_TOKEN="'wasm-unsafe-eval'";
export const CAPABILITY_LIMITS=Object.freeze({jsonBytes:262144,jsonNodes:20000,jsonDepth:24,referencesPerPage:64,references:1024,packs:8,assetsPerPack:256});
export const CAPABILITY_REVIEW_CODES=Object.freeze(['wasm-compilation-permission-not-declared','prepared-model-pack-not-selected','prepared-model-manifest-missing','prepared-model-reference-unassessed','prepared-model-reference-coverage-incomplete']);
const encoder=new TextEncoder(),hash=/^[a-f0-9]{64}$/u;
const fail=()=>{throw new TypeError('content-security-protocol: invalid or inconsistent prepared runtime capability data');};
const plain=value=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.getPrototypeOf(value)===Object.prototype;
const path=value=>typeof value==='string'&&value.length>0&&value.length<=2048&&/^[A-Za-z0-9][A-Za-z0-9._/-]*$/u.test(value)&&value.split('/').every(part=>part&&!part.startsWith('.'));
const freeze=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;};

// JSON.parse alone silently accepts duplicate keys. This small original lexical
// guard checks exact decoded keys at every depth before parsing bounded data.
// It does not evaluate expressions or interpret the projected source text.
function strictJSON(raw){
 if(typeof raw!=='string'||encoder.encode(raw).length>CAPABILITY_LIMITS.jsonBytes)fail();let at=0,nodes=0;
 const space=()=>{while(/[\t\n\r ]/u.test(raw[at]??'')&&at<raw.length)at++;};
 function string(){if(raw[at++]!=='"')fail();const start=at-1;while(at<raw.length){const code=raw.charCodeAt(at++);if(code===34){try{return JSON.parse(raw.slice(start,at));}catch{fail();}}if(code<32)fail();if(code===92){const next=raw[at++];if(next==='u'){if(!/^[A-Fa-f0-9]{4}$/u.test(raw.slice(at,at+4)))fail();at+=4;}else if(!['"','\\','/','b','f','n','r','t'].includes(next))fail();}}fail();}
 function value(depth){if(depth>CAPABILITY_LIMITS.jsonDepth||++nodes>CAPABILITY_LIMITS.jsonNodes)fail();space();const char=raw[at];if(char==='"'){string();return;}if(char==='{'){at++;space();const keys=new Set();if(raw[at]==='}'){at++;return;}while(true){space();const key=string();if(keys.has(key))fail();keys.add(key);space();if(raw[at++]!==':')fail();value(depth+1);space();const next=raw[at++];if(next==='}')return;if(next!==',')fail();}}if(char==='['){at++;space();if(raw[at]===']'){at++;return;}while(true){value(depth+1);space();const next=raw[at++];if(next===']')return;if(next!==',')fail();}}for(const literal of ['true','false','null'])if(raw.startsWith(literal,at)){at+=literal.length;return;}const number=/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(raw.slice(at));if(!number||!Number.isFinite(Number(number[0])))fail();at+=number[0].length;}
 value(0);space();if(at!==raw.length)fail();try{return JSON.parse(raw);}catch{fail();}
}
function manifestPath(value,page){
 if(typeof value!=='string'||!value||value.length>2048||/[\\%:?#\s<>"'\u0000-\u001f]/u.test(value)||value.startsWith('//'))return null;
 // Root-authored paths become ordinary ../ URLs on nested rendered pages.
 const parts=value.startsWith('/')?[]:page.split('/').slice(0,-1);let first=true;for(const part of value.split('/')){if(part===''&&first&&value.startsWith('/')){first=false;continue;}first=false;if(!part)return null;if(part==='.')continue;if(part==='..'){if(!parts.length)return null;parts.pop();}else parts.push(part);}
 const target=parts.join('/');return path(target)&&/(?:^|\/)models\.json$/u.test(target)?target:null;
}

/** A recognized inert Local AI v0 marker is a declaration hint, never proof
 * of the actual producer. Invalid values never enter returned diagnostics. */
export function inspectModelPackDeclaration(body,{page,element,basePresent=false}={}){
 const reference={page,element,status:'unassessed'},unknown=()=>freeze({reference,findings:[{code:'prepared-model-reference-unassessed',element}]});
 try{
  const data=strictJSON(body);if(!plain(data)||data.version!==0||!Array.isArray(data.sources)||data.sources.length>1024||!Object.hasOwn(data,'manifest')||Object.keys(data).some(key=>!['version','sources','manifest','graphRegistry','graphs','sourcePages','proposalFormat'].includes(key)))return unknown();
  if(data.graphRegistry!==undefined&&data.graphRegistry!==null&&typeof data.graphRegistry!=='string'||data.sourcePages!==undefined&&(!Array.isArray(data.sourcePages)||data.sourcePages.length>8||data.sourcePages.some(value=>typeof value!=='string'))||data.proposalFormat!==undefined&&!['cited-json','plain-text'].includes(data.proposalFormat)||data.graphs!==undefined&&data.graphs!==false&&data.graphs!=='all'&&(!Array.isArray(data.graphs)||data.graphs.length>32||data.graphs.some(value=>typeof value!=='string')))return unknown();
  if(data.manifest===null)return freeze({reference:{page,element,status:'none'},findings:[]});if(basePresent)return unknown();const manifest=manifestPath(data.manifest,page);if(!manifest)return unknown();
  return freeze({reference:{page,element,status:'declared',manifest},findings:[]});
 }catch{return unknown();}
}

/** Match receipt records to the caller's verified final inventory before
 * describing a capability. Digests and tokens do not prove delivered policy,
 * execution, compatible MIME/CORS/isolation or executable safety. */
export function preparedRuntimeCapabilities({prepared,files,policy,pages}={}){
 if(!prepared||!(prepared.assets instanceof Map)||!Array.isArray(prepared.manifests)||prepared.manifests.length>CAPABILITY_LIMITS.packs||!Array.isArray(files)||!plain(policy)||!Array.isArray(policy['script-src'])||!Array.isArray(pages))fail();
 const byPath=new Map();for(const file of files){if(!plain(file)||typeof file.path!=='string'||!Number.isSafeInteger(file.bytes)||file.bytes<0||!hash.test(file.sha256??'')||byPath.has(file.path))fail();byPath.set(file.path,file);}
 const selected=new Set(prepared.manifests);if(selected.size!==prepared.manifests.length)fail();const records=[],findings=[],references=[];let declarationCount=0,omittedReferences=0,assessedReferences=0;
 for(const manifest of prepared.manifests){if(!path(manifest)||!/(?:^|\/)models\.json$/u.test(manifest))fail();const prefix=manifest.slice(0,-'models.json'.length),receipt=prefix+'asset-receipt.json',manifestFile=byPath.get(manifest),receiptFile=byPath.get(receipt);if(!manifestFile||!receiptFile)fail();const assets=[];
  for(const [name,asset]of prepared.assets){if(!name.startsWith(prefix)||asset.kind!=='runtime'||!/^wasm\/[^/]+\.wasm$/u.test(name.slice(prefix.length)))continue;const observed=byPath.get(name);if(!asset.binary||!path(name)||!observed||observed.bytes!==asset.bytes||observed.sha256!==asset.sha256)fail();assets.push({path:name,bytes:observed.bytes,sha256:observed.sha256});}
  if(assets.length>CAPABILITY_LIMITS.assetsPerPack)fail();assets.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);if(!assets.length)continue;
  const declared=policy['script-src'].includes(WASM_TOKEN)&&!policy['script-src'].includes("'none'");records.push({kind:'wasm-compilation',manifest,manifestSha256:manifestFile.sha256,receipt,receiptSha256:receiptFile.sha256,assets,declaration:'author-selected-preparation-receipt',integrity:'matched-final-inventory-and-preparation-receipt',policy:{directive:'script-src',token:WASM_TOKEN,disposition:declared?'declared':'not-authorized',delivered:false},execution:'not-tested'});
  if(!declared)findings.push({code:'wasm-compilation-permission-not-declared',path:manifest,category:'compatibility',permissionGranted:false});
 }
 for(const page of pages){if(!plain(page)||!byPath.has(page.path)||page.fileSha256!==byPath.get(page.path).sha256||page.modelPackReferences!==undefined&&!Array.isArray(page.modelPackReferences))fail();for(const reference of page.modelPackReferences??[]){if(!plain(reference)||reference.page!==page.path||!Number.isSafeInteger(reference.element)||reference.element<0||!['declared','none','unassessed'].includes(reference.status))fail();if(reference.omittedReferences!==undefined){if(reference.status!=='unassessed'||reference.element!==0||!Number.isSafeInteger(reference.omittedReferences)||reference.omittedReferences<1||reference.omittedReferences>10000000)fail();declarationCount+=reference.omittedReferences;omittedReferences+=reference.omittedReferences;continue;}declarationCount++;if(references.length>=CAPABILITY_LIMITS.references){omittedReferences++;continue;}assessedReferences++;
   if(reference.status!=='declared'){references.push({page:page.path,element:reference.element,status:reference.status});continue;}if(!path(reference.manifest))fail();const file=byPath.get(reference.manifest);
   if(!file){references.push({page:page.path,element:reference.element,status:'manifest-missing'});findings.push({code:'prepared-model-manifest-missing',path:page.path,element:reference.element,category:'compatibility',permissionGranted:false});}
   else{const admitted=selected.has(reference.manifest);references.push({page:page.path,element:reference.element,status:admitted?'selected-prepared-pack':'not-selected',manifest:reference.manifest,manifestSha256:file.sha256});if(!admitted)findings.push({code:'prepared-model-pack-not-selected',path:page.path,element:reference.element,manifest:reference.manifest,category:'compatibility',permissionGranted:false});}
  }}
 if(omittedReferences)findings.push({code:'prepared-model-reference-coverage-incomplete',omittedReferences,permissionGranted:false});
 return freeze({schema:'content-security-protocol-capabilities/v1',coverage:{scope:'author-selected-prepared-runtime-declarations-only',selectedPacks:selected.size,wasmProfiles:records.length,referenceDeclarations:declarationCount,assessedReferences,omittedReferences,referenceInspectionComplete:omittedReferences===0},records,references,findings,unassessed:['dynamic-imports','unrecorded-workers','webgpu','cross-origin-isolation','actual-browser-execution','actual-host-policy-delivery'],qualification:'Prepared receipts and file hashes establish declared byte identity, not authenticity, executable safety, actual use or permission. A missing WASM token is a compatibility gap; a site may deliberately deny execution. No finding changes the policy or grants a capability.'});
}
