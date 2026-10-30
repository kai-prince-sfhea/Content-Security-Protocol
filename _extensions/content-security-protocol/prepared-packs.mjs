// Explicit bounded adapter for Local AI Websites' prepared public assets.
// A receipt is author-selected input, not a security or model-quality approval.
import {lstat,readFile,open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {Buffer} from 'node:buffer';
import {join,dirname,resolve,relative,isAbsolute,sep} from 'node:path';
import {fail} from './core.mjs';

export const PREPARED_LIMITS=Object.freeze({packs:8,resources:256,metadataBytes:262144,modelBytes:4*1024**3,wasmBytes:128*1024**2,totalBytes:8*1024**3,chunkBytes:1024**2});
const HASH=/^[a-f0-9]{64}$/u;
const plain=value=>value&&typeof value==='object'&&!Array.isArray(value);
export const packPath=value=>typeof value==='string'&&value.length>0&&value.length<=2048&&/^[A-Za-z0-9][A-Za-z0-9._/-]*$/u.test(value)&&value.split('/').every(part=>part&&!part.startsWith('.'));
async function ordinary(root,name,{maximum=PREPARED_LIMITS.metadataBytes}={}){
  const path=resolve(root,name),rel=relative(root,path);if(!rel||isAbsolute(rel)||rel==='..'||rel.startsWith('..'+sep))fail('prepared model packs','requires contained ordinary asset paths');
  let cursor=root;
  for(const part of rel.split(sep).slice(0,-1)){cursor=join(cursor,part);const info=await lstat(cursor);if(!info.isDirectory()||info.isSymbolicLink())fail('prepared model packs','linked asset paths are unsupported');}
  const info=await lstat(path);if(!info.isFile()||info.isSymbolicLink()||info.size>maximum)fail('prepared model packs','requires regular assets within the prepared bounds');return {path,info};
}
async function metadata(root,name){
  const {path}=await ordinary(root,name);let value;
  try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await readFile(path)));}catch{fail('prepared model packs','requires bounded UTF-8 manifest and receipt JSON');}
  if(!plain(value))fail('prepared model packs','requires manifest and receipt objects');return value;
}
function resource(url){
  if(typeof url!=='string'||!url.startsWith('./')||!packPath(url.slice(2)))fail('prepared model packs','manifest assets require ordinary relative paths');return url.slice(2);
}
function inventory(records,label){
  if(!Array.isArray(records)||!records.length||records.length>PREPARED_LIMITS.resources)fail('prepared model packs','requires bounded runtime and model inventories');
  const result=new Map();
  for(const record of records){
    if(!plain(record)||!Number.isSafeInteger(record.bytes)||record.bytes<1||!HASH.test(record.sha256??''))fail('prepared model packs','requires exact positive sizes and SHA-256 identities');
    const path=resource(record.url);if(result.has(path))fail('prepared model packs','duplicate manifest asset');
    result.set(path,{bytes:record.bytes,sha256:record.sha256,kind:label});
  }
  return result;
}
/** Validate one named manifest/receipt pair; never scan or exempt a folder. */
export async function preparedPacks(root,paths=[],{allowAbsent=false}={}){
  const assets=new Map(),allResources=new Set(),manifests=[],absentManifests=[];let total=0;
  if(!Array.isArray(paths)||paths.length>PREPARED_LIMITS.packs)fail('prepared model packs','select up to eight named prepared manifests');
  for(const path of paths){
    if(!packPath(path)||!/(?:^|\/)models\.json$/u.test(path)||manifests.includes(path)||absentManifests.includes(path))fail('prepared model packs','select unique ordinary models.json paths');
    const base=dirname(path),at=name=>base==='.'?name:base+'/'+name;
    const optional=async name=>{try{return await metadata(root,name);}catch(error){if(error.code==='ENOENT')return null;throw error;}};
    const manifest=await optional(path),receipt=await optional(at('asset-receipt.json'));
    if(!manifest||!receipt){
      if(allowAbsent&&!manifest&&!receipt){absentManifests.push(path);continue;}
      fail('prepared model packs','requires both the selected manifest and its preparation receipt');
    }
    if(manifest.version!==1||receipt.version!==1||receipt.operation!=='explicit-local-preparation'||!plain(manifest.runtime))fail('prepared model packs','requires the supported explicit preparation receipt');
    const runtime=inventory(manifest.runtime.inventory,'runtime'),models=inventory(manifest.models,'model');
    const receiptRuntime=inventory(receipt.runtimeInventory,'runtime'),receiptModels=inventory(receipt.models,'model');
    const same=(a,b)=>JSON.stringify([...a].sort())===JSON.stringify([...b].sort());
    if(!same(runtime,receiptRuntime)||!same(models,receiptModels))fail('prepared model packs','manifest and receipt asset identities disagree');
    const files=receipt.resourceFiles;
    if(!Array.isArray(files)||files.length<1||files.length>PREPARED_LIMITS.resources||new Set(files).size!==files.length||files.some(file=>!packPath(file)))fail('prepared model packs','requires a unique bounded exact resource inventory');
    const selected=new Set(files);
    if(!selected.has('models.json')||!selected.has('asset-receipt.json'))fail('prepared model packs','receipt must include its manifest and receipt');
    const expected=new Map([...runtime,...models]);if(expected.size!==runtime.size+models.size)fail('prepared model packs','runtime and model paths must be distinct');
    for(const [name,record]of expected){
      if(!selected.has(name))fail('prepared model packs','receipt omits a runtime or model resource');
      const binary=record.kind==='model'?/^models\/[^/]+\.litertlm$/u.test(name):/^wasm\/[^/]+\.wasm$/u.test(name);
      if(record.kind==='model'&&!binary)fail('prepared model packs','model exemptions require a prepared litertlm model');
      const maximum=record.kind==='model'?PREPARED_LIMITS.modelBytes:binary?PREPARED_LIMITS.wasmBytes:32*1024**2;
      if(record.bytes>maximum)fail('prepared model packs','prepared asset exceeds its separate bounded size budget');
      const key=at(name);await ordinary(root,key,{maximum});
      if(assets.has(key))fail('prepared model packs','overlapping prepared manifests are unsupported');
      assets.set(key,{...record,binary,maximum});if(binary&&(total+=record.bytes)>PREPARED_LIMITS.totalBytes)fail('prepared model packs','prepared binary total exceeds its bounded budget');
    }
    for(const name of files){
      const key=at(name);if(allResources.has(key))fail('prepared model packs','overlapping prepared resource inventories are unsupported');allResources.add(key);
      const {info}=await ordinary(root,key,{maximum:assets.get(key)?.maximum??PREPARED_LIMITS.metadataBytes});
      if(assets.has(key)&&info.size!==assets.get(key).bytes)fail('prepared model packs','prepared asset size differs from its receipt');
      if(!expected.has(name)&&!['models.json','asset-receipt.json'].includes(name)&&!/^licences\/[^/]+$/u.test(name))fail('prepared model packs','unregistered extra receipt resources are unsupported');
    }
    manifests.push(path);
  }
  return {assets,resources:allResources,manifests,absentManifests,totalBytes:total};
}
/** Fixed-memory hashing/UTF-8 marker scan, with identities checked after EOF. */
export async function streamAsset(path,{maximum,bytes,sha256,markers=[],algorithm='SHA-256',chunkBytes=PREPARED_LIMITS.chunkBytes}={}){
  if(!Number.isSafeInteger(maximum)||maximum<1||!Number.isInteger(chunkBytes)||chunkBytes<1||chunkBytes>PREPARED_LIMITS.chunkBytes)fail('prepared model packs','invalid streaming bounds');
  const before=await lstat(path);if(!before.isFile()||before.isSymbolicLink()||before.size>maximum||bytes!==undefined&&before.size!==bytes)fail('prepared model packs','requires unchanged regular binary assets');
  const handle=await open(path,'r'),hash=createHash('sha256'),extra=algorithm==='SHA-256'?null:createHash(algorithm.toLowerCase().replace('-',''));
  const decoder=markers.length?new TextDecoder():null,overlap=Math.max(0,...markers.map(marker=>marker.length-1)),found=new Set();let tail='',count=0;
  const scan=text=>{const combined=tail+text;for(let i=0;i<markers.length;i++)if(combined.includes(markers[i]))found.add(i);tail=overlap?combined.slice(-overlap):'';};
  try{
    const opened=await handle.stat();if(opened.ino!==before.ino||opened.dev!==before.dev)fail('prepared model packs','asset changed during streaming');
    const chunk=new Uint8Array(chunkBytes);
    for(;;){const {bytesRead}=await handle.read(chunk,0,chunk.length,null);if(!bytesRead)break;count+=bytesRead;if(count>maximum)fail('prepared model packs','asset exceeded its streaming bound');const part=chunk.subarray(0,bytesRead);hash.update(part);extra?.update(part);if(decoder)scan(decoder.decode(part,{stream:true}));}
    if(decoder)scan(decoder.decode());
    const after=await lstat(path);if(!after.isFile()||after.isSymbolicLink()||after.ino!==before.ino||after.dev!==before.dev||count!==before.size||after.size!==before.size)fail('prepared model packs','asset changed during streaming');
    const actual=hash.digest('hex');if(sha256!==undefined&&actual!==sha256)fail('prepared model packs','prepared binary SHA-256 differs from its receipt');
    return {bytes:count,sha256:actual,digest:extra?extra.digest('base64'):Buffer.from(actual,'hex').toString('base64'),markerIndices:[...found].sort((a,b)=>a-b)};
  }finally{await handle.close();}
}
