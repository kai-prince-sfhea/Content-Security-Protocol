// Authoritative state is one atomic status/receipt pointer, not report aliases.
import {readFile,writeFile,rename,unlink,lstat,mkdir,realpath} from 'node:fs/promises';
import {join,relative,resolve,isAbsolute,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {noLinks,inside,inventory,markdown} from './audit.mjs';
import {fileDigest,fail,configuration} from './core.mjs';
import {preparedPacks,streamAsset} from './prepared-packs.mjs';
const encoder=new TextEncoder(),hash=s=>fileDigest(encoder.encode(JSON.stringify(s)));
export const STATE='.quarto/content-security-protocol';
export async function runtimeDigest(){return hash((await inventory(fileURLToPath(new URL('.',import.meta.url)),undefined,{retainBytes:false})).files);}
async function location(root,create=false){const project=await realpath(root),dir=join(project,STATE);await noLinks(project,dir,{create});return {project,dir};}
async function json(path){const s=await lstat(path);if(!s.isFile()||s.isSymbolicLink()||s.size>8*1024*1024)fail('state','use regular bounded state files');return JSON.parse(await readFile(path,'utf8'));}
async function atomic(path,value){const temp=path+'.'+crypto.randomUUID()+'.tmp';try{await writeFile(temp,JSON.stringify(value,null,2)+'\n',{flag:'wx'});try{if((await lstat(path)).isSymbolicLink())fail('state','linked destinations are unsupported');}catch(e){if(e.code!=='ENOENT')throw e;}await rename(temp,path);}finally{try{await unlink(temp);}catch(e){if(e.code!=='ENOENT')throw e;}}}
export async function markState(root,status,{create=false}={}){
  let dir;try{({dir}=await location(root,create));}catch(e){if(e.code==='ENOENT'&&!create)return;throw e;}
  await atomic(join(dir,'status.json'),{schema:'content-security-protocol-state/v1',status});
}
function key(root,p){const absolute=resolve(root,p),name=relative(root,absolute).split(sep).join('/');return inside(root,absolute)?name:null;}
export async function snapshotSources(root,inspection){
  const project=await realpath(root),paths=new Set(),inputs=[];let outside=0;
  const prepared=await preparedPacks(project,configuration(inspection.config?.['content-security-protocol'])?.preparedModelPacks??[],{allowAbsent:true});
  for(const type of ['input','config','resources','configResources'])for(const p of inspection.files?.[type]??[]){
    if(typeof p!=='string')fail('source inventory','Quarto must provide file paths');const name=key(project,p);if(!name){outside++;continue;}
    if(['.git','.quarto','_extensions'].includes(name.split('/')[0])||name===inspection.config?.project?.['output-dir']||name.startsWith((inspection.config?.project?.['output-dir']??'_site')+'/'))continue;
    paths.add(name);if(type==='input')inputs.push(name);
  }
  const files=[];for(const path of [...paths].sort()){
    const absolute=resolve(project,path);await noLinks(project,resolve(absolute,'..'));const s=await lstat(absolute),asset=prepared.assets.get(path);
    if(asset?.binary){const streamed=await streamAsset(absolute,{maximum:asset.maximum,bytes:asset.bytes,sha256:asset.sha256});files.push({path,sha256:streamed.sha256,preparedBinary:true,bytes:asset.bytes});continue;}
    if(!s.isFile()||s.isSymbolicLink()||s.size>32*1024*1024)fail('source inventory','requires bounded regular source files');files.push({path,sha256:await fileDigest(await readFile(absolute))});
  }
  return {schema:'quarto-declared-source-snapshot/v1',inputs:inputs.sort(),files,digest:await hash(files),effectiveConfigDigest:await hash(inspection.config),outsideEntries:outside,coverage:'quarto-declared input/config/resource files; transitive and generated dependencies unassessed'};
}
export async function beginRun(root,{source=null,outputDir,renderedInputs=null,kind='manual',configDigest=null,kgRunId=null}={}){
  const {project,dir}=await location(root,true),output=resolve(project,outputDir);if(!inside(project,output))fail('output directory','requires a separate directory inside the project');
  const run={schema:'content-security-protocol-run/v1',id:crypto.randomUUID(),kind,outputDir:relative(project,output).split(sep).join('/'),source,renderedInputs,configDigest,...(kgRunId?{kgRunId}:{})};
  await atomic(join(dir,'status.json'),{schema:'content-security-protocol-state/v1',status:'pending',generation:run.id});await atomic(join(dir,'pending.json'),run);return run;
}
export async function pendingRun(root){const {dir}=await location(root);return json(join(dir,'pending.json'));}
function provenance(run,after,previous){
  const inputs=after?.inputs??[],rendered=run.renderedInputs;
  const current=new Map((after?.files??[]).map(f=>[f.path,f.sha256])),before=new Map((previous?.provenance?.source?.files??[]).map(f=>[f.path,f.sha256]));
  return {kind:run.kind,source:after,renderedInputs:rendered,renderCoverage:rendered===null?'unavailable':inputs.length&&inputs.every(p=>rendered.includes(p))?'all-declared-inputs-reported':'partial',sourceComparison:previous?.provenance?.source?'available':'unavailable',removedSources:[...before.keys()].filter(p=>!current.has(p)).sort(),changedUnrenderedSources:rendered===null?[]:[...current.keys()].filter(p=>before.has(p)&&before.get(p)!==current.get(p)&&inputs.includes(p)&&!rendered.includes(p)).sort()};
}
export async function publishReport(root,run,report,{sourceAfter=run.source}={}){
  if(run?.schema!=='content-security-protocol-run/v1'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u.test(run.id)||typeof run.outputDir!=='string'||isAbsolute(run.outputDir)||run.outputDir.split(/[\\/]/u).some(p=>p==='..'||p===''))fail('build state','invalid generation identity/path; start a new audit');
  const {project,dir}=await location(root,true),pending=await json(join(dir,'pending.json'));
  if(pending.id!==run.id)fail('build state','another run replaced this audit; use serial builds');
  if(run.source&&sourceAfter&&(run.source.digest!==sourceAfter.digest||run.source.effectiveConfigDigest!==sourceAfter.effectiveConfigDigest))fail('source state','changed during render/audit; render again after edits finish');
  let previous;try{const r=await json(join(dir,'current.json'));if(/^[a-f0-9-]{36}$/u.test(r.generation)){const prior=join(dir,'generations',r.generation);await noLinks(project,prior);const p=join(prior,'report.json');previous=await json(p);if(await fileDigest(await readFile(p))!==r.hashes?.['report.json'])previous=null;}}catch{previous=null;}
  report.provenance=provenance(run,sourceAfter,previous);
  report.provenance.runtimeDigest=await runtimeDigest();
  report.provenance.configDigest=run.configDigest;
  for(const path of report.provenance.removedSources)report.findings.push({code:'source-roster-removed',path});
  for(const path of report.provenance.changedUnrenderedSources)report.findings.push({code:'changed-unrendered-source',path});
  const bodies={'report.json':JSON.stringify(report,null,2)+'\n','report.md':markdown(report)},hashes={};
  if(encoder.encode(bodies['report.json']).byteLength>8*1024*1024)fail('report limit','generated JSON exceeds the bounded state reader; reduce audited output or findings and retry');
  const generation=join(dir,'generations',run.id);await noLinks(project,join(dir,'generations'),{create:true});await mkdir(generation);
  for(const [name,body]of Object.entries(bodies)){await writeFile(join(generation,name),body,{flag:'wx'});hashes[name]=await fileDigest(encoder.encode(body));}
  // One pointer is committed only after the complete immutable pair exists.
  const receipt={schema:'content-security-protocol-current/v1',generation:run.id,outputDir:run.outputDir,inventoryDigest:report.inventoryDigest,hashes,source:sourceAfter,runtimeDigest:report.provenance.runtimeDigest,configDigest:run.configDigest,policyDigest:await hash(report.declaredPolicy.directives)};
  await atomic(join(dir,'current.json'),receipt);await atomic(join(dir,'status.json'),{schema:'content-security-protocol-state/v1',status:'complete',generation:run.id});
  return {report,receipt,path:relative(project,join(generation,'report.json')).split(sep).join('/')};
}
export async function currentReport(root,{verifyOutput=true,verifySources=true}={}){
  const {project,dir}=await location(root),status=await json(join(dir,'status.json'));
  if(status.schema!=='content-security-protocol-state/v1'||!['pending','complete','failed','disabled','cleared'].includes(status.status))fail('state','unsupported state record; run a new audit');
  if(status.status!=='complete')return {status:status.status,current:false};
  const receipt=await json(join(dir,'current.json'));if(receipt.generation!==status.generation||!/^[a-f0-9-]{36}$/u.test(receipt.generation))fail('state','invalid current generation; run a new audit');
  const generation=join(dir,'generations',receipt.generation);await noLinks(project,generation);
  for(const name of ['report.json','report.md']){const p=join(generation,name);await jsonIfRegular(p);if(await fileDigest(await readFile(p))!==receipt.hashes?.[name])fail('state','report generation hash mismatch; run a new audit');}
  const report=await json(join(generation,'report.json'));
  if(await runtimeDigest()!==receipt.runtimeDigest)return {status:'stale-runtime',current:false};
  let preparedSource;
  if(verifySources&&receipt.source)for(const f of receipt.source.files){
    const p=resolve(project,f.path);if(!inside(project,p))fail('state','source path outside project');
    try{
      await noLinks(project,resolve(p,'..'));
      if(f.preparedBinary===true){
        preparedSource??=await preparedPacks(project,report.scope?.preparedModelPacks??[]);
        const asset=preparedSource.assets.get(f.path);
        if(!asset?.binary||asset.bytes!==f.bytes||asset.sha256!==f.sha256)return {status:'stale-sources',current:false};
        if((await streamAsset(p,{maximum:asset.maximum,bytes:f.bytes})).sha256!==f.sha256)return {status:'stale-sources',current:false};
      }else{await jsonIfRegular(p);if(await fileDigest(await readFile(p))!==f.sha256)return {status:'stale-sources',current:false};}
    }catch(e){if(e.code==='ENOENT')return {status:'stale-sources',current:false};throw e;}
  }
  if(verifyOutput){const output=resolve(project,receipt.outputDir);if(!inside(project,output))fail('state','output path outside project');await noLinks(project,output);const now=await inventory(output,undefined,{retainBytes:false,preparedModelPacks:report.scope?.preparedModelPacks??[]});if(await hash(now.files)!==receipt.inventoryDigest)return {status:'stale-output',current:false};}
  return {status:'current-at-snapshot',current:true,report,receipt,path:relative(project,join(generation,'report.json')).split(sep).join('/')};
}
async function jsonIfRegular(path){const s=await lstat(path);if(!s.isFile()||s.isSymbolicLink()||s.size>128*1024*1024)fail('state','requires bounded regular files');}
export async function compareReports(previous,current){
  if(previous.schema!==current.schema||previous.extensionVersion!==current.extensionVersion||JSON.stringify(previous.declaredPolicy)!==JSON.stringify(current.declaredPolicy)||JSON.stringify(previous.scope)!==JSON.stringify(current.scope)||previous.provenance?.runtimeDigest!==current.provenance?.runtimeDigest)fail('comparison','schema, runtime/version, declared policy and coverage must match');
  const collect=async r=>{const entries=[...r.findings.map(f=>({path:f.path??'',...f})),...r.pages.flatMap(p=>p.findings.map(f=>({path:p.path,...f})))],map=new Map();for(const e of entries){const id=await hash(e);map.set(id,{id,...e});}return map;};
  const before=await collect(previous),after=await collect(current);
  return {schema:'content-security-protocol-comparison/v1',added:[...after.values()].filter(e=>!before.has(e.id)),resolved:[...before.values()].filter(e=>!after.has(e.id)),unchanged:[...after.values()].filter(e=>before.has(e.id)),approval:false,limitations:['Static element-order signatures are versioned observations, not semantic identities.','No baseline/exception automatically authorizes policy or suppresses original findings.']};
}
