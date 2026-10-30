// Importing this module performs no inspection, audit or writes. The native
// post hook and the graph publisher explicitly choose when to call it.
import {lstat,readFile,readdir,realpath,writeFile,rename,unlink} from 'node:fs/promises';
import {join,resolve,relative,sep} from 'node:path';
import {inspectProject,projectOptions,projectOutput,renderInputs} from './context.mjs';
import {snapshotSources,pendingRun,publishReport,markState,STATE} from './state.mjs';
import {auditOutput,noLinks} from './audit.mjs';
import {fail,fileDigest} from './core.mjs';
import {failureCount} from './review.mjs';

export const COMPOSITION_FINALIZER_VERSION=1;
export const DEFERRED_COMPOSITION=STATE+'/deferred-composition.json';
const GRAPH_STATE='.quarto/knowledge-graph',UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const HASH=/^[a-f0-9]{64}$/u;
const env=name=>typeof Deno!=='undefined'?Deno.env.get(name):process.env[name];
const outputKey=(root,value)=>relative(root,resolve(root,value)).split(sep).join('/');
async function optionalJson(root,name){
  const path=join(root,name);
  try{
    await noLinks(root,resolve(path,'..'));const stat=await lstat(path);
    if(!stat.isFile()||stat.isSymbolicLink()||stat.size>8*1024*1024)fail('composition state','requires bounded regular private state files');
    try{return JSON.parse(await readFile(path,'utf8'));}catch{fail('composition state','invalid private JSON; render again');}
  }catch(error){if(error.code==='ENOENT')return null;throw error;}
}
async function removeMarker(root){
  await noLinks(root,join(root,STATE));const path=join(root,DEFERRED_COMPOSITION);
  try{const stat=await lstat(path);if(!stat.isFile()||stat.isSymbolicLink())fail('composition state','requires a regular private marker');await unlink(path);}catch(error){if(error.code!=='ENOENT')throw error;}
}
async function writeMarker(root,value){
  await noLinks(root,join(root,STATE));const path=join(root,DEFERRED_COMPOSITION),temp=path+'.'+crypto.randomUUID()+'.tmp';
  try{
    await writeFile(temp,JSON.stringify(value,null,2)+'\n',{flag:'wx'});
    try{const stat=await lstat(path);if(!stat.isFile()||stat.isSymbolicLink())fail('composition state','requires a regular private marker');}catch(error){if(error.code!=='ENOENT')throw error;}
    await rename(temp,path);
  }finally{try{await unlink(temp);}catch(error){if(error.code!=='ENOENT')throw error;}}
}
function terminalGraph(receipt,runId,snapshotId){
  return receipt?.runId===runId&&(snapshotId===null
    ? ['no-output-pages','no-html-observations'].includes(receipt.status)&&receipt.snapshotId==null
    : HASH.test(snapshotId??'')&&receipt.snapshotId===snapshotId&&['complete','incomplete'].includes(receipt.status));
}
async function oneInstalledGraph(root){
  const base=join(root,'_extensions');let entries;
  try{await noLinks(root,base);entries=await readdir(base,{withFileTypes:true});}catch(error){if(error.code==='ENOENT')return false;throw error;}
  if(entries.length>500)fail('composition state','too many installed extension namespaces');
  const candidates=[join(base,'knowledge-graph-extraction'),...entries.filter(entry=>entry.isDirectory()&&entry.name!=='knowledge-graph-extraction').map(entry=>join(base,entry.name,'knowledge-graph-extraction'))];
  let found=0;
  for(const path of candidates){
    try{
      await noLinks(root,path);
      for(const name of ['_extension.yml','prepare.ts']){const stat=await lstat(join(path,name));if(!stat.isFile()||stat.isSymbolicLink()||stat.size>8*1024*1024)fail('composition state','requires a regular installed graph extension');}
      found++;
    }catch(error){if(error.code!=='ENOENT')throw error;}
  }
  if(found>1)fail('composition state','expected one installed graph extension; remove duplicate copies');
  return found===1;
}
async function graphRun(root,inspection,outputDir){
  if(inspection.config?.['knowledge-graph']?.enabled===false)return null;
  const run=await optionalJson(root,GRAPH_STATE+'/run.json');
  if(!run)return null;
  // Older graph runtimes cannot call this finalizer. They retain the existing
  // explicit audit-after-hooks workflow instead of an unfinishable deferral.
  if(run.compositionVersion!==1||run.active!==true)return null;
  // KG's native prepare resolves project/page/directory selectors itself.
  // Its current run plus installed package is the composition authority; do
  // not duplicate that resolution with extra per-page inspection processes.
  if(!await oneInstalledGraph(root))return null;
  if(!UUID.test(run.runId??'')||run.contractVersion!==0||run.stateDir!==GRAPH_STATE||typeof run.outputDir!=='string')fail('composition state','invalid graph run; render again');
  if(outputKey(root,run.outputDir)!==outputKey(root,outputDir))return null;
  const prepared=await optionalJson(root,GRAPH_STATE+'/runs/'+run.runId+'/prepared.json');
  if(prepared?.runId!==run.runId||prepared.outputDir!==run.outputDir||prepared.compositionVersion!==1||prepared.active!==true)fail('composition state','graph run has no matching preparation; render again');
  return run;
}
/** Either prepare hook may run first; each extension binds its own pending run. */
export async function preparedGraphRunId(root,inspection,outputDir){
  return (await graphRun(root,inspection,outputDir))?.runId??null;
}
const boundRuns=(graph,run)=>{
  if(graph.cspRunId!==run.id&&run.kgRunId!==graph.runId)return false;
  if(run.renderedInputs===null)return true;
  if(!Array.isArray(graph.allRenderedSources)||!Array.isArray(run.renderedInputs)
    ||JSON.stringify([...new Set(graph.allRenderedSources)].sort())!==JSON.stringify([...new Set(run.renderedInputs)].sort()))fail('composition state','native input inventories disagree; render again');
  return true;
};
async function audit(root,inspection,run,options,{inputs=renderInputs,print=console.log}={}){
  const digest=await fileDigest(new TextEncoder().encode(JSON.stringify(options.value)));
  if(run.configDigest&&run.configDigest!==digest)fail('composition state','audit configuration changed during rendering; render again');
  const lateInputs=await inputs(root);if(lateInputs!==null)run={...run,renderedInputs:lateInputs};
  const report=await auditOutput(root,projectOutput(root,inspection),options.value);
  const published=await publishReport(root,run,report,{sourceAfter:await snapshotSources(root,inspection)});
  await removeMarker(root);
  if(env('QUARTO_PROJECT_SCRIPT_QUIET')!=='1')print(`content-security-protocol: audit only; ${report.pages.length} HTML pages, ${report.files.length} files; use the installed CLI status command for freshness`);
  if(failureCount(published.report,options.config.failOn))fail('audit findings','configured fail-on threshold met; review the private current generation');
  return {status:'complete',generation:published.receipt.generation};
}

/** Native post-render: defer only an explicitly selected, prepared graph run. */
export async function finalizeNativeAudit(root,{inspect=inspectProject,...services}={}){
  root=await realpath(root);const inspection=await inspect(root),options=projectOptions(inspection);
  if(!options.config){await markState(root,'disabled');return {status:'disabled'};}
  const run=await pendingRun(root),outputDir=projectOutput(root,inspection);
  const graph=await graphRun(root,inspection,outputDir);
  if(graph&&boundRuns(graph,run)){
    const receipt=await optionalJson(root,GRAPH_STATE+'/runs/'+graph.runId+'/finalized.json');
    if(!receipt){
      const state=await optionalJson(root,STATE+'/status.json');
      if(state?.status!=='pending'||state.generation!==run.id)fail('composition state','audit generation is no longer pending; render again');
      await writeMarker(root,{schema:'content-security-protocol-deferred-composition/v1',kgRunId:graph.runId,cspRunId:run.id,outputDir:outputKey(root,outputDir)});
      return {status:'pending-composition'};
    }
    if(!terminalGraph(receipt,graph.runId,receipt.snapshotId??null))fail('composition state','graph completion is invalid; render again');
  }
  return audit(root,inspection,run,options,services);
}

/** Called by KG only after its final public bytes and completion receipt exist. */
export async function finalizeAfterComposition({root,kgRunId,snapshotId},{inspect=inspectProject,...services}={}){
  root=await realpath(root);
  if(!UUID.test(kgRunId??'')||(snapshotId!==null&&!HASH.test(snapshotId??'')))fail('composition state','invalid graph completion identity');
  const marker=await optionalJson(root,DEFERRED_COMPOSITION);
  if(!marker)return {status:'skipped',reason:'no-pending-composition'};
  if(marker.schema!=='content-security-protocol-deferred-composition/v1'||!UUID.test(marker.cspRunId??'')||marker.kgRunId!==kgRunId)return {status:'skipped',reason:'stale-composition'};
  const state=await optionalJson(root,STATE+'/status.json'),run=await pendingRun(root);
  if(state?.status!=='pending'||state.generation!==marker.cspRunId||run.id!==marker.cspRunId)return {status:'skipped',reason:'stale-audit-generation'};
  const inspection=await inspect(root),options=projectOptions(inspection);
  if(!options.config)return {status:'skipped',reason:'inactive-audit'};
  const outputDir=projectOutput(root,inspection);
  if(marker.outputDir!==outputKey(root,outputDir)||marker.outputDir!==outputKey(root,run.outputDir))return {status:'skipped',reason:'stale-output-directory'};
  const graph=await graphRun(root,inspection,outputDir);
  const receipt=await optionalJson(root,GRAPH_STATE+'/runs/'+kgRunId+'/finalized.json');
  if(graph?.runId!==kgRunId||!boundRuns(graph,run)||!terminalGraph(receipt,kgRunId,snapshotId))return {status:'skipped',reason:'graph-not-finalized'};
  try{return await audit(root,inspection,run,options,services);}
  catch(error){await markState(root,'failed');throw error;}
}
