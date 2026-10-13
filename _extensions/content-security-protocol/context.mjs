import {join,resolve,relative,sep} from 'node:path';
import {readFile} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {configuration,fail} from './core.mjs';
import {inside} from './audit.mjs';
const env=name=>typeof Deno!=='undefined'?Deno.env.get(name):process.env[name];
const INSPECT_TIMEOUT_MS=30000,INSPECT_MAX_BYTES=16*1024*1024;
// Drain both pipes together, but retain only bounded stdout. Command.output()
// buffers without a byte limit and could otherwise hang a native render hook.
async function denoInspection(executable,root){
  let child,timer,stopped=false;const readers=new Set();
  const stop=()=>{
    if(stopped)return;stopped=true;
    try{child?.kill('SIGKILL');}catch{/* The owned child may already have exited. */}
    for(const reader of readers)try{reader.cancel().catch(()=>{});}catch{/* A completed reader may already be released. */}
  };
  const collect=async(stream,retain)=>{
    const reader=stream.getReader(),chunks=[];readers.add(reader);let bytes=0;
    try{
      for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>INSPECT_MAX_BYTES)throw new Error('inspection output limit');if(retain)chunks.push(value);}
      if(!retain)return null;const result=new Uint8Array(bytes);let offset=0;for(const chunk of chunks){result.set(chunk,offset);offset+=chunk.byteLength;}return result;
    }catch(error){try{reader.cancel().catch(()=>{});}catch{/* Already closed pipe. */}throw error;}
    finally{readers.delete(reader);reader.releaseLock();}
  };
  try{
    child=new Deno.Command(executable,{args:['inspect',root],cwd:root,stdin:'null',stdout:'piped',stderr:'piped'}).spawn();
    const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>{stop();reject(new Error('inspection timeout'));},INSPECT_TIMEOUT_MS);});
    const [stdout,,status]=await Promise.race([Promise.all([collect(child.stdout,true),collect(child.stderr,false),child.status]),deadline]);
    if(!status.success)throw new Error('inspection exit');return new TextDecoder().decode(stdout);
  }catch{stop();fail('configuration','quarto inspect failed; use its native diagnostics separately');}
  finally{clearTimeout(timer);}
}
export async function inspectProject(root){
  const bin=env('QUARTO_BIN_PATH'),executable=bin?join(bin,(typeof Deno!=='undefined'?Deno.build.os==='windows':process.platform==='win32')?'quarto.exe':'quarto'):'quarto';
  let text;
  if(typeof Deno!=='undefined')text=await denoInspection(executable,root);
  else{try{text=(await promisify(execFile)(executable,['inspect',root],{cwd:root,timeout:INSPECT_TIMEOUT_MS,maxBuffer:INSPECT_MAX_BYTES,windowsHide:true})).stdout;}catch{fail('configuration','quarto inspect failed; use its native diagnostics separately');}}
  let inspection;try{inspection=JSON.parse(text);}catch{fail('configuration','native inspection must return project JSON');}
  if(!inspection.config||!inspection.files)fail('configuration','requires a Quarto project; for a standalone audit specify --config and --output-dir');return inspection;
}
export function projectOptions(inspection){
  const c=inspection.config,value=c['content-security-protocol'];
  if(value===undefined&&(c['content-security-policy']!==undefined||c.csp_protocol!==undefined))fail('legacy configuration','migrate to content-security-protocol; old rewriting options are unsupported');
  return {value,config:configuration(value)};
}
export async function renderInputs(root){
  const file=env('QUARTO_USE_FILE_FOR_PROJECT_INPUT_FILES'),raw=file?await readFile(file,'utf8'):env('QUARTO_PROJECT_INPUT_FILES');
  if(raw===undefined)return null;
  return raw.split(/\r?\n/u).filter(Boolean).map(p=>{const absolute=resolve(root,p);if(!inside(root,absolute))fail('render inventory','must contain contained native input paths');return relative(root,absolute).split(sep).join('/');}).sort();
}
export function projectOutput(root,inspection){const value=env('QUARTO_PROJECT_OUTPUT_DIR')??inspection.config.project?.['output-dir'];if(typeof value!=='string'||!value)fail('output directory','set a separate project output-dir');return value;}
