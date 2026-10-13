// Explicit, private orchestration of Quarto's experimental native axe scanner.
// No browser code is bundled and ordinary rendering never calls this adapter.
import {lstat,readdir,readFile,realpath,mkdir,mkdtemp,writeFile} from 'node:fs/promises';
import {join,resolve,relative,isAbsolute,sep} from 'node:path';
import {spawn,spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {Buffer} from 'node:buffer';
import process from 'node:process';
import {VERSION} from './core.mjs';

export const ACCESSIBILITY_NATIVE_VERSION='1.11.5';
export const ACCESSIBILITY_AXE_VERSION='4.10.3';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const failure=code=>{const error=new Error('content-security-protocol: accessibility '+code+'; inspect the private run artifacts and documented prerequisites');error.code=code;return error;};
const regularPath=value=>typeof value==='string'&&value.length>0&&!value.includes('\\')&&!isAbsolute(value)&&value.split('/').every(x=>x&&x!=='.'&&x!=='..'&&!x.includes('\0'));
const within=(root,path)=>{const r=relative(root,path);return r!==''&&!isAbsolute(r)&&r!=='..'&&!r.startsWith('..'+sep);};
const integer=(v,min,max)=>Number.isInteger(v)&&v>=min&&v<=max;
const ruleId=value=>typeof value==='string'&&/^[a-z][a-z0-9-]{0,119}$/u.test(value);
const impacts=new Set(['minor','moderate','serious','critical']);
const wcagAA=new Set(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22a','wcag22aa']);
const summaryCodes=new Set(['native-version-unavailable','unsupported-native-version','native-command-failed','native-timeout','native-output-truncated','native-artifacts-missing','native-artifacts-invalid','native-scan-incomplete','native-empty-result','output-changed','staging-changed']);

function optionsFor(value={}){
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!['acknowledgeExecution','timeoutMs','totalTimeoutMs','settleMs','executable'].includes(k)))throw failure('invalid-options');
  if(value.acknowledgeExecution!==true)throw failure('requires-explicit-trusted-page-execution');
  const options={timeoutMs:30000,totalTimeoutMs:600000,settleMs:100,executable:'quarto',...value};
  if(!integer(options.timeoutMs,1000,120000)||!integer(options.totalTimeoutMs,options.timeoutMs,3600000)||!integer(options.settleMs,0,10000))throw failure('invalid-time-limits');
  // One executable, never a shell command. An absolute installed path may be supplied.
  if(typeof options.executable!=='string'||(!isAbsolute(options.executable)&&options.executable!=='quarto')||/[\r\n\0]/u.test(options.executable))throw failure('invalid-executable');
  return options;
}

async function directories(root,path){
  if(!within(root,path))throw failure('invalid-private-path');
  let at=root;
  for(const part of relative(root,path).split(sep)){
    at=join(at,part);try{await mkdir(at);}catch(error){if(error.code!=='EEXIST')throw failure('private-directory-unavailable');}
    const state=await lstat(at);if(state.isSymbolicLink()||!state.isDirectory())throw failure('linked-private-path');
  }
}

async function snapshot(output,expected){
  const files=[],data=new Map();let total=0;
  async function walk(dir){
    const entries=(await readdir(dir,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name));
    for(const entry of entries){
      const path=join(dir,entry.name),state=await lstat(path),name=relative(output,path).split(sep).join('/');
      if(state.isSymbolicLink())throw failure('linked-output');
      if(state.isDirectory())await walk(path);
      else{
        if(!state.isFile()||!regularPath(name)||files.length>=5000||state.size>32*1024*1024||(total+=state.size)>128*1024*1024)throw failure('output-limits');
        // A rendered project configuration would move native report placement.
        if(name.split('/').includes('_quarto.yml')||name.split('/').includes('_quarto.yaml'))throw failure('output-project-configuration');
        const bytes=await readFile(path);if(bytes.length!==state.size)throw failure('output-changed');
        files.push({path:name,bytes:bytes.length,sha256:sha(bytes)});data.set(name,bytes);
      }
    }
  }
  await walk(output);
  if(JSON.stringify(files)!==JSON.stringify(expected))throw failure('output-changed');
  return data;
}

async function jsonFile(path,maxBytes=32*1024*1024){
  const state=await lstat(path);if(state.isSymbolicLink()||!state.isFile()||state.size>maxBytes)throw failure('native-artifacts-invalid');
  const bytes=await readFile(path);return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
}

// The runner receives an argv array and captures output privately. A process-tree
// kill is attempted on the outer budget; the native per-cell timeout is separate.
export async function accessibilityRunner(executable,args,{cwd,timeoutMs,env,maxOutputBytes=1024*1024}={}){
  return await new Promise(resolveResult=>{
    let child,ended=false,timedOut=false,truncated=false,stdout=[],stderr=[],outSize=0,errSize=0,timer;
    const finish=(exitCode,signal)=>{if(ended)return;ended=true;clearTimeout(timer);resolveResult({exitCode,signal:signal??null,timedOut,truncated,stdout:Buffer.concat(stdout).toString('utf8'),stderr:Buffer.concat(stderr).toString('utf8')});};
    try{child=spawn(executable,args,{cwd,env,stdio:['ignore','pipe','pipe'],shell:false,windowsHide:true,detached:process.platform!=='win32'});}catch{finish(null,null);return;}
    const capture=(kind,chunk)=>{
      const old=kind==='stdout'?outSize:errSize;
      if(old<maxOutputBytes)(kind==='stdout'?stdout:stderr).push(chunk.subarray(0,maxOutputBytes-old));
      if(kind==='stdout')outSize+=chunk.length;else errSize+=chunk.length;
      if(old+chunk.length>maxOutputBytes)truncated=true;
    };
    child.stdout.on('data',chunk=>capture('stdout',chunk));child.stderr.on('data',chunk=>capture('stderr',chunk));
    child.on('error',()=>finish(null,null));child.on('close',finish);
    timer=setTimeout(()=>{
      timedOut=true;
      if(process.platform==='win32'&&child.pid)spawnSync('taskkill',['/PID',String(child.pid),'/T','/F'],{stdio:'ignore',windowsHide:true,timeout:5000});
      else if(child.pid){try{process.kill(-child.pid,'SIGKILL');}catch{child.kill('SIGKILL');}}
      else child.kill('SIGKILL');
      // Preserve a bounded failure even if the platform cannot reap a descendant.
      setTimeout(()=>finish(null,'SIGKILL'),2000).unref?.();
    },timeoutMs);
  });
}

function ruleScope(tags){
  if(tags.some(t=>wcagAA.has(t)))return 'wcag-2.2-aa-automated';
  if(tags.includes('best-practice'))return 'best-practice';
  return 'other-native-rule';
}

function safeRules(rules,kind,page,viewport,theme){
  if(!Array.isArray(rules))throw failure('native-artifacts-invalid');
  return rules.map(rule=>{
    if(!ruleId(rule?.id)||!Array.isArray(rule.tags)||rule.tags.some(t=>typeof t!=='string')||!Array.isArray(rule.nodes)||!(rule.impact===null||impacts.has(rule.impact)))throw failure('native-artifacts-invalid');
    return {kind,rule:rule.id,impact:rule.impact,scope:ruleScope(rule.tags),page,viewport,theme,nodes:rule.nodes.length};
  });
}

async function parsedArtifacts(stage,manifest,options){
  const native=join(stage,'_axe-checks'),findings=await jsonFile(join(native,'findings.json'));
  if(findings.version!==2||findings.signatureScheme!==1||findings.quartoVersion!==ACCESSIBILITY_NATIVE_VERSION||findings.axeVersion!==ACCESSIBILITY_AXE_VERSION||!Array.isArray(findings.pages)||findings.pages.length===0||!Array.isArray(findings.findings)||findings.baseline?.entries!==0)throw failure('native-artifacts-invalid');
  const config=findings.config;
  if(!config||config.siteDir!=='_site'||JSON.stringify(config.viewports)!==JSON.stringify(['1440x900','320x568'])||JSON.stringify(config.themes)!==JSON.stringify(['light','dark'])||config.pages!==null||config.maxPages!==null||(config.exclude??null)!==null||config.timeout!==options.timeoutMs||config.settle!==options.settleMs||config.failOn!=='minor')throw failure('native-artifacts-invalid');
  const html=new Set(manifest.filter(f=>f.path.endsWith('.html')&&!f.path.split('/').some(p=>p==='site_libs'||p==='_axe-checks')).map(f=>f.path));
  const expected=new Set(),covered=new Set();
  for(const page of findings.pages){
    if(!regularPath(page.output)||!html.has(page.output)||covered.has(page.output)||!Array.isArray(page.modes)||page.modes.length===0||new Set(page.modes).size!==page.modes.length||page.modes.some(m=>!['light','dark','default'].includes(m)))throw failure('native-artifacts-invalid');
    covered.add(page.output);
    for(const viewport of config.viewports)for(const theme of page.modes)expected.add(JSON.stringify([page.output,viewport,theme]));
  }
  let redirects=0;
  for(const stub of findings.redirects??[]){if(!regularPath(stub.output)||!html.has(stub.output)||covered.has(stub.output))throw failure('native-artifacts-invalid');covered.add(stub.output);redirects++;}
  if(covered.size!==html.size||!integer(findings.pagesScanned,0,findings.pages.length)||findings.cells?.total!==expected.size||!integer(findings.cells?.ok,0,expected.size)||!integer(findings.cells?.notOk,0,expected.size)||findings.cells.ok+findings.cells.notOk!==expected.size||!Array.isArray(findings.notOkCells))throw failure('native-artifacts-invalid');
  const paths=(await readdir(join(native,'cells'),{withFileTypes:true}));
  if(paths.length!==expected.size||paths.some(p=>!p.isFile()||!p.name.endsWith('.json')))throw failure('native-artifacts-invalid');
  const violations=[],failedCells=[],scannedPages=new Set();
  for(const file of paths){
    const cell=await jsonFile(join(native,'cells',file.name)),key=JSON.stringify([cell.page,cell.viewport,cell.theme]);
    if(!expected.delete(key))throw failure('native-artifacts-invalid');
    if(cell.status!=='ok'){failedCells.push({page:cell.page,viewport:cell.viewport,theme:cell.theme,status:['timeout','error','redirected','no-payload'].includes(cell.status)?cell.status:'unrecognized'});continue;}
    const result=cell.result;
    // Native 1.11.5 intentionally projects violations only. It does not retain
    // axe's incomplete/pass/inapplicable arrays; absence cannot become a pass.
    if(!result||Object.keys(result).sort().join(',')!=='testEngine,timestamp,url,violations'||result.testEngine?.name!=='axe-core'||result.testEngine?.version!==findings.axeVersion||typeof result.timestamp!=='string'||!Number.isFinite(Date.parse(result.timestamp)))throw failure('native-artifacts-invalid');
    let url;try{url=new URL(result.url);}catch{throw failure('native-artifacts-invalid');}
    if(url.protocol!=='http:'||url.hostname!=='127.0.0.1'||url.username||url.password||url.search||url.hash||url.pathname!=='/'+cell.page.split('/').map(encodeURIComponent).join('/'))throw failure('native-artifacts-invalid');
    scannedPages.add(cell.page);violations.push(...safeRules(result.violations,'violation',cell.page,cell.viewport,cell.theme));
  }
  if(expected.size||failedCells.length!==findings.cells.notOk||scannedPages.size!==findings.pagesScanned||findings.notOkCells.length!==failedCells.length)throw failure('native-artifacts-invalid');
  const needsReview=[{kind:'coverage-gap',code:'native-uncertain-checks-not-reported',scope:'all-native-rule-cells'}];
  return {axeVersion:findings.axeVersion,pages:findings.pages.length,redirects,cells:{total:findings.cells.total,ok:findings.cells.ok,failed:failedCells.length},violations,needsReview,failedCells,passes:null,inapplicable:null};
}

export async function runAccessibility(projectRoot,outputDir,report,value={}, {runner=accessibilityRunner}={}){
  const options=optionsFor(value),root=await realpath(projectRoot),output=resolve(root,outputDir);
  if(!within(root,output)||relative(root,output).split(sep).some(p=>['.quarto','.git','_extensions'].includes(p)))throw failure('invalid-output-path');
  const outputState=await lstat(output);if(outputState.isSymbolicLink()||!outputState.isDirectory()||await realpath(output)!==output)throw failure('linked-output');
  if(report?.schema!=='content-security-protocol-audit/v1'||report.mode!=='audit'||report.scope?.inventoryComplete!==true||!Array.isArray(report.files)||!report.files.length||report.inventoryDigest!==sha(Buffer.from(JSON.stringify(report.files))))throw failure('invalid-current-audit');
  const data=await snapshot(output,report.files);
  if(!report.files.some(file=>file.path.endsWith('.html')))throw failure('empty-html-inventory');
  const parent=join(root,'.quarto','content-security-protocol','accessibility');await directories(root,parent);
  const stage=await mkdtemp(join(parent,'run-')),site=join(stage,'_site');await mkdir(site);
  await writeFile(join(stage,'_quarto.yml'),'project:\n  type: website\n  output-dir: _site\n',{flag:'wx'});
  for(const [name,bytes]of data){const path=join(site,...name.split('/'));await mkdir(resolve(path,'..'),{recursive:true});await writeFile(path,bytes,{flag:'wx'});}
  const artifactDirectory=relative(root,stage).split(sep).join('/');
  const summary={schema:'content-security-protocol-accessibility/v1',extensionVersion:VERSION,assessment:'incomplete',snapshot:{inventoryDigest:report.inventoryDigest,files:report.files.length},artifactDirectory,native:{quartoVersion:null,axeVersion:null,findingsVersion:2,signatureScheme:1},scope:{standard:'WCAG 2.2 AA automated subset',nativeRules:'native default all rules; WCAG subset classified by result tags',uncertainChecks:'not-reported-by-native; manual review required',viewports:['1440x900','320x568'],themes:['light','dark'],states:'initial page load; discovered native color modes only',network:'not-sandboxed; page code may access external resources',baseline:'none; accepted findings are never suppressed',conformance:'not-established'},findings:[],needsReview:[],failures:[]};
  const env={...process.env};for(const key of ['QUARTO_PROJECT_OUTPUT_DIR','QUARTO_PROJECT_RENDER_ALL','QUARTO_PROJECT_INPUT_FILES','QUARTO_PROJECT_OUTPUT_FILES','QUARTO_USE_FILE_FOR_PROJECT_INPUT_FILES','QUARTO_USE_FILE_FOR_PROJECT_OUTPUT_FILES','QUARTO_PROJECT_DIR','QUARTO_PROJECT_SCRIPT_QUIET','QUARTO_PROFILE'])delete env[key];
  async function execute(label,args,budget){
    let result;try{result=await runner(options.executable,args,{cwd:stage,timeoutMs:budget,env,maxOutputBytes:1024*1024});}catch{throw failure('native-command-failed');}
    const safe={exitCode:Number.isInteger(result?.exitCode)?result.exitCode:null,signal:typeof result?.signal==='string'?result.signal:null,timedOut:result?.timedOut===true,truncated:result?.truncated===true};
    await writeFile(join(stage,label+'.stdout.log'),typeof result?.stdout==='string'?result.stdout.slice(0,1024*1024):'',{flag:'wx'});
    await writeFile(join(stage,label+'.stderr.log'),typeof result?.stderr==='string'?result.stderr.slice(0,1024*1024):'',{flag:'wx'});
    await writeFile(join(stage,label+'.command.json'),JSON.stringify({executable:options.executable,args,...safe},null,2)+'\n',{flag:'wx'});
    if(safe.timedOut)throw failure('native-timeout');if(safe.truncated)throw failure('native-output-truncated');return {...safe,stdout:result?.stdout};
  }
  try{
    const version=await execute('version',['--version'],15000);if(version.exitCode!==0||typeof version.stdout!=='string')throw failure('native-version-unavailable');
    const actual=version.stdout.trim();if(actual!==ACCESSIBILITY_NATIVE_VERSION)throw failure('unsupported-native-version');summary.native.quartoVersion=actual;
    const args=['call','axe','_site','--viewports','1440x900,320x568','--themes','light,dark','--timeout',String(options.timeoutMs),'--settle',String(options.settleMs),'--fail-on','minor','--quiet'];
    const native=await execute('scan',args,options.totalTimeoutMs);summary.native.exitCode=native.exitCode;
    if(![0,1,2].includes(native.exitCode))throw failure('native-command-failed');
    let parsed;try{parsed=await parsedArtifacts(stage,report.files,options);}catch(error){if(error.code==='ENOENT')throw failure('native-artifacts-missing');throw error;}
    summary.native.axeVersion=parsed.axeVersion;summary.coverage={pages:parsed.pages,redirectStubs:parsed.redirects,cells:parsed.cells,passedRuleCells:parsed.passes,inapplicableRuleCells:parsed.inapplicable};
    summary.findings=parsed.violations;summary.needsReview=parsed.needsReview;summary.failedCells=parsed.failedCells;
    if(parsed.failedCells.length||native.exitCode===2)throw failure('native-scan-incomplete');
    if((native.exitCode===0&&parsed.violations.length)||(native.exitCode===1&&!parsed.violations.length))throw failure('native-artifacts-invalid');
    await snapshot(output,report.files);try{await snapshot(site,report.files);}catch{throw failure('staging-changed');}
    summary.assessment=summary.findings.length?'findings':summary.needsReview.length?'needs-review':'automated-checks-complete';
  }catch(error){summary.failures.push({code:summaryCodes.has(error?.code)?error.code:'native-artifacts-invalid'});}
  await writeFile(join(stage,'summary.json'),JSON.stringify(summary,null,2)+'\n',{flag:'wx'});
  return summary;
}
