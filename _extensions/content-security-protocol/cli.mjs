import {readFile,lstat,realpath,writeFile} from 'node:fs/promises';
import {resolve,join,relative} from 'node:path';
import {VERSION,configuration,fail,fileDigest} from './core.mjs';
import {auditOutput,noLinks} from './audit.mjs';
import {inspectProject,projectOptions} from './context.mjs';
import {beginRun,publishReport,currentReport,markState,snapshotSources,compareReports,STATE} from './state.mjs';
import {failureCount,findingRecords,annotateExceptions,cryptoInventory} from './review.mjs';
import {REVIEWABLE_CODES} from './headers.mjs';
export const HELP=`Content Security Protocol ${VERSION} — explicit local audit tools
quarto run <installed-path>/cli.ts <command> [options]
Commands:
  audit          Audit after all site-changing hooks; commit a private generation
  status         Verify current status, output, source and runtime hashes
  headers        Prepare private Netlify _headers text; never install or deploy it
  accessibility  Run pinned native axe on a private copy of trusted HTML
  compare        Compare a previous audit JSON with the current snapshot
  findings       List private finding IDs for reviewed exceptions
  exceptions     Annotate exact finding IDs without removing original findings
  crypto         Inventory digest uses and unassessed PQC/provider layers
  clear-current  Invalidate current status; preserve history; accepts only --root
Options:
  --root <dir>          Project root (default current directory)
  --output-dir <dir>    Contained audit target; other commands require receipt match
  --config <file>       Explicit JSON extension options; --output-dir then required
  --mode <mode>         headers only: report-only (default), enforce
  --review <file>       headers only: exact inventoryDigest and acknowledged codes
  --previous <file>     compare only: previous bounded audit JSON
  --exceptions <file>   exceptions only: versioned exception object
  --as-of <YYYY-MM-DD>  exceptions only: explicit review date
  --execute-pages      accessibility only: acknowledge executing trusted page JS
  --help               Print without creating files or invoking Quarto
Reports/logs remain private under .quarto/content-security-protocol.
Exit 0 means command completed, not security/WCAG conformance. Status stale or
incomplete accessibility exits 2; accessibility needs-review exits 3.
No push, deployment, remote collector or AI.
Header-review uncertainty codes (never known violations):
${REVIEWABLE_CODES.join(', ')}
`;
async function readJson(path){const s=await lstat(path);if(!s.isFile()||s.isSymbolicLink()||s.size>8*1024*1024)fail('JSON input','use a bounded regular UTF-8 file');try{return JSON.parse(await readFile(path,'utf8'));}catch{fail('JSON input','invalid JSON; no rejected values are echoed');}}
function parse(args){const command=args.shift(),options={};if(!command||command==='--help'||args.includes('--help'))return {command:'help',options};
  const allowed=new Set(['root','output-dir','config','mode','review','previous','exceptions','as-of','execute-pages']);
  for(let i=0;i<args.length;i++){if(!args[i].startsWith('--'))fail('arguments','use documented named options');const key=args[i].slice(2);if(!allowed.has(key)||Object.hasOwn(options,key))fail('arguments','unsupported or duplicate option');if(key==='execute-pages')options[key]=true;else{const value=args[++i];if(!value||value.startsWith('--'))fail('arguments','named option needs a value');options[key]=value;}}
  const specific={audit:[],status:[],headers:['mode','review'],accessibility:['execute-pages'],compare:['previous'],findings:[],exceptions:['exceptions','as-of'],crypto:[],'clear-current':[]};
  if(!Object.hasOwn(specific,command))fail('command','choose a documented command');const common=command==='clear-current'?['root']:['root','output-dir','config'];for(const k of Object.keys(options))if(![...common,...specific[command]].includes(k))fail('arguments','option is unsupported for this command');return {command,options};
}
export async function main(args,{print=console.log}={}){
  const {command,options}=parse([...args]);if(command==='help'){print(HELP);return 0;}
  const root=await realpath(resolve(options.root??'.'));
  if(command==='clear-current'){await markState(root,'cleared');print('Current status cleared; historical generations retained.');return 0;}
  let inspection,optionsValue,source=null,outputDir=options['output-dir'];
  if(options.config){if(!outputDir)fail('output directory','manual JSON configuration requires --output-dir');optionsValue=await readJson(resolve(root,options.config));configuration(optionsValue);}
  else {inspection=await inspectProject(root);optionsValue=projectOptions(inspection).value;source=await snapshotSources(root,inspection);outputDir??=inspection.config.project?.['output-dir'];}
  if(command==='audit'){
    const config=configuration(optionsValue);if(!config)fail('configuration','activate enabled: true before an explicit audit');
    const run=await beginRun(root,{source,outputDir,kind:'manual-after-hooks',configDigest:await fileDigest(new TextEncoder().encode(JSON.stringify(optionsValue)))});
    try{const report=await auditOutput(root,outputDir,optionsValue),result=await publishReport(root,run,report,{sourceAfter:inspection?await snapshotSources(root,await inspectProject(root)):null});print(JSON.stringify({assessment:report.assessment,report:result.path,securityConformance:false}));return failureCount(report,config.failOn)?1:0;}
    catch(error){await markState(root,'failed');throw error;}
  }
  let state;try{state=await currentReport(root);}catch(e){if(e.code==='ENOENT')state={status:'unavailable',current:false};else throw e;}
  if(state.current&&outputDir!==undefined&&relative(resolve(root,state.receipt.outputDir),resolve(root,outputDir))!=='')state={status:'stale-output-directory',current:false};
  if(state.current&&state.receipt.configDigest&&state.receipt.configDigest!==await fileDigest(new TextEncoder().encode(JSON.stringify(optionsValue))))state={status:'stale-configuration',current:false};
  if(state.current&&source&&source.digest!==state.receipt.source?.digest)state={status:'stale-sources',current:false};
  if(state.current&&source&&source.effectiveConfigDigest!==state.receipt.source?.effectiveConfigDigest)state={status:'stale-configuration',current:false};
  if(command==='status'){print(JSON.stringify({status:state.status,current:state.current,report:state.path??null}));return state.current?0:2;}
  if(!state.current)fail('current report','stale, disabled, failed or pending; run audit after all output changes');
  if(source&&state.receipt.source?.effectiveConfigDigest!==source.effectiveConfigDigest)fail('effective configuration','changed since audit; run a new audit in this profile');
  if(command==='headers'){
    const {prepareHeaders}=await import('./headers.mjs'),review=options.review?await readJson(resolve(root,options.review)):undefined;
    const result=await prepareHeaders(root,state.receipt.outputDir,state.report,{adapter:'netlify',mode:options.mode??'report-only',...(review?{review}:{})});
    print(JSON.stringify({artifact:result.artifactPath,sha256:result.sha256,delivered:false,deployed:false}));return 0;
  }
  if(command==='accessibility'){
    const {runAccessibility}=await import('./accessibility.mjs');const result=await runAccessibility(root,state.receipt.outputDir,state.report,{acknowledgeExecution:options['execute-pages']===true});
    print(JSON.stringify({assessment:result.assessment,artifactDirectory:result.artifactDirectory,conformance:false}));return result.assessment==='incomplete'?2:result.assessment==='findings'?1:result.assessment==='needs-review'?3:0;
  }
  let result;
  if(command==='compare'){if(!options.previous)fail('comparison','provide --previous');result=await compareReports(await readJson(resolve(root,options.previous)),state.report);}
  if(command==='findings')result=await findingRecords(state.report);
  if(command==='exceptions'){if(!options.exceptions||!options['as-of'])fail('exceptions','provide --exceptions and --as-of');result=await annotateExceptions(state.report,await readJson(resolve(root,options.exceptions)),options['as-of']);}
  if(command==='crypto')result=cryptoInventory(state.report);
  const dir=join(root,STATE,'derived');await noLinks(root,dir,{create:true});const name=command+'-'+crypto.randomUUID()+'.json';await writeFile(join(dir,name),JSON.stringify(result,null,2)+'\n',{flag:'wx'});
  print(JSON.stringify({artifact:STATE+'/derived/'+name,approval:false}));return 0;
}
