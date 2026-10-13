import {inspectProject,projectOptions,projectOutput,renderInputs} from './context.mjs';
import {snapshotSources,pendingRun,publishReport,markState} from './state.mjs';
import {auditOutput} from './audit.mjs';
import {fail} from './core.mjs';
import {failureCount} from './review.mjs';
try {
  const root=await Deno.realPath(Deno.cwd()),inspection=await inspectProject(root),options=projectOptions(inspection);
  if(options.config){
    const run=await pendingRun(root),lateInputs=await renderInputs(root);if(lateInputs!==null)run.renderedInputs=lateInputs;
    const report=await auditOutput(root,projectOutput(root,inspection),options.value);
    const published=await publishReport(root,run,report,{sourceAfter:await snapshotSources(root,inspection)});
    if(Deno.env.get('QUARTO_PROJECT_SCRIPT_QUIET')!=='1')console.log(`content-security-protocol: audit only; ${report.pages.length} HTML pages, ${report.files.length} files; use the installed CLI status command for freshness`);
    if(failureCount(published.report,options.config.failOn))fail('audit findings','configured fail-on threshold met; review the private current generation');
  }else await markState(root,'disabled');
}catch(error){
  try{await markState(Deno.cwd(),'failed');}catch{}
  console.error(error instanceof Error&&error.message.startsWith('content-security-protocol:')?error.message:'content-security-protocol: audit failed; check configuration, permissions, regular files and output limits');Deno.exit(1);
}
