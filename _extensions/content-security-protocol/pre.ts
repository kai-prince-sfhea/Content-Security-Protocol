import {inspectProject,projectOptions,projectOutput,renderInputs} from './context.mjs';
import {snapshotSources,beginRun,markState} from './state.mjs';
import {fileDigest} from './core.mjs';
try {
  const root=await Deno.realPath(Deno.cwd()),inspection=await inspectProject(root),options=projectOptions(inspection);
  if(options.config)await beginRun(root,{source:await snapshotSources(root,inspection),outputDir:projectOutput(root,inspection),renderedInputs:await renderInputs(root),kind:'native-render',configDigest:await fileDigest(new TextEncoder().encode(JSON.stringify(options.value)))});
  else await markState(root,'disabled');
} catch(error){
  try{await markState(Deno.cwd(),'failed');}catch{}
  console.error(error instanceof Error&&error.message.startsWith('content-security-protocol:')?error.message:'content-security-protocol: pre-render state failed; inspect configuration, permissions and regular source files');Deno.exit(1);
}
