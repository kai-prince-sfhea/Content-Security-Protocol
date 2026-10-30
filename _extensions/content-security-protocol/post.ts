import {markState} from './state.mjs';
import {finalizeNativeAudit} from './finalizer.mjs';
try {
  await finalizeNativeAudit(Deno.cwd());
}catch(error){
  try{await markState(Deno.cwd(),'failed');}catch{}
  console.error(error instanceof Error&&error.message.startsWith('content-security-protocol:')?error.message:'content-security-protocol: audit failed; check configuration, permissions, regular files and output limits');Deno.exit(1);
}
