import {main} from './cli.mjs';
try{Deno.exit(await main(Deno.args));}
catch(error){console.error(error instanceof Error&&error.message.startsWith('content-security-protocol:')?error.message:'content-security-protocol: command failed; check current state, regular files, permissions and documented options');Deno.exit(1);}
