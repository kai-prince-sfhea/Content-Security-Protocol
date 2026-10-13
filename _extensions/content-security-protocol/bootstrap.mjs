// Local metadata hook: cope with Quarto's space-containing hook path rebasing.
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
const stage=Deno.args[0];if(!['pre','post'].includes(stage))throw new Error('content-security-protocol: invalid hook stage');
const base=join(Deno.cwd(),'_extensions'),candidates=[join(base,'content-security-protocol')];
for(const entry of Deno.readDirSync(base))if(entry.isDirectory&&entry.name!=='content-security-protocol')candidates.push(join(base,entry.name,'content-security-protocol'));
const found=candidates.filter(p=>{try{return Deno.statSync(join(p,'post.ts')).isFile&&Deno.statSync(join(p,'_extension.yml')).isFile;}catch{return false;}});
if(found.length!==1)throw new Error('content-security-protocol: expected one installed copy; remove duplicates with quarto remove');
await import(pathToFileURL(join(found[0],stage+'.ts')).href);
