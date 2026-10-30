// Copyright 2026 Kai Prince. SPDX-License-Identifier: Apache-2.0
// Closed, finite browser-test declarations. No script, filesystem or browser IO.
export const INTERACTION_LIMITS=Object.freeze({profiles:8,pages:128,states:16,actions:16,viewports:4,cells:512,profileBytes:131072});
export const INTERACTION_KEYS=Object.freeze(['Enter','Space','Tab','Escape','ArrowUp','ArrowDown','ArrowLeft','ArrowRight','Home','End','PageUp','PageDown']);
const encoder=new TextEncoder();
function bad(){const error=new TypeError('content-security-protocol: interaction profile: use the bounded literal schema, unique IDs and contained HTML output paths');error.code='invalid-interaction-profile';throw error;}
function fields(value,allowed,required=allowed){if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))bad();for(const key of Reflect.ownKeys(value)){const d=Object.getOwnPropertyDescriptor(value,key);if(typeof key!=='string'||!allowed.includes(key)||!d?.enumerable||!Object.hasOwn(d,'value'))bad();}if(required.some(key=>!Object.hasOwn(value,key)))bad();}
function array(value,maximum,minimum=0){if(!Array.isArray(value)||Object.getPrototypeOf(value)!==Array.prototype||value.length<minimum||value.length>maximum||Reflect.ownKeys(value).length!==value.length+1)bad();for(let i=0;i<value.length;i++){const d=Object.getOwnPropertyDescriptor(value,String(i));if(!d?.enumerable||!Object.hasOwn(d,'value'))bad();}return value;}
function text(value,maximum){if(typeof value!=='string'||!value||value.length>maximum||value!==value.trim()||encoder.encode(value).length>maximum||/[\u0000-\u001f\u007f\ud800-\udfff]/u.test(value))bad();return value;}
function id(value){text(value,64);if(!/^[a-z][a-z0-9-]{0,63}$/u.test(value)||['constructor','prototype','__proto__'].includes(value))bad();return value;}
function integer(value,min,max){if(!Number.isSafeInteger(value)||value<min||value>max)bad();return value;}
function path(value){text(value,1024);if(!/^[A-Za-z0-9_-][A-Za-z0-9_./-]*\.html$/u.test(value)||value.split('/').some(part=>!part||part==='.'||part==='..'||part.startsWith('.')||['_extensions','private'].includes(part.toLowerCase())))bad();return value;}
function selector(value){return text(value,512);}
function literalValue(value){if(typeof value!=='string'||value.length>2048||encoder.encode(value).length>2048||/[\u0000-\u001f\u007f\ud800-\udfff]/u.test(value))bad();return value;}
function action(value){fields(value,['click','fill','select','key'],[]);if(Object.keys(value).length!==1)bad();const name=Object.keys(value)[0],raw=value[name];fields(raw,name==='click'?['selector']:name==='key'?['selector','key']:['selector','value']);const out={selector:selector(raw.selector)};if(name==='key'){if(!INTERACTION_KEYS.includes(raw.key))bad();out.key=raw.key;}else if(name!=='click')out.value=literalValue(raw.value);return {[name]:out};}
function freeze(value){if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;}
function canonical(value){if(Array.isArray(value))return'['+value.map(canonical).join(',')+']';if(value&&typeof value==='object')return'{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}';return JSON.stringify(value);}
/** Every page has an implicit initial cell; authored states start from a fresh
 * browser context and contain only the finite actions declared here. */
export function validateInteractionProfile(value){
 fields(value,['id','version','pages','viewports','colorSchemes','timeoutMs','totalTimeoutMs','settleMs','layoutObservations'],['id','version','pages']);if(value.version!==1)bad();
 const result={id:id(value.id),version:1,pages:[],viewports:[],colorSchemes:[],timeoutMs:integer(value.timeoutMs??30000,1000,30000),totalTimeoutMs:integer(value.totalTimeoutMs??600000,1000,3600000),settleMs:integer(value.settleMs??100,0,10000)};if(result.totalTimeoutMs<result.timeoutMs)bad();
 if(value.layoutObservations!==undefined){if(typeof value.layoutObservations!=='boolean')bad();if(value.layoutObservations)result.layoutObservations=true;}
 const seenPages=new Set();for(const page of array(value.pages,128,1)){fields(page,['path','states'],['path']);const output=path(page.path);if(seenPages.has(output))bad();seenPages.add(output);const states=[],seenStates=new Set(['initial']);for(const state of array(page.states??[],16)){fields(state,['id','actions','ready'],['id','actions']);const name=id(state.id);if(seenStates.has(name))bad();seenStates.add(name);const row={id:name,actions:array(state.actions,16).map(action)};if(state.ready!==undefined){fields(state.ready,['selector','state']);if(!['visible','hidden'].includes(state.ready.state))bad();row.ready={selector:selector(state.ready.selector),state:state.ready.state};}states.push(row);}result.pages.push({path:output,states});}
 const seenViewports=new Set();for(const view of array(value.viewports??[{width:1440,height:900},{width:320,height:568}],4,1)){fields(view,['width','height']);const row={width:integer(view.width,240,4096),height:integer(view.height,200,4096)},key=row.width+'x'+row.height;if(seenViewports.has(key))bad();seenViewports.add(key);result.viewports.push(row);}
 for(const scheme of array(value.colorSchemes??['light','dark'],2,1)){if(!['light','dark'].includes(scheme)||result.colorSchemes.includes(scheme))bad();result.colorSchemes.push(scheme);}
 const cells=result.pages.reduce((n,page)=>n+1+page.states.length,0)*result.viewports.length*result.colorSchemes.length;if(cells>512||encoder.encode(canonical(result)).length>131072)bad();return freeze(result);
}
export function validateInteractionProfiles(value=[]){const out=array(value,8).map(validateInteractionProfile),seen=new Set();for(const profile of out){if(seen.has(profile.id))bad();seen.add(profile.id);}return freeze(out);}
export function canonicalInteractionProfile(value){return canonical(validateInteractionProfile(value));}
