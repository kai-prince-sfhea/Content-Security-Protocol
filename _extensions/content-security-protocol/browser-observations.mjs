// Copyright 2026 Kai Prince. SPDX-License-Identifier: Apache-2.0
// Bounded browser observations. No theme CSS, RGB heuristics or page text capture.
export const PAGE_OBSERVATION_LIMITS=Object.freeze({settleMs:1500,themeStylesheets:16,stylesheets:256,layoutElements:2000,layoutSamples:16});

// These functions are serialized into the explicitly acknowledged browser.
// Keep their browser dependencies local; ordinary renders never execute them.
export function inspectNativeTheme(){
 const links=[...document.querySelectorAll('link#quarto-bootstrap')],limited=links.length>16,selected=links.slice(0,16).filter(link=>!link.classList.contains('quarto-color-scheme-extra')),modes=['light','dark'];
 const bodyLight=document.body?.classList.contains('quarto-light')===true,bodyDark=document.body?.classList.contains('quarto-dark')===true,bodyMode=bodyLight===bodyDark?'unknown':bodyDark?'dark':'light';
 const active=selected.filter(link=>link.relList.contains('stylesheet')&&!link.disabled&&(!link.media||matchMedia(link.media).matches));
 // Native Quarto layers the enabled alternate on the still-enabled primary.
 // The extra bootstrap copy is only a loading fallback, not a selected mode.
 const preferred=active.some(link=>link.classList.contains('quarto-color-alternate'))?active.filter(link=>link.classList.contains('quarto-color-alternate')):active;
 const availableModes=modes.filter(mode=>selected.some(link=>link.getAttribute('data-mode')===mode)),activeModes=modes.filter(mode=>preferred.some(link=>link.getAttribute('data-mode')===mode));
 const stylesheetMode=preferred.length&&preferred.every(link=>modes.includes(link.getAttribute('data-mode')))&&activeModes.length===1?activeModes[0]:'unknown';
 const kind=links.length||document.getElementById('quarto-html-before-body')?'quarto':'not-quarto';
 return{kind,mode:kind==='quarto'&&!limited&&bodyMode===stylesheetMode?bodyMode:'unknown',bodyMode,stylesheetMode,availableModes,activeStylesheets:active.length,stylesReady:active.every(link=>!!link.sheet),nativeToggle:typeof window.quartoToggleColorScheme==='function',limited};
}
export function invokeNativeThemeToggle(){
 if(typeof window.quartoToggleColorScheme!=='function')return false;
 try{window.quartoToggleColorScheme();return true;}catch{return false;}
}
export async function settleBrowserPage(maximumMs){
 const deadline=performance.now()+Math.max(1,Math.min(1500,maximumMs));
 const bounded=promise=>new Promise(resolve=>{const timer=setTimeout(()=>resolve(false),Math.max(1,deadline-performance.now()));Promise.resolve(promise).then(()=>{clearTimeout(timer);resolve(true);},()=>{clearTimeout(timer);resolve(false);});});
 const styleState=()=>{const links=[...document.querySelectorAll('link[rel~="stylesheet"]')];if(links.length>256)return'limited';return links.filter(link=>!link.disabled&&(!link.media||matchMedia(link.media).matches)).every(link=>!!link.sheet)?'ready':'pending';};
 let styles=styleState();while(styles==='pending'&&performance.now()<deadline){await new Promise(resolve=>setTimeout(resolve,Math.min(20,Math.max(1,deadline-performance.now()))));styles=styleState();}
 let fonts=document.fonts?'pending':'unavailable';if(document.fonts){if(document.fonts.status==='loaded')fonts='ready';else if(await bounded(document.fonts.ready))fonts=document.fonts.status==='loaded'?'ready':'pending';}
 const frames=await bounded(new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))))?'complete':'timed-out';
 return{styles,fonts,frames};
}
export function observeBrowserLayout(){
 const root=document.documentElement,body=document.body,viewport={width:innerWidth,height:innerHeight},dimensions=node=>({clientWidth:node?.clientWidth??0,scrollWidth:node?.scrollWidth??0,clientHeight:node?.clientHeight??0,scrollHeight:node?.scrollHeight??0});
 const documentBox=dimensions(root),samples=[];let examined=0,horizontalOverflow=0,outsideViewport=0;
 const walker=body?document.createTreeWalker(body,NodeFilter.SHOW_ELEMENT):null;let node=body;
 while(node&&examined<2000){examined++;const box=node.getBoundingClientRect();if(box.width>0&&box.height>0){const overflow=node.clientWidth>0&&node.scrollWidth>node.clientWidth+1,outside=box.left< -1||box.right>viewport.width+1;if(overflow)horizontalOverflow++;if(outside)outsideViewport++;if((overflow||outside)&&samples.length<16){const value=getComputedStyle(node).overflowX,overflowX=['visible','hidden','clip','scroll','auto'].includes(value)?value:'other';samples.push({tag:node.tagName.toLowerCase().slice(0,64),clientWidth:node.clientWidth,scrollWidth:node.scrollWidth,left:box.left,right:box.right,overflowX});}}node=walker.nextNode();}
 return{viewport,document:documentBox,documentHorizontalOverflow:documentBox.scrollWidth>documentBox.clientWidth+1,examined,limited:node!==null,horizontalOverflow,outsideViewport,samples};
}

// Reconcile only before authored actions. Their final native theme is observed,
// never overwritten to make a requested scheme appear to have been tested.
export async function reconcileNativeTheme({requested,read,toggle,settle}){
 const firstSettle=await settle(),before=await read();let after=before,settled=firstSettle,action='none',outcome;
 if(before.kind==='not-quarto')outcome='not-quarto';
 else if(before.limited||before.mode==='unknown')outcome='unknown';
 else if(before.mode===requested)outcome='matched';
 else if(before.availableModes.length<2)outcome='single-theme';
 else if(!before.nativeToggle)outcome='unavailable';
 else{action='native-quarto-hook';const invoked=await toggle();settled=await settle();after=await read();outcome=invoked&&after.mode===requested?'switched':'unavailable';}
 return{requested,before,after,action,outcome,settled};
}

const invalid=()=>{const error=new TypeError('content-security-protocol: invalid bounded browser observation');error.code='invalid-browser-observation';throw error;};
function fields(value,keys){if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))invalid();const own=Reflect.ownKeys(value);if(own.length!==keys.length)invalid();for(const key of own){const item=Object.getOwnPropertyDescriptor(value,key);if(typeof key!=='string'||!keys.includes(key)||!item?.enumerable||!Object.hasOwn(item,'value'))invalid();}}
const choice=(value,values)=>{if(!values.includes(value))invalid();};
const boolean=value=>{if(typeof value!=='boolean')invalid();};
const number=(value,min=0,max=1e9)=>{if(!Number.isFinite(value)||value<min||value>max)invalid();};
const count=(value,max)=>{number(value,0,max);if(!Number.isSafeInteger(value))invalid();};
function list(value,max){if(!Array.isArray(value)||Object.getPrototypeOf(value)!==Array.prototype||value.length>max||Reflect.ownKeys(value).length!==value.length+1)invalid();for(let i=0;i<value.length;i++){const item=Object.getOwnPropertyDescriptor(value,String(i));if(!item?.enumerable||!Object.hasOwn(item,'value'))invalid();}}
function themeState(value){fields(value,['kind','mode','bodyMode','stylesheetMode','availableModes','activeStylesheets','stylesReady','nativeToggle','limited']);choice(value.kind,['quarto','not-quarto']);for(const key of ['mode','bodyMode','stylesheetMode'])choice(value[key],['light','dark','unknown']);list(value.availableModes,2);for(const mode of value.availableModes)choice(mode,['light','dark']);if(new Set(value.availableModes).size!==value.availableModes.length)invalid();count(value.activeStylesheets,16);for(const key of ['stylesReady','nativeToggle','limited'])boolean(value[key]);if(value.mode!=='unknown'&&(value.kind!=='quarto'||value.limited||value.mode!==value.bodyMode||value.mode!==value.stylesheetMode||!value.availableModes.includes(value.mode)||!value.activeStylesheets))invalid();}
function settleState(value){fields(value,['styles','fonts','frames']);choice(value.styles,['ready','pending','limited']);choice(value.fonts,['ready','pending','unavailable']);choice(value.frames,['complete','timed-out']);}
export function validateThemeObservation(value,requested){
 fields(value,['reconciliation','afterActions']);const row=value.reconciliation;fields(row,['requested','before','after','action','outcome','settled']);if(row.requested!==requested)invalid();themeState(row.before);themeState(row.after);choice(row.action,['none','native-quarto-hook']);choice(row.outcome,['not-quarto','unknown','matched','single-theme','unavailable','switched']);settleState(row.settled);
 fields(value.afterActions,['theme','settled']);themeState(value.afterActions.theme);settleState(value.afterActions.settled);
 if(['matched','switched'].includes(row.outcome)&&row.after.mode!==requested)invalid();if(row.outcome==='not-quarto'&&row.after.kind!=='not-quarto')invalid();
 if(row.outcome==='switched'&&row.action!=='native-quarto-hook'||['matched','single-theme','not-quarto','unknown'].includes(row.outcome)&&row.action!=='none')invalid();
 return value;
}
export function validateLayoutObservation(value){
 fields(value,['viewport','document','documentHorizontalOverflow','examined','limited','horizontalOverflow','outsideViewport','samples']);fields(value.viewport,['width','height']);for(const n of Object.values(value.viewport))number(n,1,100000);fields(value.document,['clientWidth','scrollWidth','clientHeight','scrollHeight']);for(const n of Object.values(value.document))number(n);for(const key of ['documentHorizontalOverflow','limited'])boolean(value[key]);count(value.examined,2000);count(value.horizontalOverflow,value.examined);count(value.outsideViewport,value.examined);list(value.samples,16);
 for(const sample of value.samples){fields(sample,['tag','clientWidth','scrollWidth','left','right','overflowX']);if(typeof sample.tag!=='string'||!/^[-a-z0-9:]{1,64}$/u.test(sample.tag))invalid();for(const key of ['clientWidth','scrollWidth'])number(sample[key]);for(const key of ['left','right'])number(sample[key],-1e9);choice(sample.overflowX,['visible','hidden','clip','scroll','auto','other']);}
 return value;
}
export const observationSettled=value=>value.styles==='ready'&&value.fonts!=='pending'&&value.frames==='complete';
export function layoutObservationSummary(value){validateLayoutObservation(value);return{viewport:value.viewport,document:value.document,documentHorizontalOverflow:value.documentHorizontalOverflow,examined:value.examined,limited:value.limited,horizontalOverflow:value.horizontalOverflow,outsideViewport:value.outsideViewport,sampleCount:value.samples.length};}
