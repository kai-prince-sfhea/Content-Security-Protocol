import {fileDigest,fail} from './core.mjs';
export const KNOWN_CODES=new Set(['resource-not-authorized','inline-hash-not-authorized','inline-event-handler','inline-style-attribute','executable-url','local-resource-missing','local-reference-unresolved','local-integrity-unverified','url-credentials-omitted','private-output-path','forbidden-marker','changed-unrendered-source']);
export function failureCount(report,level='none'){
  const findings=[...report.findings,...report.pages.flatMap(p=>p.findings)];
  return level==='none'?0:level==='any'?findings.length:findings.filter(f=>KNOWN_CODES.has(f.code)).length;
}
export async function findingRecords(report){
  const findings=[...report.findings.map(f=>({path:f.path??'',...f})),...report.pages.flatMap(p=>p.findings.map(f=>({path:p.path,...f})))];
  return Promise.all(findings.map(async f=>({id:await fileDigest(new TextEncoder().encode(JSON.stringify(f))),...f})));
}
const date=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}$/u.test(s)&&Number.isFinite(Date.parse(s+'T00:00:00Z'))&&new Date(s+'T00:00:00Z').toISOString().slice(0,10)===s;
export async function annotateExceptions(report,exceptions,asOf){
  if(!date(asOf)||!exceptions||exceptions.schema!=='content-security-protocol-exceptions/v1'||!Array.isArray(exceptions.entries)||exceptions.entries.length>256||Object.keys(exceptions).some(k=>!['schema','entries'].includes(k)))fail('exceptions','use a versioned entries object and explicit valid as-of date');
  const findings=await findingRecords(report),ids=new Set(findings.map(f=>f.id)),seen=new Set(),annotations=[];
  for(const entry of exceptions.entries){
    if(!entry||Object.keys(entry).some(k=>!['id','reason','expires'].includes(k))||!/^[a-f0-9]{64}$/u.test(entry.id)||seen.has(entry.id)||!ids.has(entry.id)||typeof entry.reason!=='string'||!entry.reason.trim()||entry.reason.length>1000||/[\u0000-\u001f]/u.test(entry.reason)||!date(entry.expires))fail('exceptions','require unique existing finding IDs, bounded reasons and valid expiry dates');
    seen.add(entry.id);annotations.push({id:entry.id,reason:entry.reason,expires:entry.expires,status:entry.expires<asOf?'expired':'acknowledged'});
  }
  return {schema:'content-security-protocol-exception-annotations/v1',asOf,annotations,approval:false,originalFindingsRetained:true};
}
export function cryptoInventory(report){return {schema:'content-security-protocol-cryptography/v1',inventoryDigest:report.inventoryDigest,mechanisms:[
  {algorithm:'SHA-256',purpose:'raw file and inventory identity',authenticity:false},
  {algorithm:'SHA-256/384/512',purpose:'CSP inline candidate/explicit hash comparison',delivered:false},
  {algorithm:'SHA-384',purpose:'local raw-byte SRI candidate',injected:false},
  {algorithm:'SHA-256/384/512',purpose:'existing local SRI comparison',remoteBytes:'not-fetched'}],
  readiness:{hostingTLS:'unassessed',keyExchange:'unassessed',artifactSignatures:'unassessed',encryptedRetainedData:'unassessed',providerPQC:'unassessed',browserPQC:'unassessed'},
  standards:[{name:'ML-KEM / FIPS 203',url:'https://csrc.nist.gov/pubs/fips/203/final'},{name:'ML-DSA / FIPS 204',url:'https://csrc.nist.gov/pubs/fips/204/final'},{name:'SLH-DSA / FIPS 205',url:'https://csrc.nist.gov/pubs/fips/205/final'}],
  limitations:['Digest identity is not authentication, signature verification or factual review.','This extension does not change browser/host TLS or implement custom cryptography.','Cryptographic inventory supports future migration planning; no PQC readiness is certified.']};}
