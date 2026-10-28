const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {join}=require('node:path');
const vm=require('node:vm');

function setup(){
 const nodes=new Map(),calls=[];
 const c=vm.createContext({console,TextDecoder,Uint8Array,setTimeout,clearTimeout,setInterval:()=>{},btoa:x=>Buffer.from(x,'binary').toString('base64')});
 vm.runInContext(readFileSync(join(__dirname,'../../studio/web/app.js'),'utf8'),c);
 Object.assign(c,{document:{addEventListener:()=>{},querySelector:id=>nodes.get(id),getElementById:id=>nodes.get('#'+id)},api:async(path,options)=>{calls.push({path,body:JSON.parse(options.body)});return {id:'job-one',status:'queued',events:[]}},render:()=>{},closeModal:()=>{},toast:()=>{},navigate:async()=>{}});
 vm.runInContext(readFileSync(join(__dirname,'../../studio/web/knowledge-builds.js'),'utf8'),c);
 return {c,nodes,calls,run:code=>vm.runInContext(code,c)};
}

test('CVE metadata accepts CVE Record, NVD and simple JSON without inventing descriptions',()=>{
 const {c,run}=setup();
 for(const value of [
  {cveMetadata:{cveId:'CVE-2026-12345'},containers:{cna:{descriptions:[{lang:'fr',value:'FR'},{lang:'en',value:'Unchecked buffer length'}]}}},
  {vulnerabilities:[{cve:{id:'CVE-2026-12345',descriptions:[{lang:'en',value:'Unchecked buffer length'}]}}]},
  {cve_id:'cve-2026-12345',cve_description:'Unchecked buffer length'}
 ]){c.value=value;assert.equal(run('knowledgeMetadata(value).cve_id'),'CVE-2026-12345');assert.equal(run('knowledgeMetadata(value).cve_description'),'Unchecked buffer length');}
 assert.throws(()=>run("knowledgeMetadata({cve_id:'CVE-2026-12345'})"),/description/);
 assert.throws(()=>run("knowledgeMetadata({id:'invalid',description:'valid'})"),/CVE ID/);
});

test('source uploads preserve exact UTF-8 bytes and reject binary or oversized data',async()=>{
 const {c,run}=setup(),bytes=Buffer.from('/* source */\ncopy(input);\n');
 c.file={size:bytes.length,name:'source.c',arrayBuffer:async()=>bytes};
 const result=await run('readKnowledgeFile(file)');
 assert.equal(Buffer.from(result.content_base64,'base64').toString(),bytes.toString());
 c.file={size:2*1024*1024+1};await assert.rejects(run('readKnowledgeFile(file)'),/2 MiB/);
 c.file={size:2,name:'binary',arrayBuffer:async()=>Buffer.from([0,1])};await assert.rejects(run('readKnowledgeFile(file)'),/UTF-8/);
});

test('submission sends both actual file contents and CVE metadata to the build API',async()=>{
 const {run,nodes,calls}=setup();
 nodes.set('#kb-add-form',{reportValidity:()=>true});nodes.set('#kb-submit',{isConnected:true});nodes.set('#kb-add-error',{isConnected:true});
 for(const [id,value] of Object.entries({'kb-cve':'cve-2026-12345','kb-description':'Unchecked buffer length','kb-project':'project','kb-source-language':'c'}))nodes.set('#'+id,{value});
 run("state.page='knowledge';knowledgeBuildState.draft={source:{filename:'code.c',content_base64:'YQ=='},patch:{filename:'fix.patch',content_base64:'Yg=='}};");
 await run('submitKnowledgeAddition()');
 assert.equal(calls.length,1);assert.equal(calls[0].path,'/knowledge-builds');
 assert.deepEqual(calls[0].body,{cve_id:'CVE-2026-12345',cve_description:'Unchecked buffer length',project:'project',language:'c',source:{filename:'code.c',content_base64:'YQ=='},patch:{filename:'fix.patch',content_base64:'Yg=='}});
 assert.equal(run('knowledgeBuildState.items[0].status'),'queued');
 assert.equal(run('knowledgeBuildState.submitting'),false);
});

test('missing uploads cannot start construction, and failure messages are escaped',async()=>{
 const {run,nodes,calls}=setup();
 nodes.set('#kb-add-form',{reportValidity:()=>true});nodes.set('#kb-submit',{});nodes.set('#kb-add-error',{});
 run('knowledgeBuildState.draft={source:null,patch:null}');await run('submitKnowledgeAddition()');
 assert.equal(calls.length,0);assert.match(nodes.get('#kb-add-error').textContent,/matching ground-truth/);
 run("knowledgeBuildState.items=[{id:'one',cve_id:'<script>',status:'failed',events:[{message:'<img onerror=bad>'}]}]");
 const markup=run('knowledgeBuildHistory()');assert.doesNotMatch(markup,/<script>|<img onerror/);assert.match(markup,/&lt;script&gt;/);
});
