// Manual source-pair additions use the same offline builder as batch construction.
const knowledgeBuildState={items:[],loaded:false,refreshing:false,draft:null,submitting:false,error:null};
const knowledgeLanguages=['c','cpp','Python','Go','JavaScript','TypeScript','Java','Rust','C#','PHP','Ruby','Other'];
const knowledgeBuildBusy=job=>['queued','running'].includes(job.status);

function knowledgeBuildPanel(){
 const s=knowledgeBuildState;
 return `<div class="kb-extension-toolbar"><p>Add verified source and patch pairs to the local repair knowledge.</p>${button('kb-add','Extend Knowledge Base','plus','primary')}</div><div id="kb-builds">${knowledgeBuildHistory()}</div>`;
}
function knowledgeBuildHistory(){
 const s=knowledgeBuildState;
 if(s.error)return `<p class="error-banner" role="status">${esc(s.error)}</p>`;
 if(!s.items.length)return '';
 return `<section class="kb-build-history" aria-label="Knowledge construction"><h3>${icon('layers')}Knowledge construction</h3>${s.items.map(job=>{
  const busy=knowledgeBuildBusy(job),completed=job.status==='completed';
  const latest=job.events?.at(-1)?.message||'Waiting for the offline worker';
  return `<article class="kb-build ${busy?'is-building':''}" data-ui-key="kb-build-${esc(job.id)}"><div class="kb-build-summary"><span class="kb-build-symbol">${busy?'<span class="spinner"></span>':icon(completed?'check':'info')}</span><div><strong>${esc(job.cve_id)}</strong><p role="status">${esc(latest)}</p></div>${status(job.status)}${completed?button('record','View sample','arrow','small',`data-id="${esc(job.sample_id)}"`):''}</div><details data-ui-key="kb-build-events-${esc(job.id)}"><summary>Build events · ${date(job.created_at)}</summary><ol>${(job.events||[]).map(e=>`<li><time>${date(e.time)}</time><span>${esc(e.message)}</span></li>`).join('')}</ol></details></article>`;
 }).join('')}</section>`;
}
async function refreshKnowledgeBuilds(){
 const s=knowledgeBuildState;if(s.refreshing)return;
 s.refreshing=true;
 try{
  const data=await api('/knowledge-builds'),old=new Map(s.items.map(j=>[j.id,j.status]));
  const changed=data.items.some(j=>j.status==='completed'&&old.get(j.id)!=='completed');
  s.items=data.items;s.loaded=true;s.error=null;
  if(changed&&state.page==='knowledge'){
   state.overview=await api('/overview');await loadKnowledge();render();
  }else{
   const target=document.querySelector('#kb-builds');
   if(target){const template=document.createElement('div');template.innerHTML=knowledgeBuildHistory();morphNode(target,template);target.id='kb-builds';}
  }
 }catch(e){s.error='Could not refresh knowledge construction: '+e.message;const target=document.querySelector('#kb-builds');if(target)target.innerHTML=knowledgeBuildHistory();}
 finally{s.refreshing=false;}
}
function openKnowledgeAddition(){
 knowledgeBuildState.draft={source:null,patch:null};
 state.modal='knowledge-add';
 const upload=(kind,title,hint)=>`<div class="kb-upload"><label class="field-label" for="kb-${kind}">${icon(kind==='source'?'code':'branch')}${title}</label><input id="kb-${kind}" type="file" ${kind==='patch'?'accept=".patch,.diff,.txt"':''} required aria-describedby="kb-${kind}-help"><p id="kb-${kind}-help">${hint}</p><div id="kb-${kind}-file" class="kb-file-info" role="status">No file selected</div></div>`;
 openModal('Extend Knowledge Base','Add one vulnerability and its ground-truth repair to both knowledge views.',
 `<form id="kb-add-form"><div class="kb-metadata-import"><label for="kb-cve-json">Import CVE JSON <span>optional</span></label><input id="kb-cve-json" type="file" accept=".json,application/json"><small>CVE Record, NVD, or JSON with cve_id and cve_description.</small></div>
 <div class="form-row"><div class="form-field"><label class="field-label" for="kb-cve">CVE ID</label><input id="kb-cve" placeholder="CVE-2024-12345" pattern="[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,}" maxlength="40" required></div><div class="form-field"><label class="field-label" for="kb-project">Project <span class="muted-note">optional</span></label><input id="kb-project" placeholder="owner / repository" maxlength="200"></div><div class="form-field"><label class="field-label" for="kb-source-language">Language</label><select id="kb-source-language">${knowledgeLanguages.map(l=>`<option>${esc(l)}</option>`).join('')}</select></div></div>
 <div class="form-field"><label class="field-label" for="kb-description">Vulnerability description</label><textarea id="kb-description" rows="3" maxlength="20000" required placeholder="Describe the root cause and the affected behavior."></textarea></div>
 <div class="kb-upload-grid">${upload('source','Vulnerable source','UTF-8 source file, up to 2 MiB.')}${upload('patch','Ground-truth patch','Single-file unified diff matching the source, up to 2 MiB.')}</div>
 <p class="kb-build-note">The configured offline model extracts and distills both views, then adds their embeddings to the index. The sample becomes available after a successful build.</p><div id="kb-add-error" role="alert"></div></form>`,
 `<p>Construction continues when this dialog is closed.</p><div class="kb-modal-actions">${button('close-modal','Cancel')}${button('kb-submit','Build Knowledge','layers','primary',`id="kb-submit" ${knowledgeBuildState.submitting?'disabled':''}`)}</div>`,true);
}
function knowledgeMetadata(value){
 const cve=value.vulnerabilities?.[0]?.cve||value.cve||value;
 const data=cve.containers?.cna||cve;
 const descriptions=data.descriptions||cve.description?.description_data||[];
 const english=descriptions.find(d=>d.lang==='en')||descriptions[0];
 const id=cve.cveMetadata?.cveId||cve.CVE_data_meta?.ID||cve.cve_id||cve.id;
 const description=cve.cve_description||(typeof cve.description==='string'?cve.description:english?.value);
 if(!/^CVE-\d{4}-\d{4,}$/i.test(id||'')||!description?.trim())throw new Error('CVE JSON must include a CVE ID and a vulnerability description.');
 return {cve_id:id.toUpperCase(),cve_description:description,project:cve.project||data.affected?.[0]?.product||'',language:cve.language||''};
}
async function readKnowledgeFile(file){
 if(!file.size||file.size>2*1024*1024)throw new Error('Choose a nonempty file no larger than 2 MiB.');
 const bytes=new Uint8Array(await file.arrayBuffer());
 const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 if(text.includes('\0'))throw new Error('Upload a UTF-8 text file.');
 let binary='';for(let i=0;i<bytes.length;i+=8192)binary+=String.fromCharCode(...bytes.subarray(i,i+8192));
 return {filename:file.name,content_base64:btoa(binary)};
}
async function knowledgeUploadChange(event){
 const input=event.target,kind=input.id==='kb-source'?'source':input.id==='kb-patch'?'patch':null;
 if(!kind&&input.id!=='kb-cve-json')return;
 const file=input.files?.[0],draft=knowledgeBuildState.draft,error=document.querySelector('#kb-add-error');
 if(error)error.textContent='';
 if(kind&&draft){draft[kind]=null;document.querySelector('#kb-'+kind+'-file').textContent=file?'Reading file…':'No file selected';}
 if(!file)return;
 try{
  if(!kind){
   if(file.size>2*1024*1024)throw new Error('CVE JSON must be at most 2 MiB.');
   const metadata=knowledgeMetadata(JSON.parse(await file.text()));
   if(state.modal!=='knowledge-add'||knowledgeBuildState.draft!==draft)return;
   for(const [id,key] of [['kb-cve','cve_id'],['kb-description','cve_description'],['kb-project','project']])document.getElementById(id).value=metadata[key];
   if(knowledgeLanguages.includes(metadata.language))document.querySelector('#kb-source-language').value=metadata.language;
  }else{
   const uploaded=await readKnowledgeFile(file);
   if(state.modal!=='knowledge-add'||knowledgeBuildState.draft!==draft||input.files?.[0]!==file)return;
   draft[kind]=uploaded;
   document.querySelector('#kb-'+kind+'-file').textContent=file.name+' · '+Math.ceil(file.size/1024)+' KB';
   if(kind==='source'){
    const language={c:'c',h:'c',cpp:'cpp',cc:'cpp',cxx:'cpp',hpp:'cpp',py:'Python',go:'Go',js:'JavaScript',mjs:'JavaScript',ts:'TypeScript',java:'Java',rs:'Rust',cs:'C#',php:'PHP',rb:'Ruby'}[file.name.split('.').at(-1).toLowerCase()];
    if(language)document.querySelector('#kb-source-language').value=language;
   }
  }
 }catch(e){if(error?.isConnected)error.textContent=e.message;}
}
async function submitKnowledgeAddition(){
 const s=knowledgeBuildState,form=document.querySelector('#kb-add-form'),submit=document.querySelector('#kb-submit');
 if(s.submitting||!form?.reportValidity())return;
 const error=document.querySelector('#kb-add-error'),draft=s.draft;
 if(!draft?.source||!draft?.patch){error.textContent='Choose a vulnerable source file and a matching ground-truth patch. Wait for both files to finish loading.';return;}
 const value=id=>document.getElementById(id).value.trim();
 const body={cve_id:value('kb-cve').toUpperCase(),cve_description:value('kb-description'),project:value('kb-project'),language:value('kb-source-language'),source:draft.source,patch:draft.patch};
 s.submitting=true;submit.disabled=true;submit.textContent='Submitting…';error.textContent='';
 try{
  const job=await api('/knowledge-builds',{method:'POST',body:JSON.stringify(body)});
  s.items=[job,...s.items.filter(j=>j.id!==job.id)];s.error=null;
  if(state.modal==='knowledge-add'&&s.draft===draft)closeModal();
  if(state.page!=='knowledge')await navigate('knowledge');else render();
  toast('Knowledge construction started. Follow its progress below.');
 }catch(e){if(error.isConnected)error.textContent=e.message;else toast(e.message);}
 finally{s.submitting=false;const current=document.querySelector('#kb-submit');if(current){current.disabled=false;current.innerHTML=icon('layers')+'Build Knowledge';}}
}
document.addEventListener('change',event=>{knowledgeUploadChange(event).catch(fail);});
document.addEventListener('submit',event=>{if(event.target.id==='kb-add-form'){event.preventDefault();submitKnowledgeAddition().catch(fail);}});
setInterval(()=>{if(!document.hidden&&state.page==='knowledge')refreshKnowledgeBuilds();},2500);
