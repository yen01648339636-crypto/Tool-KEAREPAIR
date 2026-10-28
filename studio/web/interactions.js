
function openModal(title,subtitle,body,footer='',wide=false){
 if(!document.querySelector('.modal'))previousFocus=document.activeElement;
 document.querySelector('#overlay-root').innerHTML=`<div class="modal-backdrop"><section class="modal ${wide?'wide':''}" role="dialog" aria-modal="true" aria-labelledby="modal-title"><header class="modal-header"><div><h2 id="modal-title">${title}</h2><p>${subtitle}</p></div><button class="icon-button" data-action="close-modal" aria-label="Close">${icon('close')}</button></header><div class="modal-body">${body}</div>${footer?`<footer class="modal-footer">${footer}</footer>`:''}</section></div>`;
 if(state.page==='workbench'&&state.modal!=='repository-task')applyTaskDisplay(document.querySelector('#overlay-root'));
 document.body.style.overflow='hidden';requestAnimationFrame(()=>document.querySelector('.modal input,.modal button')?.focus());
}
function closeModal(){document.querySelector('#overlay-root').innerHTML='';document.body.style.overflow='';state.modal=null;previousFocus?.focus();}
async function openNew(caseKey=null){
 return openRepositoryTask(caseKey);
}
function filteredCases(){return state.caseItems.filter(x=>(!state.caseLanguage||x.language.toLowerCase()===state.caseLanguage.toLowerCase())&&JSON.stringify(x).toLowerCase().includes(state.caseQuery.toLowerCase()));}
function caseOptions(){
 const items=filteredCases().slice(state.caseOffset||0,(state.caseOffset||0)+50);
 return items.length?items.map(x=>`<button class="case-option ${state.selectedCase===x.key?'active':''}" data-action="select-case" data-key="${esc(x.key)}"><span class="case-radio"></span><span class="case-option-text"><strong>${esc(x.case_id)}</strong><p>${esc(x.file)}</p></span>${pill(x.language)}${pill(x.dataset)}</button>`).join(''):'<div class="no-results">No matching cases</div>';
}
function casePager(){const count=filteredCases().length,offset=state.caseOffset||0;return `<span>${count?offset+1:0}–${Math.min(offset+50,count)} / ${count} cases${state.selectedCase?' · selected '+esc(state.selectedCase.split(':').at(-1)):''}</span><div>${button('case-page','Previous',null,'small',`data-offset="${Math.max(0,offset-50)}" ${offset===0?'disabled':''}`)}${button('case-page','Next',null,'small',`data-offset="${offset+50}" ${offset+50>=count?'disabled':''}`)}</div>`;}
function renderCasePicker(){document.querySelector('#case-options').innerHTML=caseOptions();document.querySelector('#case-pager').innerHTML=casePager();}

function renderNew(){
 if(!replayAvailable())state.executionMode='live';
 const replay=state.executionMode==='replay',issues=replay?[]:state.overview.preflight_issues;
 openModal('New Repair Task','Choose a local case. Its source will be saved as a separate snapshot for this run.',
 `<div class="filters"><label class="search-field">${icon('search')}<input id="case-search" type="search" placeholder="Search CVE or project file…" value="${esc(state.caseQuery)}" aria-label="Search cases"></label><select id="case-language" aria-label="Case language"><option value="">All languages</option>${['Python','Go','JavaScript','c','cpp'].map(x=>`<option ${x===state.caseLanguage?'selected':''}>${x}</option>`).join('')}</select></div><div class="case-picker" id="case-options">${caseOptions()}</div><div class="case-pager" id="case-pager">${casePager()}</div>
 <details class="experiment-options"><summary>Experiment settings · ${state.variant==='full'?'Full framework':esc(state.variant)}</summary><div class="form-row"><div class="form-field"><label class="field-label" for="variant">Repair variant</label><select id="variant"><option value="full">Full framework · diagnosis and dual-view retrieval</option><option value="df_only">Data-flow retrieval only</option><option value="cf_only">Control-flow retrieval only</option><option value="no_retrieval">Disable knowledge retrieval</option><option value="no_iteration">Single-round repair</option></select></div><div class="form-field"><label class="field-label" for="model-name">Online model</label><input id="model-name" value="${esc(state.overview.config.model||'Not configured')}" readonly></div></div></details>
 ${executionModeControl()}<div class="notice">${icon('info')}<p>${replay?'Replay diagnosis (15 s), retrieval (20 s), patch generation (10 s) and validation (30 s) using real saved reports and patches, without model or Docker calls. The entire workflow runs automatically to the final patch and repair report.':issues.length?esc(uiMessage(issues.join('; '))):'Run diagnosis, dual-view retrieval, patch generation and Docker validation automatically. Follow live progress and download the final patch and complete repair report.'}</p></div>`,
 `<p>${fmt(state.caseItems.length)} local cases · one task runs at a time</p><div style="display:flex;gap:8px">${button('close-modal','Cancel',null)}${button('start-task','Start Repair','play','primary',`id="start-task" ${!state.selectedCase||issues.length?'disabled':''}`)}</div>`);
 document.querySelector('#variant').value=state.variant;
 document.querySelector('#execution-mode').value=state.executionMode;
}
async function startTask(){
 const submit=document.querySelector('#start-task');if(!state.selectedCase||submit?.disabled)return;
 submit.disabled=true;submit.textContent='Creating…';
 try{const t=await api('/tasks',{method:'POST',body:JSON.stringify({case_key:state.selectedCase,variant:state.variant,mode:state.executionMode||'live'})});closeModal();await openTask(t.id);toast(t.mode==='replay'?'Automatic workflow replay started.':'Repair started. The full workflow will continue automatically.');}
 catch(e){if(submit.isConnected){submit.disabled=false;submit.innerHTML=icon('play')+'Start Repair';}fail(e);}
}
async function openRecord(id){
 state.modal='record';openModal('Repair Knowledge','Loading historical vulnerable and patched code…',loading(),'',true);
 try{const r=await api('/knowledge/'+encodeURIComponent(id));if(state.modal!=='record')return;state.record=r;state.recordView='data_flow';renderRecord();}
 catch(e){closeModal();fail(e);}
}
function renderRecord(){
 const r=state.record;if(!r)return;
 const view=r.views?.[state.recordView]?.abstracted_knowledge||r.views?.[state.recordView];
 const diff=r.patch?diffView(r.patch):`<div class="result-json">${esc(r.fixed_code||'This record has no code diff to display.')}</div>`;
 const body=`${retrievalEvidence(r)}<div class="detail-tabs"><div class="segmented"><button class="${state.recordView==='data_flow'?'active':''}" data-action="record-view" data-view="data_flow">Data flow</button><button class="${state.recordView==='control_flow'?'active':''}" data-action="record-view" data-view="control_flow">Control flow</button></div>${pill(r.language)}</div><p class="reading-copy">${esc(r.cve_description)}</p>${fields(view)}<div class="detail-tabs"><h3>Historical Diff</h3>${pill('Patched version from the knowledge base')}</div>${diff}`;
 openModal(esc(r.cve_id||'Historical Repair Example'),esc(r.project||r.language),body,`<p>Review the historical repair assumptions in the context of the current code.</p>${button('close-modal','Done','check')}`,true);
}
function analyzeModal(){
 state.modal='analyze';
 const body=`<div class="form-row"><div class="form-field"><label class="field-label" for="analysis-tool">Analysis tool</label><select id="analysis-tool"><option value="trace_data_flow">Trace data flow · trace_data_flow</option><option value="is_path_reachable">Query control path · is_path_reachable</option><option value="inspect_api_usage">Inspect function calls · inspect_api_usage</option></select></div></div><div class="form-row"><div class="form-field"><label class="field-label" for="analysis-variable">Variable / access path</label><input id="analysis-variable" value="${state.task.mode==='walkthrough'?'requested_path':''}" placeholder="e.g. requested_path"></div><div class="form-field"><label class="field-label" for="analysis-line">Target line</label><input id="analysis-line" type="number" min="1" value="${state.line||1}"></div><div class="form-field"><label class="field-label" for="analysis-source">Path start line</label><input id="analysis-source" type="number" min="1" value="${state.task.mode==='walkthrough'?9:1}"></div></div><p class="muted-note">The query uses the current source snapshot. Results appear only in this dialog; structural reachability does not prove runtime reachability.</p><div id="analysis-result" style="margin-top:16px"></div>`;
 openModal('Interactive Program Analysis','Run KeaRepair structural analysis tools directly, without language model calls.',body,`<p>Read-only source · same-file analysis</p>${button('run-analysis','Run Analysis','bolt','primary')}`);
}
async function runAnalysis(target){
 const line=Number(document.querySelector('#analysis-line').value),sourceLine=Number(document.querySelector('#analysis-source').value);
 if(!Number.isInteger(line)||line<1||!Number.isInteger(sourceLine)||sourceLine<1){toast('Enter a valid positive line number.');return;}
 target.disabled=true;
 const body={tool:document.querySelector('#analysis-tool').value,line,source_line:sourceLine,variable:document.querySelector('#analysis-variable').value.trim()};
 const output=document.querySelector('#analysis-result');output.innerHTML=loading();
 try{const data=await api('/tasks/'+state.task.id+'/analyze',{method:'POST',body:JSON.stringify(body)});if(output.isConnected){output.innerHTML=`<div class="section-head"><h3>Analysis complete</h3>${pill(data.result?.status||'observation','teal')}</div><pre class="result-json">${esc(JSON.stringify(data,null,2))}</pre>`;applyTaskDisplay(output);}}
 catch(e){if(output.isConnected)output.innerHTML=`<div class="error-banner">${esc(uiMessage(e.message))}</div>`;}
 finally{target.disabled=false;}
}
async function showLogs(){
 state.modal='logs';openModal('Run Logs','Recent repair-process output. Configured secrets are redacted.',loading(),'',true);
 try{const data=await api('/tasks/'+state.task.id+'/logs');if(state.modal!=='logs')return;openModal('Run Logs','Latest 60 KB · refresh for new output',`<pre class="log-output">${esc(data.text||'The process has not produced output yet.')}</pre>`,button('logs','Refresh Logs','refresh'),true);}
 catch(e){fail(e);}
}
function showHelp(){
 state.modal='help';
 openModal('Understand the vulnerability. Understand the repair.','KeaRepair · Initial Release',
 `<div class="drawer-info"><h3>Start with the walkthrough</h3><p>Explore diagnosis, knowledge comparison, patch review and validation reports. Example source and patches are manually written; structural evidence comes from the real analyzer.</p></div><div class="drawer-info"><h3>Run a real case</h3><p>Select New Repair Task and choose a prepared local case. The task calls the configured model and Docker validation, saving source snapshots, artifacts and execution events.</p></div><div class="drawer-info"><h3>Review validation evidence</h3><p>Patch application, build, PoC and unit tests are recorded separately. A completed run does not by itself prove a fix; only checks with recorded passing results are marked as passed.</p></div><div class="kv-row"><kbd>Ctrl / ⌘</kbd><kbd>K</kbd> Find a case</div><div class="kv-row"><kbd>Esc</kbd> Close dialog</div>`,button('close-modal','Get Started','arrow','primary'));
}

