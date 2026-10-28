// Progress is display-only. Every record is bound to the worker invocation by the server.
const runtimeLabels={initializing:'Initializing stage',source_check:'Checking container source',model_loading:'Initializing the online model',embedding_model_loading:'Loading the retrieval model',code_encoder_loading:'Loading the code reranker',index_loading:'Reading dual-view indexes',diagnosis:'Diagnosing source',query_generation:'Generating retrieval queries',retrieval:'Retrieving historical examples',reranking:'Reranking candidates',repair:'Generate Patch',source_prepare:'Preparing and installing validation source',candidate_installed:'Patched source installed',test_command:'Running validation command',complete:'Validation execution finished',baseline:'Checking validation source'};
function runtimeStepLabel(record){const key=record.substep||record.step;return uiMessage(record.replay_label||runtimeLabels[key]||runtimeLabels[record.step]||record.step||'Running current stage');}
function runtimeSeconds(value){const seconds=Math.max(0,Number(value)||0);return seconds<60?`${Math.floor(seconds)} s`:`${Math.floor(seconds/60)} min ${Math.floor(seconds%60)} s`;}
function runtimeElapsed(record,task=state.task){
 const start=record.step_started_at||record.started_at,paused=task?.status==='paused',live=active.includes(task?.status)&&!paused&&record.status==='running';
 const end=paused?Date.parse(task.pause?.paused_at||task.updated_at):live?Date.now():Date.parse((record.status==='running'?task?.updated_at:record.updated_at)||task?.updated_at||'');
 const begin=Date.parse(start),excluded=(task?.pause?.intervals||[]).reduce((sum,item)=>sum+Math.max(0,Math.min(end,Date.parse(item.finished_at)||end)-Math.max(begin,Date.parse(item.started_at))),0)/1000;
 const duration=Number.isFinite(end)&&Number.isFinite(begin)?Math.max(0,(end-begin)/1000-excluded):record.elapsed_seconds;
 return `<span class="runtime-elapsed" ${live&&start?`data-runtime-start="${esc(start)}" data-runtime-paused="${excluded}"`:''}>${runtimeSeconds(duration)}</span>`;
}
function runtimeHistoryControl(runtime=state.task?.runtime||{}){
 const p=runtime.progress||{},v=runtime.validation_progress||{},history=p.history||[];
 if(!history.length&&!Object.keys(v).length)return '';
 return `<details class="runtime-history" data-ui-key="runtime-history"><summary>Step history ${icon('chevron')}</summary><div class="runtime-history-list">${history.map(h=>`<div><span>${icon(h.status==='completed'?'check':'info')}${esc(runtimeStepLabel(h))}</span><span>${h.status==='completed'?'Done':'Incomplete'} · ${runtimeSeconds(h.elapsed_seconds)}</span></div>`).join('')}${Object.keys(v).length?`<div><span>${icon('shield')}${esc(runtimeStepLabel(v))}${v.candidate_id?' · Patch '+esc(v.candidate_id):''}</span><span>${v.running?(active.includes(state.task?.status)?'Running':'Stopped'):v.status==='completed'?'Completed':'Incomplete'}</span></div>`:''}</div></details>`;
}
function runtimeStatus(){
 const t=state.task,r=t.runtime||{},p=r.progress||{},v=r.validation_progress||{};
 const candidateActive=active.includes(t.status)&&v.running;
 const record=candidateActive?v:Object.keys(p).length?p:Object.keys(v).length?v:null;
 if(!record)return '';
 const ongoing=active.includes(t.status)&&record.status==='running',interrupted=!active.includes(t.status)&&record.status==='running';
 const candidate=record===v&&v.candidate_id?` · Patch ${v.candidate_id}`:'';
 const phase=t.status==='paused'?'Paused':t.status==='pausing'?'Pausing':ongoing?'Running':interrupted?'Stopped':record.status==='failed'?'Incomplete':'Recorded';
 const updated=record.updated_at?new Date(record.updated_at).toLocaleTimeString('en-US',{hour12:false}):'—';
 return `<div class="workspace-status runtime-status" role="status"><div class="stage-marker">${ongoing?'<span class="spinner"></span>':icon(record.status==='failed'?'info':'activity')}</div><div class="stage-copy"><strong>${esc(runtimeStepLabel(record)+candidate)}</strong><p>${phase} · elapsed ${runtimeElapsed(record,t)} · updated ${esc(updated)}</p></div>${runtimeHistoryControl(r)}</div>`;
}

function tickRuntime(){document.querySelectorAll('[data-runtime-start]').forEach(node=>{node.textContent=runtimeSeconds((Date.now()-Date.parse(node.dataset.runtimeStart))/1000-Number(node.dataset.runtimePaused||0));});}
setInterval(tickRuntime,1000);
function partialRetrieval(t=state.task||{}){
 const part=t.retrieval_progress;
 if(t.stage!=='retrieval')return null;
 if(part&&Object.keys(part).length&&part.status!=='completed')return part;
 if(t.runtime?.execution_id&&[...active,'failed','interrupted','cancelled'].includes(t.status)&&(!part||!Object.keys(part).length))return {queries:{},candidates:[],completed_views:[],status:active.includes(t.status)?'running':'failed',step:t.runtime.progress?.step||'initializing'};
 return null;
}
function progressiveRetrievalNote(m){
 if(!m.partial)return '';
 const done=m.r.completed_views||[],status=m.r.status;
 return `<div class="retrieval-live-note" role="status">${status==='running'?'<span class="spinner"></span>':icon('info')}<div><strong>${status==='failed'?'Stage stopped; showing saved progress':m.r.step==='reranking'?'Both retrieval results saved; reranking':'Saving retrieval results'}</strong><p>${done.length?done.map(v=>v==='data_flow'?'Data flow':'Control flow').join(' / ')+' returned. ':'Queries and results appear as they arrive. '}Selected examples appear after reranking.</p></div></div>`;
}
function activeValidationCandidate(){
 const p=state.task?.runtime?.validation_progress;
 if(!p||!p.running||!active.includes(state.task?.status)||!p.candidate_id)return null;
 const a=state.task?.runtime?.progress?.activity;
 if(a?.kind==='generation'&&Number(a.candidate_id)>Number(p.candidate_id))return null;
 const saved=(state.task.candidates||[]).find(c=>String(c.candidate_id)===String(p.candidate_id));
 return saved?{...saved,live_validation_progress:p}: {candidate_id:p.candidate_id,live_validation_progress:p,validation_result:null,patch:null};
}
