// Task navigation and entry deletion. Opening a saved run never starts a repair stage.
const taskVariantNames={full:'Full framework',df_only:'Data flow only',cf_only:'Control flow only',no_retrieval:'No retrieval',no_iteration:'No iteration'};
const taskStageNames={diagnosis:'Vulnerability Diagnosis',retrieval:'Knowledge Retrieval',repair:'Patch Generation',validation:'Patch Validation',all:'Full Repair'};
function taskOrderedRows(){
 return [...(state.overview?.tasks||[])].sort((a,b)=>(Date.parse(b.updated_at||b.created_at)||0)-(Date.parse(a.updated_at||a.created_at)||0));
}
function taskCaseTitle(t){return taskDisplayName(t);}
function taskResumeTab(t){
 if(t.status==='diagnosis_ready'||t.status==='diagnosis_incomplete')return 'diagnosis';
 if(t.status==='retrieval_ready')return 'knowledge';
 if(t.validated)return 'patch';
 return {diagnosis:'diagnosis',retrieval:'knowledge',repair:'patch',validation:'validation'}[t.stage]||'diagnosis';
}
function taskRecordRow(t){
 const quiet=!active.includes(t.status),time=t.updated_at||t.created_at;
 return `<article class="task-record" data-ui-key="task-record-${esc(t.id)}"><div class="task-record-body"><div class="task-record-title"><strong>${esc(taskCaseTitle(t))}</strong>${status(t.status)}${t.validated?pill('Validated','teal'):''}</div><div class="task-record-meta"><span>${esc(String(t.case_key||'').split(':')[0])}</span><span class="mono" title="Run ID ${esc(t.id)}">${esc(String(t.id).slice(0,8))}</span><span>${esc(taskVariantNames[t.variant]||t.variant||'Full framework')}</span><span>${esc(taskStageNames[t.stage]||t.stage||'Repair task')}</span><time title="Last updated">${date(time)}</time></div></div><div class="task-record-actions">${button('open-task',taskResumeLabel(t),'arrow','small',`data-id="${esc(t.id)}" data-tab="${taskResumeTab(t)}"`)}${canReplay(t)?replayButton(t):quiet?button('present-task','Present results','play','small task-present',`data-id="${esc(t.id)}" title="Present saved results in read-only mode" aria-label="Present ${esc(taskCaseTitle(t))}  saved results"`):''}${button('delete-task','Delete','trash','small task-delete',`data-id="${esc(t.id)}" aria-label="Delete ${esc(taskCaseTitle(t))}, run ${esc(t.id)}" title="${quiet?'Delete this task entry':'Stop the running task before deleting'}" ${quiet?'':'disabled'}`)}</div></article>`;
}
function taskCenterPanel(){
 const rows=taskOrderedRows();
 return `<div class="task-center-page"><div class="page-actions" role="toolbar" aria-label="Task actions">${button('new','New Repair Task','plus','primary')}</div><section class="task-browser"><header class="task-browser-heading"><h2>Run History</h2><span class="task-run-count" role="status">${fmt(rows.length)} runs</span></header>${rows.length?`<div class="task-record-list">${rows.map(taskRecordRow).join('')}</div>`:empty('Start your first repair','Start a repair task to see its execution record here.',button('new','New Repair Task','plus','primary'))}</section></div>`;
}
function taskHistoryPanel(){return taskCenterPanel();}
function confirmTaskDeletion(id){
 const task=state.overview?.tasks.find(t=>t.id===id);
 if(!task)return;
 if(active.includes(task.status)){toast('Stop the running task before deleting it.');return;}
 state.modal='delete-task';state.deleteTaskId=id;
 openModal('Delete task entry?','Remove this run from Task Center and run history.',
  `<div class="task-delete-summary"><div><strong>${esc(taskCaseTitle(task))}</strong>${status(task.status)}</div><p class="mono">Run ${esc(id)}</p></div><p class="task-delete-note">Saved reports, patches and logs will remain on disk. Other task entries, source datasets and the knowledge base will be kept.</p><div id="task-delete-error" class="error-banner" role="alert" hidden></div>`,
  `${button('close-modal','Cancel',null)}${button('confirm-delete-task','Delete Entry','trash','task-delete task-delete-confirm',`data-id="${esc(id)}"`)}`);
}
function forgetTaskSelection(id){
 if(state.task?.id===id){
  stream?.close();stream=null;clearTimeout(streamTimer);++routeSerial;
  state.task=null;state.presentation=false;state.presentationCapturedAt=null;state.loadingTask=false;
 }
 try{if(localStorage.getItem('kea-task')===id)localStorage.removeItem('kea-task');}catch{}
 for(const key of [...readingCache.keys()])if(key.startsWith('task:'+id+':'))readingCache.delete(key);
 try{
  const keys=Array.from({length:sessionStorage.length},(_,i)=>sessionStorage.key(i));
  for(const key of keys)if(key==='kea-last-review:'+id||key?.startsWith('kea-reading-v2:task:'+id+':'))sessionStorage.removeItem(key);
 }catch{}
}
async function deleteTaskEntry(target){
 if(state.deletingTask)return;
 const id=target.dataset.id;
 state.deletingTask=id;target.disabled=true;target.textContent='Deleting…';
 const error=document.querySelector('#task-delete-error');if(error)error.hidden=true;
 try{
  await api('/tasks/'+encodeURIComponent(id),{method:'DELETE'});
  state.overview.tasks=state.overview.tasks.filter(t=>t.id!==id);
  forgetTaskSelection(id);
  if(state.modal==='delete-task'&&state.deleteTaskId===id)closeModal();
  if(state.page==='workbench'&&!state.task){state.page='home';writeRoute('replace');}
  render();
  if(!document.querySelector('.modal'))document.querySelector('.task-browser [data-action]:not(:disabled)')?.focus({preventScroll:true});
  toast('Task entry deleted. Saved files remain on disk.');
 }catch(e){
  if(error?.isConnected){error.textContent=uiMessage(e.message);error.hidden=false;}
  else fail(e);
 }finally{
  state.deletingTask=null;
  if(target.isConnected){target.disabled=false;target.innerHTML=icon('trash')+'Delete Entry';}
 }
}
async function handleTaskManagementAction(target){
 switch(target.dataset.action){
 case 'delete-task':confirmTaskDeletion(target.dataset.id);return true;
 case 'confirm-delete-task':await deleteTaskEntry(target);return true;
 default:return false;
 }
}
