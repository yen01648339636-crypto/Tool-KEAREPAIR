// Replay is paced by the server; future reports are not sent to this page.
function canReplay(t){return t&&!t.repair_request?.uploaded_tests&&!active.includes(t.status)&&(t.mode==='replay'||(t.validated&&t.variant==='full'));}
function replayButton(t,style='small'){
 return canReplay(t)?button('replay-task',t.mode==='replay'?'Replay Again':'Replay Workflow','play',style,`data-id="${esc(t.id)}" title="Replay real historical records by stage in about 75 seconds"`):'';
}
async function startReplay(target){
 target.disabled=true;
 try{const t=await api('/tasks/'+encodeURIComponent(target.dataset.id)+'/replay',{method:'POST'});await openTask(t.id,{tab:'diagnosis'});toast('Replay started. All stages will continue automatically.');}
 finally{if(target.isConnected)target.disabled=false;}
}
function replayAvailable(){return state.variant==='full'&&Boolean(state.caseItems.find(c=>c.key===state.selectedCase)?.replay_source_id);}
function chooseDefaultExecutionMode(){state.executionMode=replayAvailable()?'replay':'live';}
function executionModeControl(){
 return `<div class="form-row"><div class="form-field"><label class="field-label" for="execution-mode">Execution mode</label><select id="execution-mode">${replayAvailable()?'<option value="replay">Demo replay · saved verified records (about 75 s)</option>':''}<option value="live">Live run · model calls and container tests</option></select></div></div>`;
}
