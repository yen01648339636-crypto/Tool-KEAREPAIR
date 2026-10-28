function reportConclusion(report={}){
 return report.summary||(report.hypotheses||[]).filter(x=>typeof x==='string').join('\n')||Object.values(report.root_causes_by_view||{}).filter(Boolean).join('\n');
}

function stageBanner(){
 const t=state.task;
 if(!state.presentation&&active.includes(t.status)&&runtimeStatus())return runtimeStatus();
 if(t.mode==='walkthrough')return `<div class="workspace-status"><div class="stage-marker">${icon('play')}</div><div class="stage-copy"><strong>Walkthrough</strong><p>This walkthrough uses a synthetic case and manually written patches. Validation has not run.</p></div></div>`;
 const labels={diagnosis:'Vulnerability Diagnosis',retrieval:'Dual-view Knowledge Retrieval',repair:'Patch Generation',validation:'Patch Validation',all:'Full Repair'};
 let title=labels[t.stage]||'Online Repair',note='';
 if(active.includes(t.status)){
  note=t.status==='queued'?'This stage is queued. Progress will update when execution begins.':t.status==='cancelling'?'Stopping this stage. Saved results will be retained.':t.stage==='diagnosis'?'Analyzing source and preparing the diagnosis report.':t.stage==='retrieval'?'Generating queries, retrieving and reranking historical examples.':t.stage==='validation'?'Validating the current patch. Open validation results to follow progress.':'Generating the patch. Review the code diff when complete.';
  if(t.source_preflight?.status==='running'&&t.stage!=='validation'){title='Source Consistency Check';note='Checking the source prepared inside the container before continuing.';}
 }else if(t.source_snapshot_stale){title='Case source updated';note='Create a task with the current source. Existing diagnosis and patches remain in this record.';}
 else if(t.status==='diagnosis_ready'){title='Diagnosis report ready';note=t.variant==='no_retrieval'?'Review the report, then generate a patch.':'Review the report, then retrieve repair knowledge.';}
 else if(t.status==='retrieval_ready'){title='Repair knowledge ready';note='Review both retrieval views and the selected examples, then generate a patch.';}
 else if(t.status==='patch_ready'){title='Patch generated; awaiting validation';note=t.mode==='replay'?'Review the diff, then select “Validate Patch” to continue the validation replay.':'Review the diff below, then select “Validate Patch” to run the build, PoC test and unit tests.';}
 else if(t.status==='diagnosis_incomplete'){title='Diagnosis needs review';note=(t.diagnosis_issues||[]).join('; ')||'Review the existing report or rerun diagnosis.';}
 else if(['failed','interrupted','cancelled'].includes(t.status)){title+=' · stopped';note='Saved reports and patches are retained. Resume from the current stage.';}
 else if(t.mode==='replay'&&t.status==='completed'){title='Workflow replay complete';note='Diagnosis, retrieval, patch and historical validation results are available. You can replay the workflow again.';}
 else{title=currentCandidate()?.validation_result?.success===true?'Repair passed validation':'Run finished';note=currentCandidate()?.validation_result?.success===true?'The final patch and configured validation results are saved.':'Review the results. Export detailed records from the More menu.';}
 return `<div class="workspace-status" role="status"><div class="stage-marker">${active.includes(t.status)?'<span class="spinner"></span>':icon('activity')}</div><div class="stage-copy"><strong>${esc(title)}</strong><p>${esc(uiMessage(note))}</p></div>${runtimeHistoryControl()||`<span class="workspace-status-label">${active.includes(t.status)?'Active stage':'Task status'}</span>`}</div>`;
}


function toolDetail(index){
 const c=(state.task.tool_calls||state.task.diagnosis_report?.tool_calls||[])[index];if(!c)return;state.modal='tool';
 const observation=c.observation||{},facts=observation.facts||[];
 openModal('Tool Call Results',esc(c.tool)+' · '+esc(c.status),
  `<div class="drawer-info"><h3>Input Arguments</h3><pre class="result-json">${esc(JSON.stringify(c.arguments||{},null,2))}</pre></div><div class="drawer-info"><h3>Tool Output</h3><pre class="result-json">${esc(JSON.stringify(observation.result||c.error||observation,null,2))}</pre></div><div class="drawer-info"><h3>Linked program facts · ${facts.length}</h3>${facts.map(f=>`<p><span class="mono">L${f.location?.start_line||'?'} · ${esc(f.evidence_id)}</span><br>${esc(f.statement)}</p>`).join('')||'<p>This call produced no program facts.</p>'}</div>`,
  button('close-modal','Close',null),true);
}

function downloadReport(){
 const t=state.task;
 const data=t.diagnosis_report;
 if(!data||!Object.keys(data).length){toast('The diagnosis report has not been generated yet.');return;}
 const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json;charset=utf-8'}));
 const a=document.createElement('a');a.href=url;a.download=t.case_id+'-diagnosis.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}

async function advanceStage(target){
 target.disabled=true;
 try{
  const id=state.task.id,stage=target.dataset.stage,tab=state.tab;
  await api('/tasks/'+id+'/advance',{method:'POST',body:JSON.stringify({stage})});
  const task=await api('/tasks/'+id);
  if(state.task?.id!==id)return;
  state.task=task;
  if(state.page==='workbench'&&state.tab===tab)setTaskTab(stage==='retrieval'?'knowledge':stage==='repair'?'patch':'diagnosis',{follow:Boolean(task.automatic)});
  else render();
  subscribe(id);
 }finally{if(target.isConnected)target.disabled=false;}
}
