// Live operations and report navigation use saved server observations, never simulated reasoning.
const workflowStages=[['diagnosis','Diagnosing vulnerability'],['knowledge','Retrieving repair knowledge'],['patch','Generating a patch'],['validation','Validating the patch']];
function workflowTab(t=state.task){
 if(!t)return 'diagnosis';
 if(!active.includes(t.status)&&t.automatic&&t.status==='completed')return 'report';
 if(t.stage==='validation')return 'validation';
 if(t.stage==='repair'){
  const v=t.runtime?.validation_progress||{},a=t.runtime?.progress?.activity||{};
  const newerGeneration=a.kind==='generation'&&Number(a.candidate_id)>Number(v.candidate_id||0);
  return v.running&&!newerGeneration?'validation':'patch';
 }
 return t.stage==='retrieval'?'knowledge':'diagnosis';
}
function workflowBanner(){
 const t=state.task,working=active.includes(t.status),record=t.runtime?.progress||{},tab=workflowTab(t);
 const success=Boolean((t.candidates||[]).some(c=>c.patch?.trim()&&c.validation_result?.success===true));
 const scopedPass=(t.candidates||[]).some(c=>c.patch?.trim()&&c.validation_result?.selected_checks_passed===true),patchOnly=t.repair_request?.validation_mode==='patch_only';
 const title=working?(t.status==='paused'?'Execution paused':t.status==='pausing'?'Pausing after the current operation':t.status==='queued'?'Queued for execution':t.status==='cancelling'?'Stopping safely':workflowStages.find(s=>s[0]===tab)?.[1]||'Running repair'):t.status==='completed'?(patchOnly?'Patch and report ready':success?'Repair complete':scopedPass?'PoC checks passed · report ready':'Run complete · review results'):'Workflow paused · '+statuses[t.status]?.[0];
 const elapsed={started_at:t.created_at,updated_at:t.updated_at,status:working?'running':'completed'};
 return `<div class="workflow-banner ${t.status==='paused'?'is-paused':working?'is-active':''}" role="status"><span class="workflow-status-dot"></span><strong>${esc(title)}</strong><span class="workflow-total">${icon('clock')}${runtimeElapsed(elapsed,t)}</span><span class="workflow-connection">${t.status==='paused'?'Resume to continue':working?(state.workflowConnection==='reconnecting'?'Reconnecting · polling updates':state.workflowConnection==='offline'?'Connection interrupted · reconnecting':'Live progress'):'Reports and artifacts saved'}</span>${working?button('workflow-follow',state.workflowFollow!==false?'Following current stage':'Follow current stage',state.workflowFollow!==false?'check':'activity','small',`aria-pressed="${state.workflowFollow!==false}"`):button('tab','Repair Report','file','small','data-tab="report"')}</div>`;
}
function workflowLivePanel(){
 const t=state.task;if(state.presentation||!t?.automatic||!active.includes(t.status))return '';
 const events=(t.events||[]).slice(-5),latest=events.at(-1);
 const disconnected=['offline','reconnecting'].includes(state.workflowConnection);
 const phase=t.status==='paused'?'Paused':t.status==='pausing'?'Pausing':disconnected?'Reconnecting':t.status==='queued'?'Queued':t.status==='cancelling'?'Stopping':'Running';
 const listening=t.status==='paused'?'Execution paused · ready to resume':t.status==='pausing'?'Finishing the current operation before pausing':disconnected?'Reconnecting to task updates':t.status==='queued'?'Waiting for a worker':t.status==='cancelling'?'Waiting for shutdown':'Listening for execution updates';
 const elapsed=latest?.at?runtimeElapsed({started_at:latest.at,status:'running'},t):'';
 return `<section class="workflow-live ${t.status==='paused'?'is-paused':disconnected?'is-disconnected':'is-streaming'}" aria-label="Live repair activity" data-ui-key="workflow-live">
  <div class="workflow-feed">
   <header class="workflow-feed-header"><div class="workflow-feed-title"><span class="workflow-terminal" aria-hidden="true">${icon('terminal')}</span><h2>Execution activity</h2></div><div class="workflow-feed-meta"><span class="workflow-event-count">${events.length?'Latest '+events.length+' events':'Waiting for events'}</span><span class="workflow-signal"><span class="workflow-signal-bars" aria-hidden="true">${[0,1,2,3,4].map(i=>`<i style="--bar:${i}"></i>`).join('')}</span>${phase}</span></div></header>
   <div class="workflow-event-log" role="log" aria-label="Execution events" aria-live="polite" aria-relevant="additions text"><ol class="workflow-timeline">${events.map((e,i)=>`<li data-ui-key="event-${e.seq}" class="workflow-event ${i===events.length-1?'is-latest':'is-history'}"><span class="workflow-event-node" aria-hidden="true"><i></i></span><div class="workflow-event-card"><div class="workflow-event-meta"><span class="workflow-event-label">${i===events.length-1?'Latest event':'Recorded event'}</span><time>${e.at?new Date(e.at).toLocaleTimeString('en-US',{hour12:false}):'—'}</time></div><p class="workflow-event-message">${esc(uiMessage(e.message))}</p>${i===events.length-1?'<span class="workflow-event-track" aria-hidden="true"><i></i></span>':''}</div></li>`).join('')}</ol>${!events.length?'<div class="workflow-feed-empty"><span class="spinner" aria-hidden="true"></span><span>Waiting for execution events</span></div>':''}</div>
   <footer class="workflow-feed-footer"><span class="workflow-listening"><span class="workflow-listening-dots" aria-hidden="true"><i></i><i></i><i></i></span>${listening}</span>${elapsed?`<span class="workflow-event-age" aria-live="off">Since last event <strong>${elapsed}</strong></span>`:''}</footer>
  </div></section>`;
}
function captureWorkflowEvents(){
 const rows=[...document.querySelectorAll('.workflow-timeline>.workflow-event')];
 if(!rows.length)return null;
 return {latest:rows.at(-1).dataset.uiKey,rows:new Map(rows.map(node=>[node.dataset.uiKey,{node,top:node.getBoundingClientRect().top}]))};
}
function animateWorkflowEvents(previous){
 if(!previous||window.matchMedia('(prefers-reduced-motion: reduce)').matches)return;
 const rows=[...document.querySelectorAll('.workflow-timeline>.workflow-event')];
 if(!rows.length||rows.at(-1).dataset.uiKey===previous.latest)return;
 for(const node of rows){
  const old=previous.rows.get(node.dataset.uiKey);if(!old||old.node!==node)continue;
  const offset=old.top-node.getBoundingClientRect().top;
  if(Math.abs(offset)>1)node.animate([{transform:`translateY(${offset}px)`},{transform:'translateY(0)'}],{duration:420,easing:'cubic-bezier(.2,.8,.2,1)'});
 }
}
function repairReportPanel(){
 const t=state.task,c=currentCandidate(),report=t.diagnosis_report||{},selected=t.retrieval?.final_exemplars||[],passed=c?.validation_result?.success===true,validation=c?resultValidationModel(c):null;
 const request=t.repair_request||{},mode=request.validation_mode||'full',patchOnly=mode==='patch_only',scopePassed=validation?.selectedPassed,complete=t.status==='completed',deliverable=complete&&c?.patch?.trim()&&(patchOnly||scopePassed||passed);
 const title=complete?(patchOnly&&c?.patch?.trim()?'Generated patch and repair report':passed?'Validated patch and repair report':scopePassed?'PoC results and repair report':'Repair report · validation incomplete'):active.includes(t.status)?'Repair report in progress':'Partial repair report';
 const description=patchOnly?'Patch generation was requested. Validation was not run.':scopePassed&&mode==='poc'?'Patch application, build and PoC checks passed. Unit tests were not requested.':passed?'The patch passed all configured validation checks.':'All saved findings and check outcomes are included below.';
 const downloadButtons=t.mode==='walkthrough'?'':`${button('repair-report','Download Report','download','primary','data-format="html"')}${button('repair-report','JSON','code','secondary','data-format="json"')}${button('export','Evidence Bundle','layers','secondary')}`;
 return `<div class="repair-report" data-ui-key="repair-report"><header class="report-heading"><div><span class="label">${complete?'WORKFLOW RESULT':'SAVED PROGRESS'}</span><h2>${title}</h2><p>${esc(description)}${t.mode==='replay'?' Saved execution records.':''}</p></div><div class="report-downloads">${downloadButtons}</div></header>
 <div class="report-content"><section class="report-section report-patch"><div class="report-section-heading"><span>01</span><h3>${deliverable?'Final Patch':'Latest Patch'}</h3>${c?.patch?.trim()?button('patch-download','Download Patch','download','small'):''}</div>${c?.patch?.trim()?`<p>${esc(t.file)} · ${patchOnly?'Validation not requested':passed?'Validated':scopePassed?'PoC checks passed':active.includes(t.status)?'Validation in progress':'Not fully validated'}</p><div class="report-patch-preview">${diffView(c.patch)}</div>`:empty('Patch pending','A generated patch will appear here when available.')}</section>
 <section class="report-section"><div class="report-section-heading"><span>02</span><h3>Diagnosis Report</h3>${button('tab','Inspect Diagnosis','arrow','small','data-tab="diagnosis"')}</div><p class="report-summary">${esc(report.summary||'The diagnosis report has not been generated yet.')}</p>${(report.limitations||[]).length?`<details data-ui-key="report-limitations"><summary>Analysis limitations · ${report.limitations.length}</summary><ul>${report.limitations.map(x=>`<li>${esc(x)}</li>`).join('')}</ul></details>`:''}</section>
 <section class="report-section"><div class="report-section-heading"><span>03</span><h3>Selected Examples</h3>${button('tab','Inspect Retrieval','arrow','small','data-tab="knowledge"')}</div>${t.retrieval?.skipped?'<p>Retrieval was skipped for this variant.</p>':`<div class="report-selected"><h4>${icon('layers')}After reranking · ${selected.length} selected</h4><div>${selected.map((c,i)=>`<button data-action="exemplar" data-index="${i}"><span>#${i+1}</span><strong>${esc(c.cve_id||c.sample_id)}</strong><small>${typeof c.rerank_score==='number'?'Score '+c.rerank_score.toFixed(3):'Selected example'} ${icon('arrow')}</small></button>`).join('')||'<p>Awaiting reranked examples.</p>'}</div></div>`}</section>
 <section class="report-section"><div class="report-section-heading"><span>04</span><h3>Validation Results</h3>${!patchOnly?button('tab','Inspect Checks','arrow','small','data-tab="validation"'):''}</div><div class="report-checks">${patchOnly?'<p>Validation was not requested for this task.</p>':validation?validation.stages.filter(s=>!['source_prepare','patch_apply'].includes(s.id)).map(s=>`<div>${icon(s.status==='passed'?'check':s.status==='running'?'activity':'clock')}<strong>${esc(s.label||s.title||s.id)}</strong>${pill(s.status.replace('_',' '),s.status==='passed'?'teal':['failed','error'].includes(s.status)?'red':'')}</div>`).join(''):'<p>No validation results saved yet.</p>'}</div>${mode==='poc'?'<p class="review-hint">Unit tests were not requested.</p>':''}</section></div></div>`;
}
