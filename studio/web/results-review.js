/* Read-only presentation of saved patches and native validation records. */
function reviewDiffModel(patch){
 const files=[];let file=null,hunk=null;
 const lines=String(patch||'').replace(/\r\n/g,'\n').split('\n');
 if(lines.at(-1)==='')lines.pop();
 const path=s=>s.split('\t')[0].replace(/^[ab]\//,'');
 for(let i=0;i<lines.length;i++){
  const line=lines[i];
  const complete=!hunk||(hunk.rows.filter(r=>['context','remove'].includes(r.kind)).length>=hunk.oldCount&&hunk.rows.filter(r=>['context','add'].includes(r.kind)).length>=hunk.newCount);
  if(complete&&line.startsWith('--- ')&&lines[i+1]?.startsWith('+++ ')){
   file={oldPath:path(line.slice(4)),newPath:path(lines[++i].slice(4)),hunks:[],extra:[],valid:true};files.push(file);hunk=null;continue;
  }
  const m=line.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$/);
  if(m&&file){hunk={header:line,oldStart:+m[1],oldCount:m[2]===undefined?1:+m[2],newStart:+m[3],newCount:m[4]===undefined?1:+m[4],rows:[]};file.hunks.push(hunk);continue;}
  if(hunk&&/^[ +\-\\]/.test(line)){hunk.rows.push({kind:line[0]==='+'?'add':line[0]==='-'?'remove':line[0]===' '?'context':'note',text:line.slice(1),raw:line});}
  else if(file&&!/^(diff |index |new file |deleted file |old mode |new mode |similarity |rename )/.test(line)){file.extra.push(line);file.valid=false;}
 }
 let added=0,removed=0;
 files.forEach(f=>f.hunks.forEach(h=>{
  let old=h.oldStart,next=h.newStart;
  h.rows.forEach(r=>{r.old=r.kind==='context'||r.kind==='remove'?old++:null;r.new=r.kind==='context'||r.kind==='add'?next++:null;if(r.kind==='add')added++;if(r.kind==='remove')removed++;});
  if(old-h.oldStart!==h.oldCount||next-h.newStart!==h.newCount)f.valid=false;
 }));
 return {files,added,removed,hunks:files.reduce((n,f)=>n+f.hunks.length,0),valid:files.length>0&&files.every(f=>f.valid&&f.hunks.length>0)};
}
function reviewContextModel(file){
 const t=state.task||{},source=t.source;
 // Parsed file paths already had exactly one Git a/ or b/ prefix removed.
 const normalize=s=>String(s||'').replace(/^\.\//,'');
 if(!file.valid||typeof source!=='string'||normalize(file.oldPath)!==normalize(t.file)||normalize(file.newPath)!==normalize(t.file))return null;
 const lines=source.replace(/\r\n/g,'\n').split('\n');if(lines.at(-1)==='')lines.pop();
 let end=0,delta=0;
 for(const h of file.hunks){
  // The complete old side and both range counts must agree with the snapshot.
  if(h.oldStart<1||h.oldStart-1<end||h.oldStart+h.oldCount-1>lines.length||h.newStart!==h.oldStart+delta)return null;
  const original=h.rows.filter(r=>r.kind==='context'||r.kind==='remove');
  if(original.some((r,i)=>r.text!==lines[h.oldStart-1+i]))return null;
  end=h.oldStart-1+h.oldCount;delta+=h.newCount-h.oldCount;
 }
 return lines;
}
function reviewHunkRows(file,index,expanded){
 const h=file.hunks[index],source=expanded&&reviewContextModel(file);
 if(!source)return h.rows;
 const previous=file.hunks[index-1],next=file.hunks[index+1],start=h.oldStart-1,end=start+h.oldCount;
 // Divide nearby inter-hunk context at the midpoint so it is never repeated.
 const from=Math.max(previous?Math.floor((previous.oldStart-1+previous.oldCount+start)/2):0,start-12),to=Math.min(next?Math.floor((end+next.oldStart-1)/2):source.length,end+12);
 const before=[],after=[],offset=h.newStart-h.oldStart;
 for(let p=from;p<h.oldStart-1;p++)before.push({kind:'context',text:source[p],old:p+1,new:p+1+offset});
 const afterOffset=offset+h.newCount-h.oldCount;
 for(let p=h.oldStart-1+h.oldCount;p<to;p++)after.push({kind:'context',text:source[p],old:p+1,new:p+1+afterOffset});
 return [...before,...h.rows,...after];
}
function reviewUnifiedRows(rows){
 return rows.map(r=>`<div class="review-diff-row ${r.kind}"><span class="review-line-number">${r.old??''}</span><span class="review-line-number">${r.new??''}</span><span class="review-line-sign">${r.kind==='add'?'+':r.kind==='remove'?'-':r.kind==='note'?'\\':''}</span><code>${esc(r.text)||' '}</code></div>`).join('');
}
function reviewSplitRows(rows){
 const output=[];
 const cell=(r,side)=>`<span class="review-line-number">${r?.[side]??''}</span><code class="${r?.kind||'blank'}">${r?esc(r.text)||' ':' '}</code>`;
 for(let i=0;i<rows.length;){
  const r=rows[i];
  if(r.kind==='context'){output.push(`<div class="review-split-row">${cell(r,'old')}${cell(r,'new')}</div>`);i++;continue;}
  if(r.kind==='note'){output.push(`<div class="review-diff-note">${esc(r.raw||'\\'+r.text)}</div>`);i++;continue;}
  const removed=[],added=[];
  // Mechanical row alignment of consecutive edits; no semantic matching.
  while(i<rows.length&&['remove','add'].includes(rows[i].kind)){(rows[i].kind==='remove'?removed:added).push(rows[i++]);}
  for(let p=0;p<Math.max(removed.length,added.length);p++)output.push(`<div class="review-split-row">${cell(removed[p],'old')}${cell(added[p],'new')}</div>`);
 }
 return output.join('');
}
function reviewDiffHTML(model){
 if(!model.valid)return `<div class="review-raw-diff">${diffView(currentCandidate()?.patch)}</div><p class="review-hint">This patch does not support line-by-line comparison. The original diff is shown below.</p>`;
 const split=state.diffMode==='split';
 return model.files.map((file,fi)=>`<section class="review-diff-file"><div class="review-file-head">${icon('file')}<span>${esc(file.newPath==='/dev/null'?file.oldPath:file.newPath)}</span><small>${file.hunks.length} changes</small></div><div class="review-diff-scroll" tabindex="0" aria-label="${split?'Side-by-side':'Unified'}code diff">${split?'<div class="review-split-head"><span>Original code</span><span>Patched code</span></div>':''}${file.hunks.map((h,hi)=>`<div id="patch-hunk-${fi}-${hi}" class="review-hunk"><div class="review-hunk-head"><span>${esc(h.header)}</span><small>Change ${hi+1}</small></div>${split?reviewSplitRows(reviewHunkRows(file,hi,state.diffContext)):reviewUnifiedRows(reviewHunkRows(file,hi,state.diffContext))}</div>`).join('')}</div></section>`).join('');
}
const reviewStageLabels={source_prepare:'Source Preparation',patch_apply:'Patch Application',compile:'Build Check',poc:'PoC Test',unit:'Unit Tests'};
function reviewValidationMode(task=state.task){
 const mode=task?.repair_request?.validation_mode;
 return ['patch_only','poc','full'].includes(mode)?mode:'full';
}
function reviewStatus(value){
 const names={paused:['Paused','amber'],pausing:['Pausing','amber'],passed:['Passed','teal'],failed:['Failed','red'],error:['Error','red'],running:['Running','teal'],queued:['Queued','amber'],not_run:['Not run',''],not_requested:['Not requested',''],not_recorded:['Not recorded separately',''],cancelled:['Stopped','amber'],interrupted:['Interrupted','amber']};
 return pill(...(names[value]||[value||'Not run','']));
}
function reviewDuration(value){return typeof value==='number'&&Number.isFinite(value)?value<.01?'< 0.01 s':value<60?`${value.toFixed(2)} s`:`${Math.floor(value/60)} min ${(value%60).toFixed(1)} s`:'—';}
function reviewPlain(value){return String(value??'').replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'');}
function reviewContainerPatchStage(stage,preparation){
 // Native patch_apply measures host-side diff application. The container card
 // instead waits for this command's verified install boundary, never an earlier
 // container's receipt. Keep the native detail intact for inspection/export.
 if(stage.status!=='passed'||stage.detail.operation!=='exact_original_source_application'||!preparation?.status)return stage;
 const current=preparation.steps?.at(-1),installed=preparation.status==='passed'&&current?.status==='passed'&&current.boundary==='apply';
 return {...stage,status:installed?'passed':preparation.status==='running'?'queued':'not_run',duration:null,
  operation:'container_source_installation',stepName:current?.step,
  reason:installed?'The test container confirmed patch installation. Installation was not timed separately.':preparation.status==='running'?'Preparing source in the test container; waiting for patch installation confirmation.':'The test container has not confirmed patch installation.'};
}
function resultValidationModel(c){
 const mode=reviewValidationMode(),notRequested=mode==='patch_only',requestedStages=notRequested?[]:mode==='poc'?['patch_apply','compile','poc']:['patch_apply','compile','poc','unit'];
 if(notRequested)return {candidate:c,result:{},run:null,progress:{},working:false,stages:[],states:{},details:{},error:'',hint:'',
  title:'Validation not requested',summary:'This task generates a patch and repair report. No validation checks are included.',tone:'',passed:0,
  mode,notRequested,requestedStages,checkCount:0,selectedPassed:false};
 const taskActive=active.includes(state.task?.status),live=(taskActive||!c?.validation_result)&&c?.live_validation_progress,run=c?.latest_validation,working=Boolean(taskActive&&(live?live.running:run&&active.includes(run.status)));
 const result=live?{stage_status:live.stage_status||{},stage_details:live.stage_details||{},success:false,error_log:live.error||''}:c?.validation_result||{};
 const progress=live|| (working?run.progress||{}:{}),states=live||working?progress.stage_status||{}:result.stage_status||{},details=live||working?progress.stage_details||{}:result.stage_details||{};
 const stages=Object.entries(reviewStageLabels).filter(([id])=>id==='source_prepare'||requestedStages.includes(id)).map(([id,label])=>{
  const detail=details[id]||{},value=states[id]||(!working&&result[id+'_status']);
  let status=id==='source_prepare'?states[id]||detail.status||'not_recorded':value||(working&&run?.status==='queued'?'queued':'not_run');
  if(!taskActive&&status==='running')status=state.task?.status==='cancelled'?'cancelled':state.task?.status==='interrupted'?'interrupted':'error';
  const stage={id,label,status,detail,duration:detail.duration_seconds??detail.command_duration_seconds,shared:Array.isArray(detail.declared_covers)&&detail.declared_covers.length>1};
  return id==='patch_apply'?reviewContainerPatchStage(stage,details.source_prepare):stage;
 });
 const error=uiMessage(reviewPlain(run?.error||result.error_log||'')),nativeFailure=stages.find(s=>['failed','error'].includes(s.status));
 const stopped=['failed','cancelled','interrupted'].includes(run?.status||state.task?.status);
 const selectedPassed=!working&&(mode==='poc'?result.selected_checks_passed===true:result.success===true)&&requestedStages.every(id=>(states[id]||result[id+'_status'])==='passed');
 let title=working?'Validating the current patch':selectedPassed?(mode==='poc'?'PoC checks passed':'All configured checks passed'):nativeFailure?'Validation needs attention':stopped?'Validation interrupted':'Validation incomplete';
 let summary=working?'Stage status updates as execution records arrive.':selectedPassed?(mode==='poc'?'Patch application, build and PoC test passed.':'Patch application, build, PoC test and unit tests all passed.'):nativeFailure?`${nativeFailure.label} was marked ${nativeFailure.status==='error'?'Error':'Failed'}. Check the output for this stage.`:stopped?'The patch is saved. Use the action above to validate it again.':'The patch is saved. Select “Validate Patch” to run the checks and view the results.';
 let hint='';
 if(/gnutls_handshake|TLS connection|SSL certificate|Could not resolve host|git clone[^\n]*failed|unable to access.*https?:|\u6e90\u7801\u51c6\u5907\u8d85\u65f6|source.prepar.*(?:timeout|timed out|fail)/i.test(error+'\n'+Object.values(details).map(x=>reviewPlain(x.stderr)).join('\n'))){
  hint='Source retrieval or network access failed. Check source preparation and connection errors before assessing the patch.';
 }else if(/Cannot connect to the Docker|docker daemon|permission denied.*docker|image.*not found|pull access denied/i.test(error)){hint='The container environment or image is unavailable. Check the environment and retry validation.';}
 if(taskActive&&live&&!working&&!nativeFailure){title='Saving validation results';summary='Execution has finished. Verifying and saving validation artifacts.';}
 if(state.task?.mode==='walkthrough'){title='Walkthrough validation was not run';summary='This task uses manually written example patches. Stage status does not represent real test results.';}
 return {candidate:c,result,run,progress,working,stages,states,details,error,hint,title,summary,tone:working||selectedPassed?'teal':nativeFailure||stopped?'amber':'',passed:stages.filter(s=>s.id!=='source_prepare'&&s.status==='passed').length,
  mode,notRequested,requestedStages,checkCount:requestedStages.length,selectedPassed};
}
function patchReviewPanel(){
 const c=currentCandidate();if(!c)return empty('Waiting for patch generation','');
 if(!c.patch?.trim())return candidateBar()+empty('No valid patch in this record',uiMessage(c.generation_error)||'Check the run status or wait for the next repair result.');
 const model=reviewDiffModel(c.patch),v=resultValidationModel(c),context=model.valid&&model.files.some(f=>reviewContextModel(f)),split=state.diffMode==='split';
 const badge=v.notRequested?'not_requested':v.working&&['paused','pausing'].includes(state.task.status)?state.task.status:v.working?'running':v.selectedPassed?'passed':v.stages.find(s=>['failed','error'].includes(s.status))?.status||(['failed','cancelled','interrupted'].includes(v.run?.status)?v.run.status:'not_run');
 return candidateBar()+`<div class="patch-review"><div class="review-diff-main"><div class="review-diff-toolbar"><div class="review-change-stats"><strong>${model.files.length||'—'} files</strong><span class="review-added">+${model.added}</span><span class="review-removed">−${model.removed}</span><span>${model.hunks} changes</span></div><div class="review-diff-options"><div class="segmented" role="group" aria-label="Diff display mode">${['unified','split'].map(m=>`<button data-action="diff-mode" data-mode="${m}" class="${(m==='split')===split?'active':''}" aria-pressed="${(m==='split')===split}">${m==='split'?'Side by side':'Unified diff'}</button>`).join('')}</div>${context?`<button class="button small" data-action="diff-context" aria-pressed="${Boolean(state.diffContext)}">${state.diffContext?'Hide context':'Show context'}</button>`:''}</div></div>${reviewDiffHTML(model)}${state.diffContext&&context?'<p class="review-hint">Context comes from the verified original source snapshot, with up to 12 lines around each change.</p>':''}</div><aside class="review-result-aside"><div class="review-aside-label">REPAIR SUMMARY</div><h3>Repair Summary</h3><p class="review-explanation">${esc(c.explanation||'No separate repair explanation was saved for this run.')}</p><div class="review-aside-divider"></div><div class="section-head"><h3>Validation Summary</h3>${reviewStatus(badge)}</div><div class="review-compact-stages">${v.stages.filter(s=>s.id!=='source_prepare').map(s=>`<div><span>${esc(s.label)}</span>${reviewStatus(s.status)}</div>`).join('')}</div>${v.selectedPassed?`<p class="review-hint">${v.passed} / ${v.checkCount} selected checks passed</p>`:`<p class="review-hint">${esc(v.working?'Validation is running. Status updates as execution records arrive.':v.hint||v.summary)}</p>`}${v.notRequested?'':`<button class="review-text-button" data-action="tab" data-tab="validation">View validation results ${icon('arrow')}</button>`}</aside></div>`;
}
function reviewStageReason(stage,model){
 if(stage.status==='running'&&state.task?.status==='paused')return 'Validation is paused. Select Resume to continue from this point.';
 if(stage.status==='running'&&state.task?.status==='pausing')return 'The current operation will finish before validation pauses.';
 const d=stage.detail;
 if(stage.reason)return uiMessage(stage.reason);
 if(stage.id==='source_prepare'&&d.operation==='source_preparation_until_candidate_install_receipt'){
  const current=d.steps?.at(-1),tests=(current?.declared_covers||[]).map(id=>reviewStageLabels[id]||id).join(', ');
  return (tests?`This container runs ${tests}. Each validation command prepares source in its own container. `:'')+'This duration includes container startup, source preparation and patch installation, ending when installation is confirmed. '+(d.status==='error'?'No valid installation receipt has arrived. Check the error details.':'');
 }
 if(stage.id==='source_prepare'&&d.scope)return uiMessage(d.scope);
 if(stage.id==='source_prepare'&&stage.status==='not_recorded')return 'Source preparation was not recorded separately. Other stages show their saved results.';
 const reasons={'Stage not executed':'This stage has not run.','Container did not attest candidate application':'The container did not provide an installation receipt for this patch.','exact_original_source_application':'Apply the patch strictly against the original source.'};
 if(d.reason)return reasons[d.reason]||uiMessage(d.reason);
 if(stage.status==='passed')return stage.id==='patch_apply'?'The patch was applied to the current source. Installation details are in the stage record.':'This stage passed its configured validation command.';
 if(stage.status==='running')return 'Execution is in progress. Results have not arrived yet.';
 if(stage.status==='queued')return 'Waiting to run.';
 if(stage.status==='not_run')return model.run?.error?'No execution record is available for this stage in the current validation run.':'This stage has not run.';
 return 'View command output and details for this stage.';
}
function reviewOutput(stage,{logs=true}={}){
 const d=stage.detail,stdout=reviewPlain(d.stdout||''),stderr=reviewPlain(d.stderr||''),command=d.command;
 const log=(title,body)=>body?`<div class="review-log-block"><strong>${title}</strong><pre tabindex="0">${esc(body)}</pre></div>`:'';
 let out='';
 if(logs&&(stdout||stderr))out+=`<details class="review-output" data-ui-key="review-output-${stage.id}"><summary>${icon('terminal')}Command output${stderr?' · includes stderr':''}</summary>${log('STDOUT',stdout)}${log('STDERR',stderr)}</details>`;
 if(command)out+=`<details class="review-output" data-ui-key="review-command-${stage.id}"><summary>Command</summary><pre tabindex="0">${esc(Array.isArray(command)?command.join('\n'):command)}</pre></details>`;
 const has=Object.keys(d).length;
 if(has)out+=`<details class="review-output review-native" data-ui-key="review-native-${stage.id}"><summary>Original stage record</summary><pre tabindex="0">${esc(JSON.stringify(d,null,2))}</pre></details>`;
 if(!out)out='<p class="review-hint">No command output, exit code or separate stage record is available.</p>';
 return out;
}
// Select the actual active boundary; shared commands can have several running stages.
function validationFocus(model){
 const running=model.stages.filter(s=>s.status==='running'),failure=model.stages.find(s=>['failed','error','cancelled','interrupted'].includes(s.status));
 return running[0]||failure||[...model.stages].reverse().find(s=>s.status==='passed')||model.stages[0];
}
function syncValidationWorkbench(){
 const list=document.querySelector('.validation-timeline ol'),selected=list?.querySelector('.validation-step.selected');
 if(!list||!selected||state.validationFollow===false||!active.includes(state.task?.status))return;
 if(list.dataset.following!==selected.dataset.stage){
  list.dataset.following=selected.dataset.stage;
  if(list.scrollWidth>list.clientWidth)list.scrollLeft=Math.max(0,list.scrollLeft+selected.getBoundingClientRect().left-list.getBoundingClientRect().left-(list.clientWidth-selected.offsetWidth)/2);
 }
}
function validationClock(model,stage=null){
 const p=model.progress||{},running=model.working&&(!stage||stage.status==='running');
 const start=stage?p.step_started_at:p.started_at;
 if(!running||!start)return stage?reviewDuration(stage.duration):'—';
 return runtimeElapsed({started_at:start,status:'running'},state.task);
}
function validationStageCaption(stage,model){
 if(state.task?.status==='paused'&&stage.status==='running')return 'Paused · resume to continue';
 if(state.task?.status==='pausing'&&stage.status==='running')return 'Finishing the current operation';
 if(stage.status==='running')return model.progress?.substep==='source_prepare'?'Preparing the test container':stage.id==='patch_apply'?'Installing patched source':'Waiting for command results';
 if(stage.status==='passed')return stage.id==='patch_apply'?'Patch applied':stage.shared?'Shared command passed':'Stage complete';
 if(['failed','error'].includes(stage.status))return 'Inspect the output';
 if(['cancelled','interrupted'].includes(stage.status))return 'Execution stopped';
 if(stage.status==='queued'||(model.working&&stage.status==='not_run'))return 'Waiting for previous steps';
 return stage.status==='not_recorded'?'No separate record':'Waiting to start';
}
function validationConsole(stage,model){
 const d=stage.detail,stdout=reviewPlain(d.stdout||''),stderr=reviewPlain(d.stderr||'');
 const block=(label,text)=>text?`<section class="validation-console-stream"><h4>${label}</h4><pre tabindex="0">${esc(text)}</pre></section>`:'';
 const prep=stage.id==='source_prepare'&&Array.isArray(d.steps)?d.steps:[];
 return `<section class="validation-console" aria-label="Stage execution output"><header>${icon('terminal')}<strong>Execution Output</strong><span>${stage.status==='running'?'Awaiting results':stdout||stderr?'Recorded':'Stage record'}</span></header><div class="validation-console-body" data-ui-key="validation-console-${stage.id}">${block('STDOUT',stdout)}${block('STDERR',stderr)}${!stdout&&!stderr?`<div class="validation-console-empty">${stage.status==='running'?'<span class="spinner"></span>':icon(stage.status==='passed'?'check':'clock')}<strong>${stage.status==='running'?'This stage is running':stage.status==='passed'?'This stage is complete':'No command output'}</strong><p>${stage.status==='running'?'Status and elapsed time update continuously. Command output appears after execution finishes and is saved.':stage.id==='patch_apply'&&stage.status==='passed'?'Patch application was recorded. Review the stage details below.':'No separate stdout / stderr was provided for this stage.'}</p></div>`:''}${prep.length?`<div class="validation-preparations">${prep.map((entry,i)=>`<div><span>${icon(entry.status==='passed'?'check':'clock')}<b>${esc(entry.step||'Test container '+(i+1))}</b></span><small>${esc(entry.status==='passed'?'Source installation confirmed':entry.status==='running'?'Preparing':'Incomplete')} · ${reviewDuration(entry.duration_seconds)}</small></div>`).join('')}</div>`:''}</div></section>`;
}
function validationReviewPanel(){
 if(reviewValidationMode()==='patch_only'){
  const m=resultValidationModel(null);
  return `<div class="validation-review validation-workbench"><header class="validation-overview"><div class="validation-overview-symbol">${icon('file')}</div><div class="validation-overview-copy"><span class="validation-eyebrow">PATCH GENERATION ONLY</span><h2>${esc(m.title)}</h2><p>${esc(m.summary)}</p></div></header></div>`;
 }
 const live=activeValidationCandidate(),c=live||currentCandidate();
 if(!c)return empty('Validation has not started','Once a patch is generated, start validation to follow each check.');
 const m=resultValidationModel(c),focus=validationFocus(m),follow=state.validationFollow!==false;
 const selected=follow?focus:m.stages.find(s=>s.id===state.validationStage)||focus;
 const running=m.stages.filter(s=>s.status==='running'),passed=m.stages.filter(s=>s.status==='passed').length;
 const suspended=m.working&&['paused','pausing'].includes(state.task.status);
 const title=suspended?(state.task.status==='paused'?'Validation paused':'Pausing validation'):m.working?(running.length?running.map(s=>s.label).join(' / '):'Preparing validation'):m.title;
 const stageNumber=m.stages.indexOf(selected)+1;
 const d=selected.operation?{...selected.detail,operation:selected.operation,step_name:selected.stepName}:selected.detail;
 const exit=d.exit_code===0||d.exit_code?String(d.exit_code):'—';
 const summary=suspended?(state.task.status==='paused'?'Select Resume to continue the validation workflow.':'Waiting for the current operation to finish before pausing.'):m.working?'The active step and stage results update as execution progresses.':m.summary;
 const terminal=icon(m.selectedPassed?'shield':m.error?'info':'activity');
 const history=c.validation_runs?.length?`<details class="review-validation-history" data-ui-key="review-validation-history"><summary>Validation history · ${c.validation_runs.length} runs</summary>${[...c.validation_runs].reverse().map(j=>`<div><span>${date(j.created_at)} · ${esc(String(j.id||'').slice(0,8))}</span>${status(j.status)}</div>`).join('')}</details>`:'';
 const records={...selected,detail:d};
 // Output is visible above; keep native metadata and commands available without duplicating it.
 const extra=Object.keys(d).length?reviewOutput(records,{logs:false}):'';
 return `<div class="validation-review validation-workbench"><header class="validation-overview ${m.tone}"><div class="validation-overview-symbol">${m.working?'<span class="spinner"></span>':terminal}</div><div class="validation-overview-copy"><span class="validation-eyebrow">PATCH VALIDATION</span><h2 aria-live="polite">${esc(title)}</h2><p>${esc(summary)}</p></div><div class="validation-overview-metrics">${m.working?`<div><span>Elapsed time</span><strong>${validationClock(m)}</strong></div>`:''}<div><span>Checks passed</span><strong>${m.passed}<small> / ${m.checkCount}</small></strong></div></div></header>${m.hint?`<p class="validation-hint">${icon('info')}${esc(m.hint)}</p>`:''}<div class="validation-progress-caption"><span>${suspended?esc(statuses[state.task.status][0]):m.working?'<i class="validation-live-dot"></i>Running':'Validation progress'}</span><span>${passed} / ${m.stages.length} steps passed</span></div><div class="validation-progress-track" aria-label="Validation step status">${m.stages.map(s=>`<span class="${s.status}" title="${esc(s.label)}"></span>`).join('')}</div><div class="validation-workspace"><aside class="validation-timeline" aria-label="Validation steps"><header><h3>Validation Workflow</h3><button class="button small validation-follow" data-action="validation-follow" aria-pressed="${follow}">${icon(follow?'activity':'play')}${follow?'Auto-follow':'Resume follow'}</button></header><ol>${m.stages.map((s,i)=>`<li class="${s.status}"><button data-action="validation-stage" data-stage="${s.id}" class="validation-step ${s===selected?'selected':''}" aria-pressed="${s===selected}" ${s.status==='running'?'aria-current="step"':''}><span class="validation-step-marker">${s.status==='passed'?icon('check'):s.status==='running'?'<span class="spinner"></span>':['failed','error','cancelled','interrupted'].includes(s.status)?icon('info'):String(i+1).padStart(2,'0')}</span><span class="validation-step-copy"><strong>${esc(s.label)}</strong><small>${esc(validationStageCaption(s,m))}</small><span class="validation-step-status">${reviewStatus(suspended&&s.status==='running'?state.task.status:m.working&&s.status==='not_run'?'queued':s.status)}<time>${s.status==='running'?validationClock(m,s):reviewDuration(s.duration)}</time></span></span></button></li>`).join('')}</ol></aside><section class="validation-stage-view" aria-label="Current stage details"><header class="validation-stage-title"><div><span class="validation-eyebrow">STEP ${String(stageNumber).padStart(2,'0')} / ${String(m.stages.length).padStart(2,'0')}</span><h3>${esc(selected.label)}</h3></div>${reviewStatus(suspended&&selected.status==='running'?state.task.status:selected.status)}</header>${selected.status==='running'?'<div class="validation-activity-line" aria-hidden="true"></div>':''}<p class="validation-stage-description">${esc(reviewStageReason(selected,m))}</p><dl class="validation-stage-facts"><div><dt>${selected.status==='running'?'Stage elapsed time':selected.shared?'Shared command duration':'Recorded duration'}</dt><dd>${validationClock(m,selected)}</dd></div><div><dt>Exit code</dt><dd>${esc(exit)}</dd></div><div><dt>Command identifier</dt><dd>${esc(d.step_name||d.operation||(selected.status==='running'?m.progress?.step:null)||'—')}</dd></div></dl>${selected.shared?`<p class="validation-shared">${icon('link')}Shares a command with ${esc(d.declared_covers.filter(s=>s!==selected.id).map(s=>reviewStageLabels[s]||s).join(' / '))} ; the duration covers the entire command.</p>`:running.length>1&&selected.status==='running'?`<p class="validation-shared">${icon('link')}${esc(running.map(s=>s.label).join(' / '))}  run through the same command and update together when it completes.</p>`:''}${validationConsole(selected,m)}<div class="validation-records">${extra}</div></section></div>${m.error?`<details class="review-run-error" open data-ui-key="review-run-error"><summary>${icon('info')}Validation error details</summary><pre tabindex="0">${esc(m.error)}</pre></details>`:''}${history}</div>`;
}
