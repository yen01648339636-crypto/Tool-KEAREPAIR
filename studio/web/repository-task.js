/* Repository-first task setup. Test inputs are saved with the requested scope. */
let repositoryTaskState=null;
const repositoryValidationPlans=[
 {id:'patch_only',title:'Generate patch',description:'Diagnose, retrieve examples and generate a patch.',icon:'file',result:'Patch + repair report'},
 {id:'poc',title:'Patch + PoC',description:'Build the repair and test the supplied vulnerability input.',icon:'bolt',result:'Patch + PoC results + report'},
 {id:'full',title:'Patch + full tests',description:'Run the PoC and the selected unit-test suite.',icon:'check',result:'Patch + all test results + report'},
];
function repositoryTaskIsCurrent(session){return state.modal==='repository-task'&&repositoryTaskState===session;}
function repositorySelectedTarget(session=repositoryTaskState){return session?.resolved?.targets?.find(item=>item.id===session.targetId)||null;}
function repositoryTaskIsDemo(session=repositoryTaskState){return Boolean(repositorySelectedTarget(session)?.demo_source_task_id);}
function repositoryTaskCanUseSaved(session=repositoryTaskState){return !repositoryTaskIsDemo(session)&&Boolean(repositorySelectedTarget(session)?.replay_source_id)&&session?.variant==='full'&&!repositoryTaskUsesUploads(session);}
function repositoryTaskNeedsTests(session=repositoryTaskState){return session?.validationMode!=='patch_only';}
function repositoryTaskUsesUploads(session=repositoryTaskState){return repositoryTaskNeedsTests(session)&&session?.testSource==='upload';}
function repositoryTaskValuesComplete(session=repositoryTaskState){
 if(!session?.resolved||!repositorySelectedTarget(session)||!session.file.trim()||!session.revision.trim())return false;
 if(!repositoryTaskNeedsTests(session))return true;
 if(repositoryTaskUsesUploads(session))return Boolean(session.uploads?.poc?.id&&!session.uploading?.poc&&(session.validationMode!=='full'||session.uploads?.unit?.id&&!session.uploading?.unit));
 return Boolean(session.poc.trim()&&(session.validationMode!=='full'||session.unit.trim()));
}
function repositoryTaskMessage(error){return typeof uiMessage==='function'?uiMessage(error?.message||String(error)):error?.message||String(error);}
function repositoryTaskField(label,id,value,help,placeholder=''){
 return `<div class="repo-field"><label for="${id}">${label}<span class="repo-required">Required</span></label><input id="${id}" value="${esc(value)}" placeholder="${esc(placeholder)}" autocomplete="off" spellcheck="false" required aria-describedby="${id}-help"><p id="${id}-help">${help}</p></div>`;
}
async function openRepositoryTask(caseKey=null){
 const previousUrl=caseKey&&state.task?.case_key===caseKey?state.task.repair_request?.repository_url||'':'';
 const session={url:previousUrl,resolved:null,targetId:'',file:'',revision:'',poc:'',unit:'',validationMode:'patch_only',variant:'full',mode:'live',testSource:'upload',uploads:{poc:null,unit:null},uploading:{poc:false,unit:false},uploadErrors:{poc:'',unit:''},uploadFiles:{poc:null,unit:null},uploadSerial:{poc:0,unit:0},resolving:false,submitting:false,error:'',request:0,advanced:false,preferredCaseKey:caseKey};
 repositoryTaskState=session;state.modal='repository-task';renderRepositoryTask();
 if(previousUrl&&session.url===previousUrl){await resolveRepositoryTask();return;}
 if(caseKey&&!session.url){
  try{
   const data=await api('/cases');if(!repositoryTaskIsCurrent(session)||session.url)return;
   const source=(data.items||[]).find(item=>item.key===caseKey);
   const url=source?.repository_url||(/^(?:(?:https?|git|ssh):\/\/|git@)/i.test(source?.project||'')?source.project:'');
   if(url){session.url=url;const input=document.querySelector('#repo-url');if(input)input.value=session.url;updateRepositoryTaskControls();await resolveRepositoryTask();}
  }catch{/* A new task remains available if an older case is no longer present. */}
 }
}
function repositoryTargetOptions(){
 const session=repositoryTaskState,targets=session.resolved?.targets||[];
 if(targets.length<2)return '';
 return `<div class="repo-target-selector"><div class="repo-section-caption">Choose a source baseline <span>${targets.length} available · selection required</span></div><div class="repo-target-list" role="group" aria-label="Source baselines">${targets.map(item=>`<button type="button" class="repo-target ${session.targetId===item.id?'selected':''}" data-action="repository-target" data-id="${esc(item.id)}" aria-pressed="${session.targetId===item.id}"><span class="repo-target-check">${session.targetId===item.id?icon('check'):''}</span><span class="repo-target-copy"><strong>${esc(item.file)}</strong><span>Revision <code>${esc(item.revision||'Not available')}</code></span>${item.target_label?`<span class="repo-target-hint">${esc(item.target_label)}</span>`:''}</span>${pill(item.language||'Source')}</button>`).join('')}</div></div>`;
}
function repositoryPlansHtml(){
 const session=repositoryTaskState,target=repositorySelectedTarget(),available=target?.validation_modes||['patch_only'];
 return `<fieldset class="repo-plan-fieldset"><legend>Repair scope</legend><p class="repo-section-note">Choose how far this task should run. The workflow continues automatically.</p><div class="repo-plans">${repositoryValidationPlans.map(plan=>{const allowed=available.includes(plan.id),selected=plan.id===session.validationMode;return `<label class="repo-plan ${selected?'selected':''} ${allowed?'':'unavailable'}"><input type="radio" name="repo-validation-mode" value="${plan.id}" ${selected?'checked':''} ${allowed?'':'disabled'}><span class="repo-plan-symbol">${icon(plan.icon)}</span><strong>${plan.title}</strong><span>${plan.description}</span><small>${allowed?plan.result:'Test inputs unavailable for this baseline'}</small></label>`;}).join('')}</div></fieldset>`;
}
function repositoryTestInputsHtml(){
 const session=repositoryTaskState;if(!repositoryTaskNeedsTests(session))return '';
 const upload=repositoryTaskUsesUploads();
 return `<section class="repo-test-inputs" aria-label="Required test inputs"><div class="repo-test-heading">${icon('check')}<div><h3>Test inputs</h3><p>${upload?(repositoryTaskIsDemo()?'Upload the PoC and unit-test inputs for this task.':'Upload your own checks. They will run against the patched source in a live task.'):'Use the matched target’s bundled test input. These references identify prepared files or suites; entering a path does not upload a file.'}</p></div></div><div class="repo-test-source segmented" role="group" aria-label="Test input source"><button type="button" data-action="repository-test-source" data-source="upload" class="${upload?'active':''}" aria-pressed="${upload}">Upload files</button><button type="button" data-action="repository-test-source" data-source="prepared" class="${!upload?'active':''}" aria-pressed="${!upload}">Use prepared tests</button></div><div class="repo-fields ${session.validationMode==='full'?'two-columns':''}">${upload?repositoryUploadHtml('poc')+(session.validationMode==='full'?repositoryUploadHtml('unit'):''):repositoryTaskField('PoC file or test entry','repo-poc',session.poc,'Required for PoC validation. Use the exact bundled reference for this source baseline.','Bundled PoC reference')+(session.validationMode==='full'?repositoryTaskField('Unit-test suite / entry','repo-unit',session.unit,'Required for full validation. Use the bundled unit-test file, directory or suite reference.','Bundled unit-test reference'):'')}</div>${upload&&!repositoryTaskIsDemo()?'<p class="repo-upload-note">Uploaded tests use Live run. Scripts run from the prepared source directory and pass when they exit with code 0.</p>':''}</section>`;
}
function repositoryUploadHtml(kind){
 const session=repositoryTaskState,file=session.uploads[kind],busy=session.uploading[kind],error=session.uploadErrors[kind],dataAllowed=kind==='poc'&&repositorySelectedTarget()?.uploaded_poc_data;
 const title=kind==='poc'?'PoC file':'Unit-test script',help=kind==='poc'?(dataAllowed?'Upload a .sh / .py script, or a data file for this target’s PoC runner.':'Upload a self-contained .sh or .py test script.'):'Upload a self-contained .sh or .py unit-test script.';
 return `<div class="repo-field repo-upload"><div class="repo-upload-label"><strong>${title}</strong><span class="repo-required">Required</span></div>${file?`<div class="repo-uploaded">${icon('check')}<div><strong>${esc(file.filename)}</strong><small>${repositoryUploadSize(file.size)} · uploaded</small></div><button type="button" class="icon-button" data-action="repository-upload-remove" data-kind="${kind}" aria-label="Remove ${title.toLowerCase()}">${icon('close')}</button></div>`:`<label class="repo-file-picker ${busy?'uploading':''}" for="repo-${kind}-upload"><input type="file" id="repo-${kind}-upload" ${dataAllowed?'':'accept=".sh,.py"'} ${busy?'disabled':''} aria-label="Upload ${title.toLowerCase()}" aria-required="true" aria-describedby="repo-${kind}-upload-help">${busy?'<span class="spinner"></span>':icon('file')}<span><strong>${busy?'Uploading…':'Choose file'}</strong><small>${busy?esc(session.uploadFiles[kind]?.name||''):dataAllowed?'Script or PoC input · up to 10 MiB':'.sh or .py · up to 10 MiB'}</small></span></label>`}<p id="repo-${kind}-upload-help">${help}</p>${error?`<div class="repo-upload-error" role="alert">${esc(error)}${session.uploadFiles[kind]?button('repository-upload-retry','Retry upload',null,'small',`data-kind="${kind}"`):''}</div>`:''}</div>`;
}
function repositoryUploadSize(bytes){return bytes>=1024*1024?(bytes/(1024*1024)).toFixed(1)+' MiB':Math.max(1,Math.ceil(bytes/1024))+' KiB';}
async function uploadRepositoryInput(kind,file){
 const session=repositoryTaskState;if(!repositoryTaskIsCurrent(session)||session.submitting||!['poc','unit'].includes(kind)||!file)return;
 const serial=++session.uploadSerial[kind];session.uploads[kind]=null;session.uploading[kind]=false;session.uploadErrors[kind]='';session.uploadFiles[kind]=file;session.error='';session.mode='live';
 const dataAllowed=kind==='poc'&&repositorySelectedTarget()?.uploaded_poc_data;
 if((!file.size&&(!dataAllowed||/\.(sh|py)$/i.test(file.name)))||file.size>10*1024*1024){session.uploadErrors[kind]='Choose a non-empty file up to 10 MiB.';session.uploadFiles[kind]=null;renderRepositoryTask();return;}
 if(!dataAllowed&&!/\.(sh|py)$/i.test(file.name)){session.uploadErrors[kind]='Choose a .sh or .py script for this test.';session.uploadFiles[kind]=null;renderRepositoryTask();return;}
 session.uploading[kind]=true;renderRepositoryTask();
 try{
  const bytes=new Uint8Array(await file.arrayBuffer()),parts=[];
  for(let i=0;i<bytes.length;i+=32768)parts.push(String.fromCharCode(...bytes.subarray(i,i+32768)));
  if(!repositoryTaskIsCurrent(session)||serial!==session.uploadSerial[kind])return;
  const result=await api('/test-inputs',{method:'POST',body:JSON.stringify({kind,filename:file.name,content_base64:btoa(parts.join(''))})});
  if(repositoryTaskIsCurrent(session)&&serial===session.uploadSerial[kind])session.uploads[kind]=result;
 }catch(error){if(repositoryTaskIsCurrent(session)&&serial===session.uploadSerial[kind])session.uploadErrors[kind]=repositoryTaskMessage(error);}
 finally{if(repositoryTaskIsCurrent(session)&&serial===session.uploadSerial[kind]){session.uploading[kind]=false;renderRepositoryTask();}}
}
function repositoryAdvancedHtml(){
 const session=repositoryTaskState,canSaved=repositoryTaskCanUseSaved();
 return `<details class="repo-advanced" ${session.advanced?'open':''}><summary>Execution settings<span>${session.mode==='replay'?'Saved run':'Live run'} · ${session.variant==='full'?'Full framework':esc(session.variant)}</span></summary><div class="repo-fields two-columns"><div class="repo-field"><label for="repo-execution-mode">Execution mode</label><select id="repo-execution-mode"><option value="live" ${session.mode==='live'?'selected':''}>Live run</option>${canSaved?`<option value="replay" ${session.mode==='replay'?'selected':''}>Saved run</option>`:''}</select><p>${session.mode==='replay'?'Use the matching recorded run’s artifacts and test results. No new model or test execution is performed.':'Run the configured repair engine and the selected checks.'}</p></div><div class="repo-field"><label for="repo-variant">Repair strategy</label><select id="repo-variant">${[['full','Full framework'],['df_only','Data-flow retrieval only'],['cf_only','Control-flow retrieval only'],['no_retrieval','Without knowledge retrieval'],['no_iteration','Single-round repair']].map(([value,label])=>`<option value="${value}" ${session.variant===value?'selected':''}>${label}</option>`).join('')}</select><p>Full framework uses diagnosis and both retrieval views.</p></div></div></details>`;
}
function renderRepositoryTask(focusId=null){
 const session=repositoryTaskState;if(!repositoryTaskIsCurrent(session))return;
 const configured=Boolean(session.resolved),plan=repositoryValidationPlans.find(item=>item.id===session.validationMode),step=configured?2:1;
 const previousScroll=document.querySelector('.modal-body')?.scrollTop||0;
 const body=`<div class="repository-task" aria-busy="${session.resolving||session.submitting}"><ol class="repo-steps" aria-label="Task setup"><li class="${configured?'complete':'current'}"><span>${configured?icon('check'):'1'}</span>Repository</li><li class="${configured?'current':''}"><span>2</span>Configure repair</li></ol>${configured?
 `<div class="repo-resolved"><div class="repo-resolved-icon">${icon('layers')}</div><div><strong>${esc(session.resolved.project||'Repository connected')}</strong><span>${esc(session.resolved.repository_url)}</span></div>${button('repository-change','Change',null,'small',session.submitting?'disabled':'')}</div>${repositoryTargetOptions()}<section class="repo-source-section"><div class="repo-section-heading"><h3>Source to repair</h3><span>Required details</span></div><div class="repo-fields">${repositoryTaskField('Vulnerable file','repo-file',session.file,'Path relative to the repository root. It must match the selected source baseline.','src/parser.c')}</div></section>${repositoryPlansHtml()}${repositoryTestInputsHtml()}${repositoryAdvancedHtml()}`:
 `<section class="repo-connect"><div class="repo-connect-icon">${icon('layers')}</div><h3>Start with your repository</h3><p>Enter a Git repository URL to find its prepared source baselines.</p><label for="repo-url">Git repository URL<span class="repo-required">Required</span></label><div class="repo-url-row"><input id="repo-url" type="text" inputmode="url" value="${esc(session.url)}" placeholder="https://github.com/owner/repository" autocomplete="url" spellcheck="false" required ${session.resolving?'disabled':''}>${button('repository-resolve',session.resolving?'Resolving…':'Continue',session.resolving?null:'arrow','primary',`id="repo-resolve" ${!session.url.trim()||session.resolving?'disabled':''}`)}</div></section>`}<div id="repo-task-error" class="repo-error" role="alert" ${session.error?'':'hidden'}>${esc(session.error)}</div></div>`;
 const footer=`<div class="repo-footer-summary"><span>STEP ${step} / 2</span><strong>${configured?plan.result:'Connect a repository'}</strong>${configured&&session.mode==='replay'?'<small>Saved run selected</small>':''}</div><div class="repo-footer-actions">${button('close-modal','Cancel',null,'',session.submitting?'disabled':'')}${configured?button('repository-start',session.submitting?'Creating…':'Start Repair','play','primary',`id="repo-start" ${!repositoryTaskValuesComplete()||session.submitting?'disabled':''}`):''}</div>`;
 openModal('New Repair Task',configured?'Choose the vulnerable source and the checks to include.':'Connect a repository, configure the repair, and follow every stage.',body,footer,true);
 document.querySelector('.modal')?.classList.add('repository-task-modal');
 if(configured){const scroll=document.querySelector('.modal-body');if(scroll)scroll.scrollTop=previousScroll;}
 if(focusId)requestAnimationFrame(()=>document.getElementById(focusId)?.focus({preventScroll:true}));
}
function updateRepositoryTaskControls(){
 const session=repositoryTaskState;if(!repositoryTaskIsCurrent(session))return;
 const resolve=document.querySelector('#repo-resolve');if(resolve)resolve.disabled=!session.url.trim()||session.resolving;
 const submit=document.querySelector('#repo-start');if(submit)submit.disabled=!repositoryTaskValuesComplete()||session.submitting;
 const error=document.querySelector('#repo-task-error');if(error){error.hidden=!session.error;error.textContent=session.error;}
}
function repositoryApplyTarget(id){
 const session=repositoryTaskState,target=session.resolved?.targets?.find(item=>item.id===id);if(!target)return;
 session.targetId=target.id;session.file=target.file||'';session.revision=target.revision||'';session.poc=target.poc_file||'';session.unit=target.unit_test||'';
 if(target.demo_source_task_id){session.validationMode='full';session.testSource='upload';session.variant='full';}
 if(!(target.validation_modes||['patch_only']).includes(session.validationMode))session.validationMode='patch_only';
 for(const kind of ['poc','unit']){session.uploadSerial[kind]++;session.uploads[kind]=null;session.uploading[kind]=false;session.uploadErrors[kind]='';session.uploadFiles[kind]=null;}
 session.mode=repositoryTaskCanUseSaved(session)?'replay':'live';session.error='';
}
async function resolveRepositoryTask(){
 const session=repositoryTaskState;if(!repositoryTaskIsCurrent(session)||session.resolving||!session.url.trim())return;
 const request=++session.request;session.resolving=true;session.error='';renderRepositoryTask();
 try{
  const result=await api('/repositories/resolve',{method:'POST',body:JSON.stringify({repository_url:session.url.trim()})});
  if(!repositoryTaskIsCurrent(session)||request!==session.request)return;
  if(!Array.isArray(result.targets)||!result.targets.length)throw new Error('No prepared source baselines are available for this repository. Choose an available repository to continue.');
  session.resolved=result;session.url=result.repository_url||session.url;
  session.targetId='';session.file='';session.revision='';session.poc='';session.unit='';session.mode='live';
  const preferred=result.targets.find(item=>session.preferredCaseKey&&item.case_key===session.preferredCaseKey)||(result.targets.length===1?result.targets[0]:null);
  if(preferred)repositoryApplyTarget(preferred.id);
 }catch(error){if(repositoryTaskIsCurrent(session)&&request===session.request)session.error=repositoryTaskMessage(error);}
 finally{if(repositoryTaskIsCurrent(session)&&request===session.request){session.resolving=false;renderRepositoryTask(session.resolved?'repo-file':'repo-url');}}
}
function repositoryTaskValidationError(){
 const session=repositoryTaskState,target=repositorySelectedTarget();
 if(!repositoryTaskValuesComplete())return 'Complete the required source and test input fields before starting.';
 if(session.file.trim()!==target.file)return 'The vulnerable file must match the selected source baseline. Select another baseline if you need a different file.';
 if(session.revision.trim()!==target.revision)return 'The revision must match the selected source baseline.';
 if(repositoryTaskNeedsTests()&&!repositoryTaskUsesUploads()&&session.poc.trim()!==target.poc_file)return 'The PoC reference must match this baseline’s bundled input. Choose Upload files to supply your own test.';
 if(session.validationMode==='full'&&!repositoryTaskUsesUploads()&&session.unit.trim()!==target.unit_test)return 'The unit-test reference must match this baseline’s bundled suite. Choose Upload files to supply your own test.';
 if(!(target.validation_modes||['patch_only']).includes(session.validationMode))return 'The selected checks are not available for this source baseline.';
 if(session.mode==='replay'&&!repositoryTaskCanUseSaved())return 'A matching saved run is not available. Select Live run to continue.';
 return '';
}
async function startRepositoryTask(){
 const session=repositoryTaskState;if(!repositoryTaskIsCurrent(session)||session.submitting)return;
 session.error=repositoryTaskValidationError();updateRepositoryTaskControls();
 if(session.error){document.querySelector('#repo-task-error')?.scrollIntoView({block:'nearest'});return;}
 session.submitting=true;renderRepositoryTask();
 const uploads=repositoryTaskUsesUploads(),body={repository_url:session.resolved.repository_url,target_id:session.targetId,vulnerable_file:session.file.trim(),revision:session.revision.trim(),validation_mode:session.validationMode,poc_file:repositoryTaskNeedsTests()&&!uploads?session.poc.trim():'',unit_test:session.validationMode==='full'&&!uploads?session.unit.trim():'',variant:session.variant,mode:uploads?'live':session.mode,automatic:true};
 if(uploads){body.poc_upload_id=session.uploads.poc.id;if(session.validationMode==='full')body.unit_upload_id=session.uploads.unit.id;}
 try{
  const task=await api('/tasks',{method:'POST',body:JSON.stringify(body)});
  if(!repositoryTaskIsCurrent(session)){toast('Repair task created. Open it in Task Center.');return;}
  closeModal();await openTask(task.id);toast(session.mode==='replay'?'Saved workflow started with your selected repair scope.':'Repair started. Follow its progress in Online Repair.');
 }catch(error){if(repositoryTaskIsCurrent(session)){session.error=repositoryTaskMessage(error);session.submitting=false;renderRepositoryTask();}else fail(error);}
}
async function repositoryTaskClick(target){
 const action=target?.dataset?.action;if(!action?.startsWith('repository-'))return false;
 const session=repositoryTaskState;if(!repositoryTaskIsCurrent(session)||session.submitting)return true;
 switch(action){
  case 'repository-resolve':await resolveRepositoryTask();break;
  case 'repository-change':session.request++;session.resolved=null;session.error='';renderRepositoryTask('repo-url');break;
  case 'repository-target':repositoryApplyTarget(target.dataset.id);renderRepositoryTask('repo-file');break;
  case 'repository-test-source':session.testSource=target.dataset.source==='prepared'?'prepared':'upload';if(repositoryTaskUsesUploads())session.mode='live';session.error='';renderRepositoryTask();break;
  case 'repository-upload-remove':{const kind=target.dataset.kind;if(['poc','unit'].includes(kind)){session.uploadSerial[kind]++;session.uploads[kind]=null;session.uploadFiles[kind]=null;session.uploading[kind]=false;session.uploadErrors[kind]='';renderRepositoryTask();}break;}
  case 'repository-upload-retry':{const kind=target.dataset.kind;if(['poc','unit'].includes(kind))await uploadRepositoryInput(kind,session.uploadFiles[kind]);break;}
  case 'repository-start':await startRepositoryTask();break;
 }
 return true;
}
function repositoryTaskInput(event){
 const session=repositoryTaskState;if(!repositoryTaskIsCurrent(session)||session.submitting)return false;
 const field={'repo-url':'url','repo-file':'file','repo-poc':'poc','repo-unit':'unit'}[event.target.id];
 if(!field)return false;
 session[field]=event.target.value;session.error='';updateRepositoryTaskControls();return true;
}
function repositoryTaskChange(event){
 const session=repositoryTaskState;if(!repositoryTaskIsCurrent(session)||session.submitting)return false;
 const uploadKind={'repo-poc-upload':'poc','repo-unit-upload':'unit'}[event.target.id];
 if(uploadKind){uploadRepositoryInput(uploadKind,event.target.files?.[0]);return true;}
 if(event.target.name==='repo-validation-mode'){
  const allowed=repositorySelectedTarget()?.validation_modes||['patch_only'];if(!allowed.includes(event.target.value))return true;
  session.validationMode=event.target.value;if(repositoryTaskUsesUploads())session.mode='live';session.error='';renderRepositoryTask();
  requestAnimationFrame(()=>document.querySelector(`input[name="repo-validation-mode"][value="${session.validationMode}"]`)?.focus({preventScroll:true}));return true;
 }
 if(event.target.id==='repo-execution-mode'){session.mode=event.target.value==='replay'&&repositoryTaskCanUseSaved()?'replay':'live';session.advanced=true;renderRepositoryTask('repo-execution-mode');return true;}
 if(event.target.id==='repo-variant'){session.variant=event.target.value;if(!repositoryTaskCanUseSaved())session.mode='live';session.advanced=true;renderRepositoryTask('repo-variant');return true;}
 return false;
}
function repositoryTaskKeydown(event){
 if(state.modal!=='repository-task'||event.key!=='Enter'||event.isComposing)return false;
 if(event.target.id==='repo-url'){event.preventDefault();resolveRepositoryTask();return true;}
 if(['repo-file','repo-poc','repo-unit'].includes(event.target.id)){event.preventDefault();startRepositoryTask();return true;}
 return false;
}
