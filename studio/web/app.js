
const paths = {
 grid:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
 layers:'<path d="m12 3 10 5-10 5L2 8zM2 12l10 5 10-5M2 16l10 5 10-5"/>',
 tasks:'<rect x="4" y="3" width="16" height="18" rx="2"/><path d="m8 8 1 1 2-2m-3 7 1 1 2-2m3-5h3m-3 6h3"/>',
 settings:'<path d="M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1M5.6 18.4l2.1-2.1m8.6-8.6 2.1-2.1"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="2"/>',
 arrow:'<path d="M5 12h14m-6-6 6 6-6 6"/>', chevron:'<path d="m9 5 7 7-7 7"/>', pause:'<path d="M8 5v14M16 5v14"/>', plus:'<path d="M12 5v14M5 12h14"/>',
 search:'<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
 help:'<circle cx="12" cy="12" r="9"/><path d="M9.2 9a3 3 0 1 1 4.4 2.6c-1 .5-1.6 1-1.6 2.4m0 3h.01"/>',
 moon:'<path d="M20 15.4A9 9 0 0 1 8.6 4a9 9 0 1 0 11.4 11.4Z"/>',
 sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5M17.5 17.5 19 19M5 19l1.5-1.5M17.5 6.5 19 5"/>',
 code:'<path d="m8 7-5 5 5 5m8-10 5 5-5 5m-3-14-2 18"/>',
 shield:'<path d="M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7z"/><path d="m8 12 3 3 5-6"/>',
 branch:'<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="7" r="2"/><path d="M6 7v10m0-4h5a7 7 0 0 0 7-4"/>',
 flow:'<rect x="2" y="9" width="5" height="6" rx="1"/><rect x="17" y="2" width="5" height="6" rx="1"/><rect x="17" y="16" width="5" height="6" rx="1"/><path d="M7 12h5V5h5m-5 7v7h5"/>',
 file:'<path d="M14 2H5v20h14V7zM14 2v6h5M8 12h8m-8 4h6"/>',
 clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',play:'<path d="m8 4 12 8-12 8z"/>',
 download:'<path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/>',activity:'<path d="M2 12h5l3-8 4 16 3-8h5"/>',
 terminal:'<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m6 8 4 4-4 4m7 0h5"/>',
 info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10h.01"/>',check:'<path d="m5 12 4 4L19 6"/>',
 close:'<path d="m6 6 12 12M6 18 18 6"/>',stop:'<rect x="6" y="6" width="12" height="12" rx="2"/>',
 trash:'<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7"/>',
 panelClose:'<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M9 3v18m7-13-4 4 4 4"/>',
 panelOpen:'<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M9 3v18m4-13 4 4-4 4"/>',
 bolt:'<path d="m13 2-9 12h7l-1 8 10-12h-7z"/>',link:'<path d="m10 13 4-4m-5 6-2 2a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0m4 10 4-4a4 4 0 0 0-6-6l-2 2"/>',
 lock:'<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V6a4 4 0 0 1 8 0v4m-4 4v3"/>',
 refresh:'<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 6a8 8 0 0 1 13 3M5 15a8 8 0 0 0 13 3"/>'
};
const icon=n=>`<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${paths[n]||paths.code}</svg>`;
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=n=>Number(n||0).toLocaleString('en-US');
const date=v=>v?new Date(v).toLocaleString('en-US',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}):'—';
const active=['queued','running','pausing','paused','cancelling'];
const statuses={pausing:['Pausing','amber'],paused:['Paused','amber'],patch_ready:['Patch ready','amber'],diagnosis_ready:['Diagnosis ready','teal'],retrieval_ready:['Examples ready','teal'],diagnosis_incomplete:['Review diagnosis','amber'],queued:['Queued','amber'],running:['Running','teal'],cancelling:['Stopping','amber'],cancelled:['Stopped',''],interrupted:['Interrupted','amber'],completed:['Completed','teal'],failed:['Failed','red'],example:['Walkthrough','amber']};
const validations={paused:['Paused','amber'],pausing:['Pausing','amber'],passed:['Passed','teal'],failed:['Failed','red'],error:['Error','red'],not_run:['Not run',''],running:['Running','teal'],queued:['Queued','amber']};
const pill=(s,c='')=>`<span class="pill ${c}">${esc(s)}</span>`;
const status=s=>pill(...(statuses[s]||[s,'']));
const validation=s=>pill(...(validations[s]||validations.not_run));
const button=(a,t,i,c='',extra='')=>`<button class="button ${c}" data-action="${a}" ${extra}>${i?icon(i):''}${t}</button>`;
const loading=()=>'<div class="loading"><span class="spinner"></span>Loading local records…</div>';
const empty=(t,d,a='')=>`<div class="empty">${icon('layers')}<h3>${esc(t)}</h3><p>${esc(d)}</p>${a}</div>`;
const state={page:'home',overview:null,task:null,tab:'diagnosis',evidence:1,line:9,candidate:1,validationStage:'compile',kb:null,kbQuery:'',kbLanguage:'',kbOffset:0,modal:null,caseItems:[],caseQuery:'',caseLanguage:'',selectedCase:'',variant:'full',record:null,recordView:'data_flow',related:[],error:null};
state.sidebarMode='auto';
let stream=null,streamTimer=null,toastTimer=null,searchTimer=null,previousFocus=null,searchSerial=0;
try{document.documentElement.dataset.theme=localStorage.getItem('kea-theme')||'dark';}catch{}
try{const mode=localStorage.getItem('kea-sidebar');if(['expanded','collapsed'].includes(mode))state.sidebarMode=mode;}catch{}
async function api(path,options={}){
 const response=await fetch('/api'+path,{headers:{'Content-Type':'application/json'},...options});
 const data=await response.json();
 if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail||data));
 return data;
}
function toast(message){const e=document.querySelector('#toast');e.textContent=uiMessage(message);e.classList.add('visible');clearTimeout(toastTimer);toastTimer=setTimeout(()=>e.classList.remove('visible'),4200);}
function fail(e){console.error(e);toast(e.message||'Request failed. Check the local service.');}
function download(url){const a=document.createElement('a');a.href=url;a.download='';document.body.append(a);a.click();a.remove();}
function logo(){return '<img src="/assets/brand-mark.svg?v=mark-1" width="40" height="40" alt="" aria-hidden="true" draggable="false">';}
function sidebarIsCollapsed(){return state.sidebarMode==='collapsed'||(state.sidebarMode!=='expanded'&&window.innerWidth<=1100);}
function shell(){
 const o=state.overview,k=o.knowledge,labels={home:'Task Center',workbench:'Online Repair',tasks:'Run History',knowledge:'Offline Knowledge Base',settings:'Environment & Settings'};
 const home=state.page==='home'||state.page==='tasks';
 const collapsed=sidebarIsCollapsed(),sidebarAction=collapsed?'Expand sidebar':'Collapse sidebar';
 return `<div class="shell ${collapsed?'sidebar-is-collapsed':'sidebar-is-expanded'}"><aside class="sidebar" id="studio-sidebar">
 <div class="sidebar-header"><a class="brand" href="#home" aria-label="KeaRepair Task Center"><div class="brand-logo">${logo()}</div><div class="brand-word">KeaRepair</div></a><button class="icon-button sidebar-toggle" data-action="toggle-sidebar" aria-label="${sidebarAction}" title="${sidebarAction}" aria-expanded="${!collapsed}" aria-controls="studio-sidebar">${icon(collapsed?'panelOpen':'panelClose')}</button></div><div class="nav-label">WORKSPACE</div>
 <nav aria-label="Main navigation">${[['knowledge','layers','Offline Knowledge Base'],['home','tasks','Task Center'],['workbench','grid','Online Repair'],['settings','settings','Environment & Settings']].map(([id,i,label])=>{const selected=id==='home'?home:state.page===id;return `<button class="nav-button ${selected?'active':''}" data-action="nav" data-page="${id}" title="${label}" aria-label="${label}" ${selected?'aria-current="page"':''}>${icon(i)}<span class="nav-text">${label}</span>${id==='home'?`<span class="nav-badge">${o.tasks.length}</span>`:''}</button>`;}).join('')}</nav>
 <div class="sidebar-bottom"><div class="engine-card"><div class="tiny-label">KNOWLEDGE ENGINE</div><div class="engine-title"><span class="dot ${k.ready?'':'warn'}"></span>${k.ready?'Dual-view knowledge loaded':'Knowledge setup required'}</div><p>${fmt(k.samples)} historical repair samples<br>Data flow × Control flow</p><div class="engine-spark" aria-hidden="true">${[8,13,9,19,12,22,15,17,10,21,16,11,18,22,14,19,10,17,21,13,8,16].map(h=>`<i style="height:${h}px"></i>`).join('')}</div></div><div class="workspace-user"><div class="avatar">KR</div><div><strong>KeaRepair</strong><p>Agentic Vulnerability Repair</p></div>${icon('lock')}</div></div></aside>
 <main class="main ${state.presentation&&state.page==='workbench'?'presentation-mode ':''}${state.page==='workbench'?'workbench-mode':home?'home-mode':''}"><header class="topbar"><div class="breadcrumb"><span>Workspace</span>${icon('chevron')}<strong>${labels[state.page]||labels.home}</strong>${state.page==='workbench'&&state.task?`<span class="breadcrumb-task">${icon('chevron')}${esc(taskDisplayName(state.task))}</span>`:''}</div><div class="topbar-actions"><span class="local-status"><span class="dot"></span>LOCAL CONNECTED</span><span class="divider"></span><button class="icon-button" data-action="theme" aria-label="Toggle light and dark theme" title="Toggle theme">${icon(document.documentElement.dataset.theme==='dark'?'sun':'moon')}</button><button class="icon-button" data-action="help" aria-label="Help" title="Help">${icon('help')}</button></div></header>
 <div class="content">${state.error?`<div class="error-banner">${esc(uiMessage(state.error))}</div>`:''}${({home:homePage,workbench,tasks:tasksPage,knowledge:knowledgePage,settings:settingsPage}[state.page]||homePage)()}${state.page==='workbench'?'':`<footer class="page-footer"><span>KEA REPAIR / EVIDENCE-CENTERED SECURITY</span><span>Understand. Repair. Verify.</span></footer>`}</div></main></div>`;
}
function render(){if(state.overview)updateApp(shell());}
function taskResumeLabel(t){
 if(t.mode==='replay'&&t.status==='completed')return 'View replay';
 if(active.includes(t.status))return 'View progress';
 if(t.status==='diagnosis_ready')return 'Review diagnosis';
 if(t.status==='retrieval_ready')return 'Review knowledge';
 if(t.status==='patch_ready')return 'Review & validate';
 if(t.validated)return 'View final patch';
 if(['failed','interrupted','cancelled','diagnosis_incomplete'].includes(t.status))return 'Review & resume';
 return 'View results';
}
function homePage(){return taskCenterPanel();}

function taskDisplayName(t){return t?.repair_request?.display_name||t?.title||t?.case_id||t?.case_key||'Repair task';}
function taskDisplayContext(t){return /CVE-\d{4}-\d+/i.test(taskDisplayName(t))?t.case_key||t.title:t.repair_request?.vulnerable_file||'Repository repair task';}
function applyTaskDisplay(root,t=state.task){
 const label=t?.repair_request?.display_name,identifier=t?.case_id||t?.case_key?.split(':').at(-1);
 if(!root||!label||!identifier)return;
 // Format visible text only. Action IDs, source records and exports keep the original identity.
 const replace=value=>String(value).replaceAll(identifier,label),walker=document.createTreeWalker(root,4);
 while(walker.nextNode())walker.currentNode.nodeValue=replace(walker.currentNode.nodeValue);
 for(const node of root.querySelectorAll('[title],[aria-label],[placeholder]')){
  for(const name of ['title','aria-label','placeholder'])if(node.hasAttribute(name))node.setAttribute(name,replace(node.getAttribute(name)));
 }
}

function taskPrimaryAction(t=state.task){
 if(state.presentation)return presentationAction();
 if(!t||t.mode==='walkthrough')return button('new','New Repair Task','plus','primary');
 if(t.status==='paused'||t.status==='pausing')return button('resume',t.status==='pausing'?'Continue Running':'Resume','play','primary');
 if(t.status==='queued'||t.status==='running')return button('pause','Pause','pause','primary');
 if(t.status==='cancelling')return button('running-state','Stopping','activity','primary','disabled');
 if(t.source_snapshot_stale)return button('new-aligned','New task with current source','plus','primary');
 if(t.status==='diagnosis_ready')return button('advance',t.variant==='no_retrieval'?'Generate Patch':'Retrieve Knowledge','arrow','primary',`data-stage="${t.variant==='no_retrieval'?'repair':'retrieval'}"`);
 if(t.status==='retrieval_ready')return button('advance','Generate Patch','arrow','primary','data-stage="repair"');
 if(t.status==='diagnosis_incomplete')return button('advance','Rerun Diagnosis','refresh','primary','data-stage="diagnosis"');
 const c=currentCandidate(),hasPatch=Boolean(c?.patch?.trim());
 if(c&&finalCandidate()===c)return button('patch-download','Download Final Patch','download','primary');
 if(['failed','interrupted','cancelled'].includes(t.status)&&['diagnosis','retrieval','repair'].includes(t.stage))return button('advance','Retry Current Stage','refresh','primary',`data-stage="${esc(t.stage)}"`);
 if(hasPatch&&t.repair_request?.validation_mode==='patch_only')return button('patch-download','Download Patch','download','primary');
 if(hasPatch)return button('validate-candidate',t.stage==='validation'||c.latest_validation?'Revalidate Patch':'Validate Patch','shield','primary',`data-candidate="${esc(c.candidate_id)}"`);
 return button('new','New Repair Task','plus','primary');
}
function taskActions(){
 const t=state.task,demo=t.mode==='walkthrough',c=currentCandidate();
 if(state.presentation)return `<details class="task-actions" data-ui-key="task-actions"><summary>More</summary><div class="task-actions-menu">${c?.patch?.trim()?button('patch-download','Download Patch','download','small'):''}${button('presentation-export','Export presentation snapshot','download','small')}${button('exit-presentation','Back to Online Repair','arrow','small')}</div></details>`;
 return `<details class="task-actions" data-ui-key="task-actions"><summary aria-label="More task actions">${icon('chevron')}<span>More</span></summary><div class="task-actions-menu">${replayButton(t)}${!demo&&!active.includes(t.status)?button('present-task','Present saved results','play','small',`data-id="${esc(t.id)}"`):''}${!demo?button('logs','Run Logs','terminal','small'):''}${!demo&&c?.patch?.trim()&&!active.includes(t.status)&&c.validation_result?.success===true?candidateValidationButton(c,'small'):''}${!demo&&c?.patch?.trim()&&c.validation_result?.success!==true?button('patch-download','Download current patch','download','small'):''}${button('export','Export results','download','small')}${demo?button('nav','Back to Task Center','tasks','small','data-page="home"'):''}${!demo&&active.includes(t.status)&&t.status!=='cancelling'?button('cancel','Stop Current Run','stop','small danger'):''}</div></details>`;
}
function workbench(){
 const t=state.task;
 if(!t&&state.loadingTask)return `<section class="workspace-panel focused-workspace" aria-busy="true">${loading()}</section>`;
 if(!t)return `<section class="workspace-panel focused-workspace">${empty('Select a repair task','Resume a task from the Task Center, or select a case to start a new repair.',button('nav','Open Task Center','tasks','secondary','data-page="home"')+button('new','New Repair Task','plus','primary'))}</section>`;
 const demo=t.mode==='walkthrough',events=t.events||[];
 return `<section class="workspace-panel focused-workspace ${t.status==='paused'?'is-paused':''}" aria-label="Online Repair"><div class="workspace-navigation"><div class="workspace-heading"><div class="workspace-identity"><div class="case-title"><h1>${esc(taskDisplayName(t))}</h1>${pill(t.language||'SOURCE')}${status(t.status)}</div><div class="case-sub"><span>${icon('file')}${esc(t.file||'Loading source')}</span><span class="mono">${demo?'Walkthrough':esc(t.id)}</span></div></div><div class="workspace-actions">${taskPrimaryAction()}${taskActions()}</div></div>${presentationBanner()}${t.automatic&&!state.presentation?workflowBanner():stageBanner()}</div>${workflowLivePanel()}<div class="workspace-stage-content" role="region" id="task-panel-${state.tab}" aria-label="${({diagnosis:'Vulnerability diagnosis',knowledge:'Repair knowledge',patch:'Generated patch',validation:'Patch validation',report:'Repair report'}[state.tab]||'Repair details')}" tabindex="0">${t.error?`<details class="workspace-failure" data-ui-key="task-error"><summary>${icon('info')}Run error · view details</summary><pre>${esc(uiMessage(t.error))}</pre></details>`:''}${({diagnosis:diagnosisPanel,knowledge:knowledgePanel,patch:patchPanel,validation:validationPanel,report:repairReportPanel}[state.tab])()}</div><footer class="workspace-activity"><details class="activity-details" data-ui-key="task-activity"><summary>All events${events.length?' · '+events.length:''}</summary><div class="activity-items">${events.slice(-30).map(e=>`<div class="activity-event"><time>${date(e.at)}</time><span>${esc(uiMessage(e.message))}</span></div>`).join('')||'<span class="muted-note">No execution events yet.</span>'}${events.length>30?'<p class="muted-note">Showing the latest 30 events. Open the run logs or export the results for the full record.</p>':''}</div></details></footer></section>`;
}
function highlight(line){
 const pattern=/(#[^\n]*|\/\/[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\b(?:from|import|as|def|return|if|else|elif|raise|try|except|class|with|for|in|not|and|or|while|const|let|function|var|async|await|package|func|nil|None|True|False|int|char|void|static|unsigned|sizeof)\b|\b\d+(?:\.\d+)?\b|\b[A-Za-z_]\w*(?=\())/g;
 let last=0,result='';
 for(const match of line.matchAll(pattern)){
  result+=esc(line.slice(last,match.index));const v=match[0];
  const type=v.startsWith('#')||v.startsWith('//')?'comment':/^["']/.test(v)?'string':/^\d/.test(v)?'number':line[match.index+v.length]==='('?'call':'keyword';
  result+=`<span class="tok-${type}">${esc(v)}</span>`;last=match.index+v.length;
 }
 return result+esc(line.slice(last));
}
let sourceHighlightCache={source:null,lines:[]};
function codeView(source,line=0){
 const text=String(source||'');
 if(sourceHighlightCache.source!==text)sourceHighlightCache={source:text,lines:text.split('\n').map(s=>highlight(s)||' ')};
 return `<div class="code-box ${state.sourceWrap!==false?'wrap-lines':''}" id="source-view" tabindex="0" aria-label="Full source; select a line number to inspect it">${sourceHighlightCache.lines.map((s,i)=>`<div class="code-line ${line===i+1?'active':''} ${state.task?.mode==='walkthrough'&&i===9?'danger-line':''}" data-line="${i+1}"><button class="line-number" data-action="line" data-line="${i+1}" title="Select line ${i+1}">${i+1}</button><span class="line-code">${s}</span></div>`).join('')}</div>`;
}
function visibleFacts(){return state.task?.facts||[];}
function diagnosisPanel(){return diagnosisReviewPanel();}

function fields(view){
 if(!view)return '<p class="muted-note">No knowledge was recorded for this view.</p>';
 return [['root_cause','Root Cause'],['risky_calls','Related Calls'],['fixing_strategy','Repair Strategy'],[view.taint_flow?'taint_flow':'control_branch',view.taint_flow?'Data Flow':'Control Flow']].map(([key,label])=>`<div class="knowledge-field"><strong>${label}</strong>${Array.isArray(view[key])?`<div class="tag-list">${view[key].map(v=>pill(v)).join('')}</div>`:`<p>${esc(view[key]||'Not recorded')}</p>`}</div>`).join('');
}
function exemplarSummary(item){const p=item.views?.data_flow||item.views?.control_flow||{};return p.abstracted_knowledge||p;}
function knowledgePanel(){
 if(state.task.mode!=='walkthrough')return retrievalPanel();
 const t=state.task,demo=t.mode==='walkthrough',related=demo?state.related:t.exemplars||[];
 return `<div class="split-content"><div class="knowledge-pane"><div class="label">CURRENT CONTEXT</div><h3>Repair context for this vulnerability</h3><p class="reading-copy">${esc(t.description)}</p><div class="knowledge-field"><strong>Diagnosis Summary</strong><p>${esc(reportConclusion(t.diagnosis_report)||t.description||'No diagnosis summary has been recorded yet.')}</p></div>${[["data_flow","Data-flow retrieval query"],["control_flow","Control-flow retrieval query"]].map(([v,l])=>{const q=t.retrieval?.queries?.[v];return `<div class="knowledge-field"><strong>${l}</strong><p>${esc(typeof q==='string'?q:q?.root_cause||"Generated from the diagnosis report during retrieval")}</p></div>`;}).join("")}</div>
 <div class="knowledge-pane"><div class="section-head"><div class="label">${demo?'HISTORICAL REFERENCES':'RETRIEVED EXEMPLARS'}</div>${pill(demo?'Related reading':'Retrieval Results',demo?'':'teal')}</div><h3>Evidence from historical repairs</h3><div class="related-list">${related.length?related.slice(0,4).map((r,i)=>`<button class="related-card" data-action="${demo?'record':'exemplar'}" ${demo?`data-id="${esc(r.sample_id)}"`:`data-index="${i}"`}><div class="section-head"><strong>${esc(r.cve_id||r.sample_id?.slice(0,20)||'EXEMPLAR '+(i+1))}</strong>${pill(r.language||'KNOWLEDGE')}</div><p>${esc(r.cve_description||exemplarSummary(r).root_cause||'View knowledge and code pairs')}</p></button>`).join(''):empty('No knowledge records',demo?'No path-related samples were found in the knowledge base.':'Historical repair examples will appear after retrieval.')}</div></div></div>`;
}
function finalCandidate(){
 if(state.task?.mode==='walkthrough')return;
 const task=state.task,mode=task?.repair_request?.validation_mode||'full';
 return [...(task?.candidates||[])].reverse().find(c=>c.patch?.trim()&&(mode==='patch_only'?task.status==='completed':mode==='poc'?task.status==='completed'&&resultValidationModel(c).selectedPassed:c.validation_result?.success===true||c.original_validation_result?.success===true));
}
function currentCandidate(){if(state.task?.mode==='walkthrough')return state.task.candidates?.[state.candidate]||state.task.candidates?.[0];return finalCandidate()||[...(state.task?.candidates||[])].reverse().find(c=>c.patch?.trim())||state.task?.candidates?.at(-1);}
function candidateTitle(c){return c===finalCandidate()?'Final Patch':state.task?.status==='patch_ready'?'Patch ready':'Current Patch';}
function candidateBar(){
 const final=finalCandidate();
 if(!final&&state.task?.mode!=='walkthrough'){const c=currentCandidate();return c?.patch?.trim()?`<div class="candidate-bar"><div class="file-tab">${icon('code')}<strong>${candidateTitle(c)}</strong></div>${state.task.status==='patch_ready'?pill('Ready · awaiting validation','amber'):''}</div>`:'';}
 if(final)return `<div class="candidate-bar"><div class="file-tab">${icon('code')}<strong>Final Patch</strong></div>${state.task.repair_request?.validation_mode==='patch_only'?pill('Generated · validation not requested'):state.task.repair_request?.validation_mode==='poc'?pill('PoC checks passed','teal'):final.validation_result?.success?pill(state.task.mode==='replay'?'Historical validation passed':'All checks passed','teal'):''}</div>`;
 return `<div class="candidate-bar"><div class="candidate-tabs">${(state.task.candidates||[]).map((c,i)=>`<button class="candidate-tab ${currentCandidate()===c?'active':''}" data-action="candidate" data-index="${i}">${state.task.mode==='walkthrough'?'Example patch':'Candidate patch'} ${esc(c.candidate_id||i+1)}</button>`).join('')}</div>${pill(state.task.mode==='walkthrough'?'Manually written example patches':'Original generation records retained',state.task.mode==='walkthrough'?'amber':'')}</div>`;
}
function diffView(patch){
 if(!patch)return empty('No patch content yet','Wait for generation to finish or inspect the run logs for errors.');
 return `<div class="diff-view" tabindex="0" aria-label="Unified patch diff">${patch.split('\n').map(line=>{const type=/^---|^\+\+\+|^diff /.test(line)?'meta':line.startsWith('+')?'add':line.startsWith('-')?'remove':line.startsWith('@@')?'hunk':'';return `<div class="diff-line ${type}">${esc(line)||' '}</div>`;}).join('')}</div>`;
}
function patchPanel(){return patchReviewPanel();}

function candidateValidationButton(c,style='primary'){
 if(state.task.repair_request?.validation_mode==='patch_only')return '';
 const run=c.latest_validation,busy=active.includes(state.task.status),hasPatch=typeof c.patch==='string'&&c.patch.trim().length>0;
 const label=busy&&state.task.automatic?'Automatic validation':run&&active.includes(run.status)?'Validating…':run?'Revalidate Current Patch':'Validate Patch';
 return button('validate-candidate',label,'shield',style,`data-candidate="${esc(c.candidate_id)}" title="Validate ${esc(candidateTitle(c))}" ${busy||!hasPatch||state.task.source_snapshot_stale?'disabled':''}`);
}
function validationPanel(){return validationReviewPanel();}

function tasksPage(){return taskHistoryPanel();}

function knowledgePage(){
 return `${knowledgeBuildPanel()}<div class="filters"><label class="search-field">${icon('search')}<input id="kb-search" type="search" placeholder="Search CVE, project or vulnerability keyword…" value="${esc(state.kbQuery)}" aria-label="Search knowledge base"></label><select id="kb-language" aria-label="Filter knowledge by language"><option value="">All languages</option>${Object.keys(state.overview.knowledge.languages).map(l=>`<option ${state.kbLanguage===l?'selected':''}>${esc(l)}</option>`).join('')}</select><span class="filter-note">KEYWORD SEARCH</span></div><div id="kb-results">${state.kb?knowledgeResults():loading()}</div>`;
}
function knowledgeResults(){
 const k=state.kb;if(!k?.items.length)return empty('No matching knowledge records','Try a CVE ID, project name or vulnerability keyword.');
 return `<div class="knowledge-grid">${k.items.map(r=>`<button class="kb-card" data-action="record" data-id="${esc(r.sample_id)}"><div class="kb-card-head">${icon('layers')}${pill(r.language)}</div><h3>${esc(r.cve_id||'Historical sample')}</h3><div class="kb-project">${esc(r.project.replace(/^https:\/\/github.com\//,''))}</div><p class="kb-description">${esc(r.views.data_flow?.root_cause||r.views.control_flow?.root_cause||r.cve_description)}</p><div class="kb-card-footer">${pill('Data flow','teal')}${pill('Control flow','purple')}${icon('arrow')}</div></button>`).join('')}</div><div class="pagination">${button('kb-prev','Previous',null,'small',state.kbOffset===0?'disabled':'')}<span>${state.kbOffset+1}–${Math.min(state.kbOffset+12,k.total)} / ${fmt(k.total)}</span>${button('kb-next','Next',null,'small',state.kbOffset+12>=k.total?'disabled':'')}</div>`;
}
function settingsPage(){
 const o=state.overview,c=o.config,k=o.knowledge;
 const rows=items=>items.map(([a,b])=>`<div class="setting-row"><span>${a}</span><strong>${esc(b)}</strong></div>`).join('');
 return `<div class="page-actions" role="toolbar" aria-label="Environment actions">${button('refresh','Recheck','refresh')}</div><div class="settings-grid">
 <section class="settings-card"><h3>${icon('bolt')}Online Repair Engine</h3>${rows([['Configuration',c.config_file||'Not loaded'],['Provider',c.provider||'—'],['Model',c.model||'—'],['API key',c.key_configured?'Configured (connection not tested)':'Not configured'],['Max repair rounds',c.max_iterations||'—'],['Validation mode',c.execution_mode||'—']])}<p>After editing config/online.yaml or the project .env, select Recheck. The first live run may need to load or download models.</p></section>
 <section class="settings-card"><h3>${icon('layers')}Local Knowledge Assets</h3>${rows([['Directory',k.path],['Samples',fmt(k.samples)],['View entries',fmt(k.vectors)],['Languages',Object.keys(k.languages).join(' / ')],['Read status',k.ready?'Available':'Unavailable']])}<p>Extend the knowledge base with verified source and patch pairs. Each successful build publishes a new index generation and retains previous records.</p></section>
 <section class="settings-card"><h3>${icon('shield')}Preflight Checks</h3><div class="status-list">${o.preflight_issues.length?o.preflight_issues.map(s=>`<div class="status-row">${icon('info')}<span>${esc(uiMessage(s))}</span></div>`).join(''):`<div class="status-row good">${icon('check')}Static configuration checks passed</div>`}<div class="status-row">${icon('info')}Docker, images and model connectivity are checked during live execution.</div></div><p>KeaRepair runs locally for a single user. Live tasks call the configured model and validate patches in case-specific containers.</p></section>
 <section class="settings-card"><h3>${icon('grid')}Workspace Preferences</h3><div class="setting-row"><span>Theme</span>${button('theme',document.documentElement.dataset.theme==='dark'?'Switch to light':'Switch to dark','moon','small')}</div><div class="setting-row"><span>Keyboard shortcut</span><strong><kbd>Ctrl</kbd> + <kbd>K</kbd> Find a case</strong></div><div class="setting-row"><span>Platform version</span><strong class="mono">0.1.0 · INITIAL RELEASE</strong></div><p>The walkthrough uses a synthetic case and runs structural analysis without model API calls. Start a real case for the full repair workflow.</p></section></div>`;
}

