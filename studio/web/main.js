// Keep task review context independent from live execution updates.
const reviewTabs=['diagnosis','knowledge','patch','validation','report'];
const appPages=['home','workbench','tasks','knowledge','settings'];
const readingCache=new Map();
const reviewDefaults={diagnosisView:'facts',factQuery:'',factTool:'',sourceWrap:true,sourceTouched:false,validationFollow:true,diffMode:'unified',diffContext:false,retrievalSample:null,retrievalView:'data_flow'};
const reviewSelectionKeys=['line','evidence','candidate','validationStage',...Object.keys(reviewDefaults)];
Object.assign(state,reviewDefaults,{presentation:false,presentationCapturedAt:null,caseOffset:0});
let retrievalReturnFocus=null;
let renderedView=null,renderedSelection=null,routeSerial=0,readingTimer=null;
function viewKey(){return state.page==='workbench'?`task:${state.task?.id||'loading'}:${state.tab}${state.presentation?':presentation':''}`:`page:${state.page}`;}
function readingKey(key){return 'kea-reading-v2:'+key;}
function readContext(key){
 if(!readingCache.has(key)){try{readingCache.set(key,JSON.parse(sessionStorage.getItem(readingKey(key)))||{});}catch{readingCache.set(key,{});}}
 return readingCache.get(key);
}
function nodeKey(node){
 if(node.nodeType!==1)return null;
 if(node.id)return 'id:'+node.id;
 if(node.dataset.uiKey)return 'ui:'+node.dataset.uiKey;
 if(node.classList.contains('code-line'))return 'line:'+node.dataset.line;
 if(node.dataset.action)return 'action:'+node.dataset.action+':'+['page','tab','index','line','id','key','stage','candidate','sample','view','mode','target','filter','offset','caseKey','rank'].map(k=>node.dataset[k]||'').join(':');
 return null;
}
function domPath(node,root){
 const path=[];for(let n=node;n&&n!==root;n=n.parentElement){const key=nodeKey(n);path.unshift(key||n.tagName+':'+Array.prototype.indexOf.call(n.parentNode.children,n));}
 return path.join('/');
}
function captureReading(key=renderedView){
 const root=document.querySelector('#app');if(!key||!root?.firstElementChild)return;
 const scrolls={},details={};
 root.querySelectorAll('*').forEach(n=>{const path=domPath(n,root);if(n.scrollTop||n.scrollLeft)scrolls[path]=[n.scrollLeft,n.scrollTop];if(n.tagName==='DETAILS')details[path]=n.open;});
 const focused=root.contains(document.activeElement)?domPath(document.activeElement,root):null;
 const value={selection:renderedSelection,scrolls,details,focused,y:window.scrollY,x:window.scrollX};
 readingCache.set(key,value);try{sessionStorage.setItem(readingKey(key),JSON.stringify(value));if(key.startsWith('task:')&&!key.includes(':loading:')){const parts=key.split(':');sessionStorage.setItem('kea-last-review:'+parts[1],parts[2]);}}catch{}
}
function restoreSelection(){
 const selection=readContext(viewKey()).selection;
 if(selection)for(const key of reviewSelectionKeys)if(selection[key]!==undefined)state[key]=selection[key];
 state.line=Math.max(1,Math.min(Number(state.line)||1,diagnosisSourceLines().length));
 if(state.line<=1&&!state.sourceTouched)state.line=diagnosisInitialLine(state.task);
 if(!['facts','tools'].includes(state.diagnosisView))state.diagnosisView='facts';
 state.evidence=Math.max(0,Math.min(Number(state.evidence)||0,(state.task?.facts?.length||1)-1));
 state.candidate=Math.max(0,Math.min(Number(state.candidate)||0,(state.task?.candidates?.length||1)-1));
 if(!['source_prepare','patch_apply','compile','poc','unit'].includes(state.validationStage))state.validationStage='compile';
 if(state.tab==='validation'&&!selection&&currentCandidate()){const model=resultValidationModel(currentCandidate()),step=model.stages.find(s=>['failed','error','running'].includes(s.status));if(step)state.validationStage=step.id;}
 // A successful final patch always takes priority over historical candidate selection.
 if(state.task?.mode!=='walkthrough'&&finalCandidate())selectSavedCandidate();
}
function restoreReading(context,restoreFocus=true){
 const root=document.querySelector('#app'),nodes=new Map([...root.querySelectorAll('*')].map(n=>[domPath(n,root),n]));
 for(const [path,open] of Object.entries(context.details||{})){const n=nodes.get(path);if(n)n.open=open;}
 for(const [path,[x,y]] of Object.entries(context.scrolls||{})){const n=nodes.get(path);if(n){n.scrollLeft=x;n.scrollTop=y;}}
 if(restoreFocus&&context.focused)nodes.get(context.focused)?.focus({preventScroll:true});
 window.scrollTo({left:context.x||0,top:context.y||0,behavior:'instant'});
}
function morphNode(oldNode,newNode){
 if(oldNode.nodeType!==newNode.nodeType||oldNode.nodeName!==newNode.nodeName){oldNode.replaceWith(newNode.cloneNode(true));return;}
 if(oldNode.nodeType!==1){if(oldNode.nodeValue!==newNode.nodeValue)oldNode.nodeValue=newNode.nodeValue;return;}
 if(oldNode.isEqualNode(newNode))return;
 // Native details state and input drafts belong to the reader, not a status refresh.
 for(const a of [...oldNode.attributes])if(!newNode.hasAttribute(a.name)&&!(oldNode.tagName==='DETAILS'&&a.name==='open'))oldNode.removeAttribute(a.name);
 for(const a of newNode.attributes)if(!(oldNode.tagName==='DETAILS'&&a.name==='open')&&oldNode.getAttribute(a.name)!==a.value)oldNode.setAttribute(a.name,a.value);
 if(oldNode.tagName==='INPUT'||oldNode.tagName==='TEXTAREA')return;
 const keyed=new Map([...oldNode.childNodes].map(n=>[nodeKey(n),n]).filter(([k])=>k));
 let cursor=oldNode.firstChild;
 for(const incoming of [...newNode.childNodes]){
  const key=nodeKey(incoming);let match=key?keyed.get(key):cursor;
  if(!key&&match&&(nodeKey(match)||match.nodeName!==incoming.nodeName))match=null;
  if(match){if(match!==cursor)oldNode.insertBefore(match,cursor);morphNode(match,incoming);cursor=match.nextSibling;}
  else{const added=incoming.cloneNode(true);oldNode.insertBefore(added,cursor);cursor=added.nextSibling;}
 }
 while(cursor){const next=cursor.nextSibling;cursor.remove();cursor=next;}
}
function updateApp(markup){
 const root=document.querySelector('#app'),key=viewKey(),same=renderedView===key;
 const workflowEvents=same?captureWorkflowEvents():null;
 if(renderedView)captureReading();
 const context=readContext(key),template=document.createElement('template');template.innerHTML=markup;
 if(state.page==='workbench')applyTaskDisplay(template.content);
 if(same&&root.firstElementChild)morphNode(root.firstElementChild,template.content.firstElementChild);
 else root.replaceChildren(template.content);
 renderedView=key;renderedSelection=Object.fromEntries(reviewSelectionKeys.map(k=>[k,state[k]]));
 restoreReading(context,same||Boolean(context.focused));syncRetrievalDrawer();syncValidationWorkbench();animateWorkflowEvents(workflowEvents);
 if(state.tab==='diagnosis'&&document.querySelector('#source-view')&&!state.sourceAutoLocated&&!state.sourceTouched&&(state.task?.diagnosis_report?.summary||(!active.includes(state.task?.status)&&visibleFacts().length))){scrollSourceLine();state.sourceAutoLocated=true;}
}
function syncRetrievalDrawer(){const nav=document.querySelector('.workspace-navigation');if(nav)document.documentElement.style.setProperty('--workspace-navigation-height',nav.offsetHeight+'px');const drawer=state.page==='workbench'&&state.tab==='knowledge'?document.querySelector('.retrieval-drawer'):null,mobile=Boolean(drawer&&innerWidth<=1200);document.body.classList.toggle('retrieval-sheet-open',mobile);if(drawer){drawer.setAttribute('role',mobile?'dialog':'complementary');if(mobile)drawer.setAttribute('aria-modal','true');else drawer.removeAttribute('aria-modal');}}
window.addEventListener('resize',syncRetrievalDrawer);
window.matchMedia('(max-width:1100px)').addEventListener('change',()=>{if(state.sidebarMode==='auto')render();});
document.addEventListener('transitionend',event=>{if(event.target.matches('.sidebar')&&event.propertyName==='width')syncRetrievalDrawer();});
function writeRoute(mode='push'){
 const url=new URL(location.href);url.hash=state.page;
 if(state.page==='workbench'&&state.task){url.searchParams.set('task',state.task.id);url.searchParams.set('tab',state.tab);if(state.presentation)url.searchParams.set('presentation','1');else url.searchParams.delete('presentation');}
 else{url.searchParams.delete('task');url.searchParams.delete('tab');url.searchParams.delete('presentation');}
 if(url.href!==location.href)history[mode==='replace'?'replaceState':'pushState']({kea:true},'',url);
}
function setTaskTab(tab,{route=true,follow=false}={}){
 if(!reviewTabs.includes(tab))return;
 captureReading();state.workflowFollow=follow;state.tab=tab;restoreSelection();render();
 if(route)writeRoute();
}
async function navigate(page,{route=true}={}){
 if(!appPages.includes(page))return;
 if(page==='workbench'&&!state.task){
  let id;try{id=localStorage.getItem('kea-task');}catch{}
  if(id)return openTask(id,{historyMode:route?'push':'none'});
 }
 captureReading();++routeSerial;state.page=page;state.error=null;render();if(route)writeRoute();
 if(page==='knowledge'&&!state.kb)await loadKnowledge();
 if(page==='knowledge')await refreshKnowledgeBuilds();
 if(['home','tasks','settings'].includes(page)){state.overview=await api('/overview');if(state.page===page)render();}
}
async function loadKnowledge(){
 const serial=++searchSerial,target=document.querySelector('#kb-results');if(target)target.innerHTML=loading();
 try{const data=await api('/knowledge?'+new URLSearchParams({q:state.kbQuery,language:state.kbLanguage,offset:state.kbOffset,limit:12}));if(serial!==searchSerial)return;state.kb=data;const results=document.querySelector('#kb-results');if(results)results.innerHTML=knowledgeResults();}
 catch(e){if(target?.isConnected)target.innerHTML=empty('Could not load the knowledge base',e.message);fail(e);}
}
async function openTask(id,{tab=null,historyMode='push',presentation=false}={}){
 const serial=++routeSerial;captureReading();stream?.close();stream=null;clearTimeout(streamTimer);
 state.task=null;state.presentation=presentation;state.loadingTask=true;state.error=null;state.page='workbench';state.tab=tab||'diagnosis';render();
 try{
  const [overview,task]=await Promise.all([api('/overview'),api(id==='walkthrough'?'/walkthrough':'/tasks/'+encodeURIComponent(id))]);
  if(serial!==routeSerial)return;
  state.overview=overview;state.loadingTask=false;state.presentation=presentation&&!active.includes(task.status);state.presentationCapturedAt=state.presentation?new Date().toISOString():null;state.task=state.presentation?structuredClone(task):task;state.workflowFollow=Boolean(task.automatic&&active.includes(task.status));state.workflowConnection='connecting';Object.assign(state,reviewDefaults);state.sourceAutoLocated=false;state.candidate=id==='walkthrough'?1:0;state.evidence=id==='walkthrough'?1:0;state.line=id==='walkthrough'?9:diagnosisInitialLine(task);
  selectSavedCandidate();let previousTab;try{previousTab=sessionStorage.getItem('kea-last-review:'+id);}catch{}state.tab=reviewTabs.includes(tab)?tab:state.presentation?presentationTabs()[0]:task.automatic?savedTaskTab():reviewTabs.includes(previousTab)?previousTab:savedTaskTab();restoreSelection();state.error=null;render();
  if(state.tab==='diagnosis'&&!readContext(viewKey()).selection){scrollSourceLine();captureReading();}
  try{localStorage.setItem('kea-task',id);}catch{}
  if(historyMode!=='none')writeRoute(historyMode);
  if(id!=='walkthrough'&&!state.presentation&&active.includes(task.status))subscribe(id);
  if(id==='walkthrough'&&!state.related.length)api('/knowledge?q=path&language=Python&limit=4').then(d=>{state.related=d.items;if(state.page==='workbench'&&state.task?.id===id&&state.tab==='knowledge')render();}).catch(()=>{});
 }catch(e){if(serial===routeSerial){state.loadingTask=false;state.error='Could not load task: '+e.message;render();}return false;}
}
function selectSavedCandidate(){
 if(state.task?.mode==='walkthrough')return;
 const candidates=state.task?.candidates||[],recent=state.task?.validation_runs?.at(-1)?.candidate_id;
 const final=finalCandidate();if(final){state.candidate=candidates.indexOf(final);return;}
 const selected=candidates.findIndex(c=>c.candidate_id===recent),index=selected>=0?selected:candidates.map(c=>Boolean(c.patch?.trim())).lastIndexOf(true);
 state.candidate=index<0?0:index;
}
function savedTaskTab(){
 if(state.task?.automatic)return workflowTab(state.task);
 if(state.task?.validated||finalCandidate()?.validation_result?.success===true)return 'patch';
 if(state.task?.stage==='validation')return 'validation';
 if(state.task?.stage==='repair'&&state.task.candidates?.length)return 'patch';
 if(state.task?.status==='retrieval_ready'||state.task?.stage==='retrieval')return 'knowledge';
 return 'diagnosis';
}
async function validateCandidate(target){
 const id=state.task.id,candidate=Number(target.dataset.candidate),tab=state.tab;target.disabled=true;
 try{
  await api('/tasks/'+id+'/validate',{method:'POST',body:JSON.stringify({candidate_id:candidate})});
  if(state.task?.id!==id)return;
  const task=await api('/tasks/'+id);if(state.task?.id!==id)return;
  state.task=task;if(state.page==='workbench'&&state.tab===tab){setTaskTab('validation');state.validationFollow=true;render();}else render();subscribe(id);
 }finally{if(target.isConnected)target.disabled=false;}
}
function subscribe(id){
 if(state.presentation)return;
 stream?.close();const source=new EventSource('/api/tasks/'+id+'/events');stream=source;let pending=false,finished=false;
 const refresh=async(done=false)=>{
  if(stream!==source||state.task?.id!==id)return;
  if(pending){if(done)setTimeout(()=>refresh(true),200);return;}
  pending=true;
  try{
   const [task,overview]=await Promise.all([api('/tasks/'+id),done?api('/overview'):Promise.resolve(null)]);
   if(stream!==source||state.task?.id!==id)return;
   state.workflowConnection='connected';
   if(task.automatic&&state.workflowFollow!==false&&state.page==='workbench')captureReading();
   state.task=task;
   if(!state.sourceTouched&&!state.sourceAutoLocated&&task.diagnosis_report?.summary)state.line=diagnosisInitialLine(task);
   if(overview)state.overview=overview;
   else state.overview.tasks=state.overview.tasks.map(row=>row.id===id?{...row,status:task.status,stage:task.stage,validated:task.validated,updated_at:task.updated_at}:row);
   if(task.automatic&&state.workflowFollow!==false&&state.page==='workbench'){
    const tab=workflowTab(task);if(tab!==state.tab){state.tab=tab;restoreSelection();writeRoute('replace');}
   }
   if(['workbench','home','tasks'].includes(state.page))render();
   if(!active.includes(task.status)){finished=true;source.close();clearInterval(poll);}
  }catch(e){state.workflowConnection='offline';if(state.page==='workbench')render();}
  finally{pending=false;}
 };
 source.onopen=()=>{state.workflowConnection='connected';};
 source.onerror=()=>{if(stream===source&&!finished){state.workflowConnection='reconnecting';if(state.page==='workbench')render();}};
 source.onmessage=()=>{clearTimeout(streamTimer);streamTimer=setTimeout(()=>refresh(),180);};
 source.addEventListener('done',()=>{source.close();clearTimeout(streamTimer);refresh(true);});
 const poll=setInterval(()=>{if(stream!==source||finished||state.task?.id!==id){clearInterval(poll);return;}refresh();},1800);
}

function scrollSourceLine(){const node=document.querySelector(`.code-line[data-line="${state.line}"]`),box=document.querySelector('#source-view');if(node&&box){const top=node.getBoundingClientRect().top-box.getBoundingClientRect().top+box.scrollTop;if(top<box.scrollTop||top+30>box.scrollTop+box.clientHeight)box.scrollTop=Math.max(0,top-box.clientHeight/2);}}
let sourceResizeTimer=null;
window.addEventListener('resize',()=>{clearTimeout(sourceResizeTimer);sourceResizeTimer=setTimeout(()=>{if(state.page==='workbench'&&state.tab==='diagnosis')scrollSourceLine();},120);});
function focusLine(line,evidenceIndex=null){
 if(!Number.isInteger(Number(line))||Number(line)<1||Number(line)>diagnosisSourceLines().length){toast('Line number is outside the source file.');return;}
 state.sourceTouched=true;
 state.line=Number(line);const index=evidenceIndex??visibleFacts().findIndex(f=>f.location?.start_line===state.line);if(index>=0)state.evidence=index;render();
 scrollSourceLine();const jump=document.querySelector('#source-jump');if(jump)jump.value=state.line;
 captureReading();
}
document.addEventListener('click',async event=>{
 document.querySelectorAll('.task-actions[open]').forEach(menu=>{if(!menu.contains(event.target))menu.open=false;});
 const target=event.target.closest('[data-action]');if(!target||target.disabled)return;
 if(state.presentation&&['new','new-aligned','advance','validate-candidate','cancel','pause','resume','analyze','run-analysis','start-task','repository-start'].includes(target.dataset.action)){toast('Exit the saved-results presentation before starting a repair action.');return;}
 try{
 if(await repositoryTaskClick(target))return;
 switch(target.dataset.action){
 case 'toggle-sidebar':{
  state.sidebarMode=sidebarIsCollapsed()?'expanded':'collapsed';
  try{localStorage.setItem('kea-sidebar',state.sidebarMode);}catch{}
  render();
  break;
 }
 case 'nav':await navigate(target.dataset.page);break;
 case 'new':await openNew();break;
 case 'new-aligned':await openNew(state.task.case_key);break;
 case 'demo':await openTask('walkthrough');break;
 case 'open-task':await openTask(target.dataset.id,{tab:target.dataset.tab||null});break;
 case 'present-task':await openTask(target.dataset.id,{presentation:true});break;
 case 'replay-task':await startReplay(target);break;
 case 'presentation-tab':if(presentationTabs().includes(target.dataset.tab))setTaskTab(target.dataset.tab);break;
 case 'exit-presentation':await openTask(state.task.id,{tab:state.tab,presentation:false});break;
 case 'presentation-export':exportPresentation();break;
 case 'theme':{const theme=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=theme;try{localStorage.setItem('kea-theme',theme);}catch{}render();break;}
 case 'help':showHelp();break;
 case 'close-modal':closeModal();break;
 case 'tab':setTaskTab(target.dataset.tab);break;
 case 'evidence':{const index=Number(target.dataset.index),fact=visibleFacts()[index];if(!fact)break;state.diagnosisView='facts';const line=fact.location?.start_line;if(Number.isInteger(line)&&line>0)focusLine(line,index);else{state.evidence=index;render();toast('This fact has no source location.');}break;}
 case 'line':focusLine(target.dataset.line);break;
 case 'tool-detail':toolDetail(Number(target.dataset.index));break;
 case 'report-download':downloadReport();break;
 case 'advance':await advanceStage(target);break;
 case 'validate-candidate':await validateCandidate(target);break;
 case 'analyze':analyzeModal();break;
 case 'run-analysis':await runAnalysis(target);break;
 case 'candidate':state.candidate=Number(target.dataset.index);render();break;
 case 'validation-stage':state.validationStage=target.dataset.stage;state.validationFollow=false;render();break;
 case 'validation-follow':state.validationFollow=state.validationFollow===false;render();break;
 case 'record':await openRecord(target.dataset.id);break;
 case 'record-view':state.recordView=target.dataset.view;renderRecord();break;
 case 'exemplar':state.record=state.task.exemplars[Number(target.dataset.index)];state.recordView='data_flow';state.modal='record';renderRecord();break;
 case 'retrieval-example':retrievalReturnFocus=target;openRetrievalExample(target.dataset.sample,target.dataset.view);requestAnimationFrame(()=>document.querySelector('.retrieval-drawer [data-action=retrieval-close]')?.focus({preventScroll:true}));break;
 case 'retrieval-view':setRetrievalView(target.dataset.view);break;
 case 'retrieval-close':closeRetrievalExample();retrievalReturnFocus?.isConnected&&retrievalReturnFocus.focus({preventScroll:true});break;
 case 'retrieval-jump':scrollReviewTarget(target.dataset.target);break;
 case 'retrieval-origin':{const row=document.getElementById('retrieval-row-'+target.dataset.view+'-'+target.dataset.rank)?.querySelector('.retrieval-row')||[...document.querySelectorAll('.retrieval-lane.'+target.dataset.view+' .retrieval-row')].find(n=>n.dataset.sample===target.dataset.sample);if(row){if(innerWidth<=1200)closeRetrievalExample();scrollReviewTarget(row);row.focus({preventScroll:true});}break;}
 case 'diagnosis-view':state.diagnosisView=target.dataset.view;render();break;
 case 'source-wrap':state.sourceWrap=state.sourceWrap===false;render();scrollSourceLine();break;
 case 'diagnosis-jump':{const input=document.querySelector('#source-jump'),line=Number(input?.value),max=diagnosisSourceLines().length;if(!Number.isInteger(line)||line<1||line>max){toast('Enter a source line between 1 and '+max+' .');break;}focusLine(line);document.querySelector('#source-view')?.focus({preventScroll:true});break;}
 case 'diff-mode':state.diffMode=target.dataset.mode==='split'?'split':'unified';render();break;
 case 'diff-context':state.diffContext=!state.diffContext;render();break;
 case 'diff-hunk':scrollReviewTarget(target.dataset.target);break;
 case 'kb-next':state.kbOffset+=12;await loadKnowledge();document.querySelector('.filters')?.scrollIntoView({block:'start',behavior:'smooth'});break;
 case 'kb-prev':state.kbOffset=Math.max(0,state.kbOffset-12);await loadKnowledge();break;
 case 'kb-add':openKnowledgeAddition();break;
 case 'kb-submit':await submitKnowledgeAddition();break;
 case 'case-page':state.caseOffset=Number(target.dataset.offset);renderCasePicker();document.querySelector('#case-options').scrollTop=0;break;
 case 'select-case':state.selectedCase=target.dataset.key;chooseDefaultExecutionMode();renderNew();break;
 case 'start-task':await startTask();break;
 case 'refresh':state.overview=await api('/overview');render();toast('Local status updated.');break;
 case 'pause':case 'resume':{const id=state.task.id,action=target.dataset.action;target.disabled=true;try{await api('/tasks/'+id+'/'+action,{method:'POST'});const task=await api('/tasks/'+id);if(state.task?.id===id){state.task=task;render();}}finally{if(target.isConnected)target.disabled=false;}break;}
 case 'cancel':{const id=state.task.id;await api('/tasks/'+id+'/cancel',{method:'POST'});const task=await api('/tasks/'+id);if(state.task?.id===id){state.task=task;render();}toast('Stop request sent.');break;}
 case 'logs':await showLogs();break;
 case 'workflow-follow':state.workflowFollow=state.workflowFollow===false;if(state.workflowFollow){captureReading();state.tab=workflowTab();restoreSelection();writeRoute('replace');}render();break;
 case 'repair-report':download('/api/tasks/'+state.task.id+'/report?format='+(target.dataset.format||'html'));break;
 case 'export':download('/api/tasks/'+state.task.id+'/export');break;
 default:await handleTaskManagementAction(target);break;
 case 'patch-download':{const candidate=currentCandidate(),patch=candidate?.patch;if(!patch){toast('No patch is available to download.');break;}const url=URL.createObjectURL(new Blob([patch],{type:'text/x-diff;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download=`${state.task.case_id}-${candidate===finalCandidate()?'final':'candidate-'+candidate.candidate_id}.patch`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);break;}
 }
 }catch(e){fail(e);}
});
document.addEventListener('input',event=>{
 if(repositoryTaskInput(event))return;
 if(event.target.id==='diagnosis-fact-search'){state.factQuery=event.target.value;render();}
 if(event.target.id==='kb-search'){state.kbQuery=event.target.value;state.kbOffset=0;clearTimeout(searchTimer);searchTimer=setTimeout(loadKnowledge,250);}
 if(event.target.id==='case-search'){state.caseQuery=event.target.value;state.caseOffset=0;renderCasePicker();}
});
document.addEventListener('change',event=>{
 if(repositoryTaskChange(event))return;
 if(event.target.id==='diagnosis-tool-filter'){state.factTool=event.target.value;render();}
 if(event.target.id==='kb-language'){state.kbLanguage=event.target.value;state.kbOffset=0;loadKnowledge();}
 if(event.target.id==='case-language'){state.caseLanguage=event.target.value;state.caseOffset=0;renderCasePicker();}
 if(event.target.id==='variant'){state.variant=event.target.value;chooseDefaultExecutionMode();renderNew();}
 if(event.target.id==='execution-mode'){state.executionMode=event.target.value;renderNew();}
});
document.addEventListener('keydown',event=>{
 if(repositoryTaskKeydown(event))return;
 if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'){event.preventDefault();if(!state.presentation)openNew().catch(fail);}
 if(event.key==='Escape'){if(document.querySelector('.modal'))closeModal();else if(state.retrievalSample&&state.page==='workbench'&&state.tab==='knowledge'){closeRetrievalExample();retrievalReturnFocus?.isConnected&&retrievalReturnFocus.focus({preventScroll:true});}document.querySelectorAll('.task-actions[open]').forEach(menu=>{menu.open=false;menu.querySelector('summary')?.focus();});}
 if(event.key==='Enter'&&event.target.id==='source-jump'){event.preventDefault();document.querySelector('[data-action=diagnosis-jump]')?.click();}
 const drawer=innerWidth<=1200&&state.page==='workbench'&&state.tab==='knowledge'?document.querySelector('.retrieval-drawer'):null;
 const modal=document.querySelector('.modal')||drawer;
 if(event.key==='Tab'&&modal){
 const nodes=[...modal.querySelectorAll('button:not(:disabled),input,select,textarea,a[href],[tabindex="0"]')].filter(x=>x.getClientRects().length),first=nodes[0],last=nodes.at(-1);
 if(event.shiftKey&&document.activeElement===first){event.preventDefault();last?.focus();}
 else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first?.focus();}
 }
});
function scrollReviewTarget(target){const node=typeof target==='string'?document.getElementById(target):target;if(!node)return;const navigation=document.querySelector('.workspace-navigation'),offset=navigation?.getBoundingClientRect().height||0;window.scrollTo({top:Math.max(0,node.getBoundingClientRect().top+scrollY-offset-16),behavior:'instant'});}
function routeLocation(){
 const params=new URLSearchParams(location.search),hash=location.hash.slice(1);
 return {page:appPages.includes(hash)?hash:params.has('task')?'workbench':'home',id:params.get('task'),tab:params.get('tab'),presentation:params.get('presentation')==='1'};
}
async function followLocation(){
 const route=routeLocation();
 if(route.page==='workbench'){
  let id=route.id;try{id=id||localStorage.getItem('kea-task');}catch{}
  if(id&&(state.task?.id!==id||state.presentation!==route.presentation))return openTask(id,{tab:route.tab,historyMode:'none',presentation:route.presentation});
  if(id&&state.page==='workbench'&&reviewTabs.includes(route.tab)&&route.tab!==state.tab){setTaskTab(route.tab,{route:false});return;}
 }
 if(route.page!==state.page){await navigate(route.page,{route:false});if(route.page==='workbench'&&reviewTabs.includes(route.tab))setTaskTab(route.tab,{route:false});}
}
let pendingLocation=null;
function syncLocation(){const href=location.href;if(pendingLocation===href)return;pendingLocation=href;followLocation().catch(fail).finally(()=>{if(pendingLocation===href)pendingLocation=null;});}
window.addEventListener('popstate',syncLocation);
window.addEventListener('hashchange',syncLocation);
window.addEventListener('beforeunload',()=>{captureReading();stream?.close();});
document.addEventListener('scroll',()=>{clearTimeout(readingTimer);readingTimer=setTimeout(()=>captureReading(),180);},true);
document.addEventListener('toggle',()=>{clearTimeout(readingTimer);readingTimer=setTimeout(()=>captureReading(),100);},true);
document.addEventListener('keydown',event=>{
 if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)||event.target.getAttribute('role')!=='tab')return;
 if(event.target.closest('.dr-tabs')){event.preventDefault();const tabs=['facts','tools'],index=tabs.indexOf(state.diagnosisView),next=event.key==='Home'?0:event.key==='End'?1:(index+(event.key==='ArrowRight'?1:-1)+2)%2;state.diagnosisView=tabs[next];render();document.querySelector('#diagnosis-tab-'+state.diagnosisView)?.focus();return;}
});
async function init(){
 try{
  state.overview=await api('/overview');const route=routeLocation();state.page=route.page;
  if(route.page==='workbench'){
   let id=route.id;try{id=id||localStorage.getItem('kea-task');}catch{}
   if(id)await openTask(id,{tab:route.tab,historyMode:'replace',presentation:route.presentation});else render();
  }else{render();writeRoute('replace');}
  if(state.page==='knowledge'){await loadKnowledge();await refreshKnowledgeBuilds();}
 }catch(e){document.querySelector('#app').innerHTML=`<div class="boot"><div class="boot-mark">K</div><h2>Could not connect to KeaRepair</h2><p>${esc(e.message)}</p><p>Check the local service and refresh the page.</p></div>`;}
}
init();

let overviewRefreshing=false;
setInterval(async()=>{if(overviewRefreshing||document.hidden||!['home','tasks'].includes(state.page))return;overviewRefreshing=true;try{const overview=await api('/overview');if(['home','tasks'].includes(state.page)){state.overview=overview;render();}}catch{}finally{overviewRefreshing=false;}},5000);
