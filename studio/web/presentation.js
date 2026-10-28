// A frozen, explicitly labelled view of saved task results. It never advances the engine.
function presentationTabs(){
 const t=state.task||{},tabs=[];
 if(Object.keys(t.diagnosis_report||{}).length||t.mode==='walkthrough')tabs.push('diagnosis');
 if(Object.keys(t.retrieval||{}).length||t.exemplars?.length||Object.keys(t.retrieval_progress||{}).length)tabs.push('knowledge');
 if((t.candidates||[]).some(c=>c.patch?.trim()))tabs.push('patch');
 if((t.candidates||[]).some(c=>c.validation_result||c.latest_validation))tabs.push('validation');
 return tabs.length?tabs:['diagnosis'];
}
function presentationAction(){
 const tabs=presentationTabs(),index=tabs.indexOf(state.tab),next=tabs[index+1],names={diagnosis:'Diagnose Vulnerability',knowledge:'Retrieve Knowledge',patch:'Generate Patch',validation:'Patch Validation'};
 return next?button('presentation-tab','Next: '+names[next],'arrow','primary',`data-tab="${next}"`):button('exit-presentation','Back to Online Repair','arrow','primary');
}
function presentationBanner(){
 if(!state.presentation)return '';
 const tabs=presentationTabs(),index=tabs.indexOf(state.tab),previous=tabs[index-1];
 return `<div class="presentation-banner">${icon('play')}<strong>Saved-results presentation</strong><span>Viewing saved task artifacts</span><span class="presentation-time">Snapshot captured ${date(state.presentationCapturedAt)}</span><div class="presentation-controls">${button('presentation-tab','Previous stage','chevron','small',`data-tab="${previous||''}" ${previous?'':'disabled'}`)}${button('exit-presentation','Exit presentation',null,'small')}</div></div>`;
}
function exportPresentation(){
 const data={mode:'saved_results_presentation',captured_at:state.presentationCapturedAt,task:state.task};
 const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json;charset=utf-8'})),a=document.createElement('a');
 a.href=url;a.download=state.task.case_id+'-saved-results.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
