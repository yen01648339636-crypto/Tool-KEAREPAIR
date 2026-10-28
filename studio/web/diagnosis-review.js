// Review the original diagnosis beside its source. Display fields never rewrite the report.
function diagnosisSourceLines(source=state.task?.source){return String(source||'').split('\n');}
function diagnosisInitialLine(task){
 const maximum=diagnosisSourceLines(task?.source).length,report=task?.diagnosis_report||{};
 const valid=n=>Number.isInteger(n)&&n>0&&n<=maximum;
 // Prefer an explicit line in the original summary to a file header or an
 // incidental definition returned by a structural query. Never infer a line.
 const summary=String(report.summary||'');
 for(const match of summary.matchAll(/\b(?:lines?\s+|L)(\d+)\b/gi))if(valid(+match[1]))return +match[1];
 const calls=task?.tool_calls||report.tool_calls||[];
 for(const call of calls){const line=call.arguments?.statement?.line;if(valid(line))return line;}
 for(const fact of task?.facts||report.facts||[])if(valid(fact.location?.start_line))return fact.location.start_line;
 return 1;
}
function diagnosisParagraphs(text){
 // Only insert paragraph breaks; keep every sentence and uncertainty qualifier.
 return String(text||'').split(/\n\s*\n/).flatMap(block=>{
  if(block.length<500||typeof Intl.Segmenter!=='function')return [block];
  const sentences=[...new Intl.Segmenter('en',{granularity:'sentence'}).segment(block)].map(x=>x.segment),parts=[];
  for(let i=0;i<sentences.length;i+=3)parts.push(sentences.slice(i,i+3).join(''));
  return parts;
 }).filter(p=>p.trim());
}
function diagnosisInline(text){return String(text).split(/(`[^`\n]+`)/g).map(p=>p.startsWith('`')&&p.endsWith('`')?`<code>${esc(p.slice(1,-1))}</code>`:esc(p)).join('');}
function diagnosisFilteredFacts(){
 const query=String(state.factQuery||'').trim().toLocaleLowerCase(),tool=state.factTool||'';
 return visibleFacts().map((fact,index)=>({fact,index})).filter(({fact})=>{
  if(tool&&fact.tool!==tool)return false;
  const line=fact.location?.start_line;
  return !query||[fact.statement,fact.tool,fact.evidence_id,fact.location?.file,line,line?'L'+line:''].join(' ').toLocaleLowerCase().includes(query);
 });
}

function diagnosisConclusion(){
 const t=state.task,report=t.diagnosis_report||{},demo=t.mode==='walkthrough';
 const conclusion=reportConclusion(report)||(demo?t.description:'');
 if(!conclusion)return `<div class="dr-empty">${icon('file')}<h3>No diagnosis summary yet</h3><p>${t.status==='paused'?'Diagnosis is paused. Select Resume to continue.':t.status==='pausing'?'Finishing the current diagnosis operation before pausing.':active.includes(t.status)?'Diagnosis is running. Recorded facts and calls are available in their tabs.':'The original report summary will appear when diagnosis finishes.'}</p></div>`;
 const issues=t.diagnosis_issues||[];
 return `<article class="dr-conclusion"><div class="dr-section-title"><h3>${demo?'Walkthrough Notes':'Diagnosis Summary'}</h3><span>${demo?'Synthetic example':t.mode==='replay'?'Historical diagnosis report':'Original diagnosis report'}</span></div><div class="dr-conclusion-text">${diagnosisParagraphs(conclusion).map(p=>`<p>${diagnosisInline(p)}</p>`).join('')}</div>${issues.length?`<div class="dr-report-issue">${icon('info')}<p>${esc(uiMessage(issues.join('; ')))}</p></div>`:''}${report.limitations?.length||report.termination_reason?`<details class="dr-report-notes" data-ui-key="diagnosis-report-notes"><summary>Report status & analysis scope ${icon('chevron')}</summary>${report.limitations?.length?`<ul>${report.limitations.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`:''}${report.termination_reason?`<p>Termination reason <code>${esc(report.termination_reason)}</code></p>`:''}</details>`:''}</article>`;
}

function diagnosisFacts(){
 const facts=visibleFacts(),filtered=diagnosisFilteredFacts(),tools=[...new Set(facts.map(f=>f.tool).filter(Boolean))];
 const groups=new Map();
 for(const item of filtered){
  const fact=item.fact,tool=fact.tool||'Tool not recorded',line=fact.location?.start_line||0,key=tool+':'+line;
  if(!groups.has(key))groups.set(key,{tool,line,items:[]});
  groups.get(key).items.push(item);
 }
 return `<div class="dr-facts"><div class="dr-fact-filters"><label class="dr-search">${icon('search')}<input type="search" id="diagnosis-fact-search" aria-label="Search program facts" placeholder="Search facts, tools or lines…" value="${esc(state.factQuery||'')}"></label><label class="dr-filter-label"><span class="sr-only">Filter by analysis tool</span><select id="diagnosis-tool-filter" aria-label="Filter by analysis tool"><option value="">All tools</option>${tools.map(t=>`<option value="${esc(t)}" ${state.factTool===t?'selected':''}>${esc(t)}</option>`).join('')}</select></label></div><div class="dr-fact-count" role="status">${filtered.length===facts.length?`${facts.length} recorded facts`:`Matched ${filtered.length} / ${facts.length} facts`}<span>Select a fact to locate source</span></div><div class="dr-fact-results" data-ui-key="diagnosis-fact-results">${filtered.length?[...groups.values()].map(group=>`<section class="dr-fact-group"><div class="dr-group-heading"><span>${icon('terminal')}${esc(group.tool)}</span><span>${group.line?'L'+esc(group.line):'No line'} · ${group.items.length} items</span></div>${group.items.map(({fact,index})=>{const line=fact.location?.start_line;return `<button class="dr-fact ${state.evidence===index&&state.line===line?'is-selected':''}" data-action="evidence" data-index="${index}" ${line?'':`disabled title="No source line was recorded for this fact"`} aria-pressed="${state.evidence===index&&state.line===line}"><div class="dr-fact-meta"><strong>E${String(index+1).padStart(2,'0')}</strong><span>${line?'L'+esc(line):'No location'}${fact.location?.end_line&&fact.location.end_line!==line?'–'+esc(fact.location.end_line):''}</span>${line?icon('arrow'):''}</div><p>${esc(fact.statement||'No description was recorded for this fact.')}</p></button>`;}).join('')}</section>`).join(''):`<div class="dr-empty">${icon('search')}<h3>${facts.length?'No matching facts':'No program facts recorded'}</h3><p>${facts.length?'Try a different keyword or tool filter.':'The diagnosis agent chooses tools according to its analysis needs.'}</p></div>`}</div></div>`;
}

function diagnosisTools(){
 const calls=state.task.tool_calls||state.task.diagnosis_report?.tool_calls||[];
 if(!calls.length)return `<div class="dr-empty">${icon('terminal')}<h3>${state.task.stage==='diagnosis'&&active.includes(state.task.status)?'Awaiting tool-call records':'No analysis tools were called'}</h3><p>Actual tool inputs and results recorded by the agent appear here.</p></div>`;
 return `<div class="dr-tool-list">${calls.map((call,index)=>{
  const result=call.observation?.result,facts=call.observation?.facts||[],line=call.arguments?.statement?.line;
  const locatable=Number.isInteger(line)&&line>0&&line<=diagnosisSourceLines().length;
  return `<details class="dr-tool" data-ui-key="diagnosis-tool-${index}" ${index===0?'open':''}><summary><span class="dr-tool-number">${String(index+1).padStart(2,'0')}</span><strong>${esc(call.tool||'Tool not recorded')}</strong>${icon('chevron')}</summary><div class="dr-tool-body"><div class="dr-tool-label">Input arguments ${locatable?button('line','Go to L'+line,'arrow','small',`data-line="${line}"`):''}</div><pre class="dr-tool-arguments">${esc(JSON.stringify(call.arguments||{},null,2))}</pre><dl class="dr-tool-status"><div><dt>Call status</dt><dd>${esc(call.status||'Not recorded')}</dd></div><div><dt>Result status</dt><dd>${esc(result?.status||'Not recorded')}</dd></div><div><dt>Linked facts</dt><dd>${facts.length} items</dd></div></dl>${call.error?`<p class="dr-tool-error">${esc(uiMessage(call.error))}</p>`:''}${button('tool-detail','View full call record','terminal','small',`data-index="${index}"`)}</div></details>`;
 }).join('')}</div>`;
}

function diagnosisReviewPanel(){
 const t=state.task,report=t.diagnosis_report||{},facts=visibleFacts(),calls=t.tool_calls||report.tool_calls||[];
 const view=state.diagnosisView==='tools'?'tools':'facts',lines=diagnosisSourceLines(t.source).length;
 const stats=[['Program Facts',facts.length],['Tool Calls',calls.length],['Reasoning rounds',report.reasoning_call_count??'—'],['Report requests',report.report_call_count??'—']];
 return `<section class="diagnosis-review" aria-label="Diagnosis report and source evidence"><header class="dr-heading"><div><span class="dr-eyebrow">VULNERABILITY DIAGNOSIS</span><h2>Vulnerability Diagnosis Report</h2></div>${t.mode!=='walkthrough'?button('report-download','Download Report','download','small',Object.keys(report).length?'':'disabled'):pill('Walkthrough example','amber')}</header><div class="dr-report-layout">${diagnosisConclusion()}<aside class="dr-report-context" aria-label="Diagnosis record overview"><h3>Analysis Records</h3><dl class="dr-stat-grid">${stats.map(([label,value])=>`<div><dt>${label}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl>${report.keywords?.length?`<div class="dr-keyword-section"><h3>Report Keywords</h3><div class="dr-keywords">${report.keywords.map(x=>pill(x)).join('')}</div></div>`:''}</aside></div><header class="dr-evidence-heading" id="diagnosis-evidence"><div><span class="dr-eyebrow">SOURCE & EVIDENCE</span><h2>Source & Analysis Evidence</h2></div><span>Select a fact to inspect the corresponding source</span></header><div class="dr-workspace"><section class="dr-source" aria-label="Full source review"><div class="dr-source-toolbar"><div class="dr-file" title="${esc(t.file||'source')}">${icon('file')}<span>${esc(t.file?.split('/').pop()||'source')}</span></div><div class="dr-source-controls">${button('source-wrap','Wrap lines',null,'small',`aria-pressed="${state.sourceWrap!==false}"`)}<div class="dr-line-jump"><label for="source-jump">Line</label><input type="number" id="source-jump" min="1" max="${lines}" value="${Math.min(Number(state.line)||1,lines)}" aria-label="Go to source line">${button('diagnosis-jump','Go',null,'small')}</div></div></div>${codeView(t.source,state.line)}<footer class="dr-source-meta"><span>${esc(t.language||'SOURCE')} · ${fmt(lines)} lines · full source</span><span>${icon('lock')}Read only</span>${button('analyze','Analyze','bolt','small')}</footer></section><aside class="dr-analysis" aria-label="Program facts and tool calls"><div class="dr-tabs" role="tablist" aria-label="Analysis evidence">${[['facts','Program Facts',facts.length],['tools','Tool Calls',calls.length]].map(([id,label,count])=>`<button role="tab" id="diagnosis-tab-${id}" aria-selected="${id===view}" aria-controls="diagnosis-content-${id}" tabindex="${id===view?0:-1}" data-action="diagnosis-view" data-view="${id}" class="${id===view?'is-active':''}">${label}<span>${count}</span></button>`).join('')}</div><div class="dr-analysis-content dr-content-${view}" role="tabpanel" id="diagnosis-content-${view}" aria-labelledby="diagnosis-tab-${view}" tabindex="0" data-ui-key="diagnosis-${view}">${view==='tools'?diagnosisTools():diagnosisFacts()}</div></aside></div></section>`;
}
