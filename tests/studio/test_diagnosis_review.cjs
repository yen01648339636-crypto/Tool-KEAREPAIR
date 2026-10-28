const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {join}=require('node:path');
const vm=require('node:vm');

function context(task){
 const c=vm.createContext({task});
 for(const file of ['legacy-messages.js','app.js','diagnosis.js','diagnosis-review.js'])vm.runInContext(readFileSync(join(__dirname,'../../studio/web',file),'utf8'),c);
 vm.runInContext("state.task=task;state.sourceWrap=true;state.diagnosisView='facts';state.line=diagnosisInitialLine(task)",c);
 return c;
}
function fixture(){return {id:'fixture',mode:'live',status:'diagnosis_ready',stage:'diagnosis',source:Array.from({length:3000},(_,i)=>`int line_${i+1};`).join('\n'),file:'parser.c',language:'c',facts:[{statement:'Recorded fact',tool:'trace_data_flow',location:{start_line:805},evidence_id:'evidence-1'}],tool_calls:[],diagnosis_report:{summary:'Suspected divide by zero in parser.c line 2501. `value % size` may fail. Exploitability is not proven.',keywords:['divide by zero'],reasoning_call_count:2,report_call_count:1},diagnosis_issues:[]};}

test('source location follows an explicit in-range summary line, not incidental first fact',()=>{
 const task=fixture(),c=context(task);
 assert.equal(vm.runInContext('state.line',c),2501);
 task.diagnosis_report.summary='A risk at line 99999 is outside the snapshot.';
 assert.equal(vm.runInContext('diagnosisInitialLine(task)',c),805);
 task.tool_calls=[{arguments:{statement:{line:2800}}}];
 assert.equal(vm.runInContext('diagnosisInitialLine(task)',c),2800);
});

test('complete source is rendered and every valid line can be selected beyond 2000',()=>{
 const c=context(fixture()),html=vm.runInContext('diagnosisReviewPanel()',c);
 assert.match(html,/data-line="3000"/);
 assert.match(html,/id="source-jump"[^>]*max="3000"/);
 assert.ok(!html.includes('预览前 2,000'));
 assert.ok(html.includes('wrap-lines'));
 assert.ok(html.indexOf('dr-report-layout')<html.indexOf('dr-workspace'));
 assert.ok(!html.includes('diagnosis-tab-conclusion'));
});

test('paragraph formatting preserves all sentences and uncertainty qualifiers',()=>{
 const task=fixture();task.diagnosis_report.summary=Array.from({length:24},(_,i)=>`Sentence ${i} contains an unconfirmed inference.`).join(' ');
 const c=context(task),parts=vm.runInContext('diagnosisParagraphs(task.diagnosis_report.summary)',c);
 assert.ok(parts.length>1);
 assert.equal(parts.join('').replace(/\s/g,''),task.diagnosis_report.summary.replace(/\s/g,''));
 const html=vm.runInContext('diagnosisConclusion()',c);
 assert.ok(html.includes('Sentence 23 contains an unconfirmed inference.'));
 assert.ok(!html.includes('is-collapsed')&&!html.includes('diagnosis-expand'));
});

test('rendering escapes report/code and preserves the native report object',()=>{
 const task=fixture();task.diagnosis_report.summary+=' <img src=x onerror=alert(1)> `a < b`';
 const before=JSON.stringify(task),c=context(task),html=vm.runInContext('diagnosisReviewPanel()',c);
 assert.ok(!html.includes('<img src=x'));
 assert.ok(html.includes('&lt;img src=x'));
 assert.ok(html.includes('<code>a &lt; b</code>'));
 assert.equal(JSON.stringify(task),before);
});

test('tool inputs are not silently truncated and include full-record navigation',()=>{
 const task=fixture();task.tool_calls=[{tool:'trace_data_flow',status:'ok',arguments:{variable:'x'.repeat(500),statement:{line:2800}},observation:{result:{status:'unknown'},facts:[]}}];
 const c=context(task),html=vm.runInContext('diagnosisTools()',c);
 assert.ok(html.includes('x'.repeat(500)));
 assert.ok(html.includes('data-action="tool-detail"'));
 assert.ok(html.includes('Go to L2800'));
 assert.ok(html.includes('unknown'));
});

test('fact filtering handles late source lines and leaves report completeness intact',()=>{
 const task=fixture();task.facts.push({statement:'Late-source fact',tool:'inspect_api_usage',location:{start_line:2999}});
 const c=context(task);
 vm.runInContext("state.factQuery='L2999';state.factTool='inspect_api_usage'",c);
 const filtered=vm.runInContext('diagnosisFilteredFacts()',c);
 assert.equal(filtered.length,1);assert.equal(filtered[0].index,1);
 assert.equal(task.facts.length,2);
});
