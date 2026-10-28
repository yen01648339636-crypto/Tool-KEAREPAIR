const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {join}=require('node:path');
const vm=require('node:vm');

function setup(){
 let clock=Date.parse('2026-01-01T00:00:15Z');
 class TestDate extends Date {static now(){return clock}}
 const c=vm.createContext({Date:TestDate,setInterval:()=>{},setTimeout:()=>{},clearTimeout:()=>{},console});
 for(const name of ['legacy-messages.js','app.js','runtime.js','workflow.js','results-review.js','replay.js'])vm.runInContext(readFileSync(join(__dirname,'../../studio/web',name),'utf8'),c);
 const run=s=>vm.runInContext(s,c);
 run("state.task={id:'task-one',mode:'live',status:'running',stage:'diagnosis',automatic:true,created_at:'2026-01-01T00:00:00Z',updated_at:'2026-01-01T00:00:10Z',events:[],candidates:[],runtime:{},pause:{intervals:[]}};state.workflowConnection='connected'");
 return {run,c,tick:v=>{clock=Date.parse(v)}};
}

test('live and replay both expose pause/resume controls and keep paused tasks active',()=>{
 const {run}=setup();
 for(const mode of ['live','replay']){
  run(`state.task.mode='${mode}'`);
  for(const status of ['queued','running']){run(`state.task.status='${status}'`);assert.match(run('taskPrimaryAction()'),/data-action="pause"/);}
  run("state.task.status='paused'");assert.match(run('taskPrimaryAction()'),/data-action="resume"[^>]*>.*Resume/);
  assert.equal(run("active.includes(state.task.status)"),true);
  assert.equal(run('canReplay(state.task)'),false);
  assert.match(run('workflowLivePanel()'),/is-paused/);
  assert.match(run('workflowLivePanel()'),/Execution paused/);
  run("state.task.status='pausing'");assert.match(run('taskPrimaryAction()'),/Continue Running/);
  assert.match(run('workflowLivePanel()'),/Finishing the current operation/);
 }
 run("state.task.status='cancelling'");assert.doesNotMatch(run('taskPrimaryAction()'),/data-action="pause"|data-action="resume"/);
});

test('elapsed display freezes while paused and subtracts only overlapping pause intervals',()=>{
 const {run,tick}=setup();
 run("state.task.status='paused';state.task.pause={paused_at:'2026-01-01T00:00:10Z',intervals:[{started_at:'2026-01-01T00:00:02Z',finished_at:'2026-01-01T00:00:05Z'},{started_at:'2026-01-01T00:00:10Z',finished_at:null}]};globalThis.record={started_at:state.task.created_at,status:'running'}");
 const frozen=run('runtimeElapsed(record)');assert.match(frozen,/>7 s</);assert.doesNotMatch(frozen,/data-runtime-start/);
 tick('2026-01-01T00:01:40Z');assert.equal(run('runtimeElapsed(record)'),frozen);
 run("state.task.status='running';state.task.pause.paused_at=null;state.task.pause.intervals[1].finished_at='2026-01-01T00:01:30Z'");
 assert.match(run('runtimeElapsed(record)'),/>17 s</);
 assert.match(run('runtimeElapsed(record)'),/data-runtime-paused="83"/);
 assert.match(run("runtimeElapsed({started_at:'2026-01-01T00:01:35Z',status:'running'})"),/>5 s</);
});

test('validation clocks and captions freeze without rewriting recorded test outcomes',()=>{
 const {run}=setup();
 run("state.task.status='paused';state.task.pause={paused_at:'2026-01-01T00:00:10Z',intervals:[]};globalThis.model={working:true,progress:{started_at:'2026-01-01T00:00:00Z',step_started_at:'2026-01-01T00:00:05Z'}}");
 assert.match(run("validationClock(model,{status:'running'})"),/>5 s</);
 assert.doesNotMatch(run("validationClock(model,{status:'running'})"),/data-runtime-start/);
 assert.equal(run("validationStageCaption({status:'running'},model)"),'Paused · resume to continue');
 assert.equal(run("validationStageCaption({status:'passed',id:'poc'},model)"),'Stage complete');
});
