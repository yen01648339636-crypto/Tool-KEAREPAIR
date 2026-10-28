const {test} = require('node:test');
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {join} = require('node:path');
const vm = require('node:vm');
function storage(values={}) {
 const map=new Map(Object.entries(values));
 return {getItem:k=>map.get(k)||null,removeItem:k=>map.delete(k),key:i=>[...map.keys()][i],get length(){return map.size}};
}
function setup() {
 const error={isConnected:true,hidden:true,textContent:''},calls=[],notices=[];
 const c=vm.createContext({clearTimeout,localStorage:storage({'kea-task':'one'}),sessionStorage:storage({'kea-last-review:one':'patch','kea-reading-v2:task:one:patch':'{}','kea-last-review:two':'diagnosis'}),readingCache:new Map([['task:one:patch',{}],['task:two:diagnosis',{}]]),routeSerial:0});
 for(const name of ['app.js','legacy-messages.js','replay.js','task-center.js'])vm.runInContext(readFileSync(join(__dirname,'../../studio/web',name),'utf8'),c);
 Object.assign(c,{document:{querySelector:s=>s==='#task-delete-error'?error:null},openModal:(...args)=>{c.modal=args},closeModal:()=>vm.runInContext('state.modal=null',c),render:()=>{},toast:s=>notices.push(s),fail:e=>{throw e},api:async(path,options)=>{calls.push({path,options});return {deleted:true}}});
 vm.runInContext("state.page='home';state.overview={tasks:[{id:'one',case_id:'CVE-2026-1',status:'completed'},{id:'two',case_id:'CVE-2026-2',status:'failed'}]};state.task=state.overview.tasks[0]",c);
 c.target={dataset:{id:'one'},isConnected:true,disabled:false};
 return {c,error,calls,notices,run:code=>vm.runInContext(code,c)};
}
test('delete is visible per run and disabled for active tasks',()=>{
 const {run}=setup();
 for(const status of ['queued','running','cancelling','completed','failed','diagnosis_ready']){
  const html=run(`taskRecordRow({id:'one',case_id:'CVE-1',status:'${status}'})`);
  const button=html.match(/<button[^>]*data-action="delete-task"[^>]*>/)[0];
  assert.match(button,/aria-label="Delete CVE-1, run one"/);
  assert.equal(/disabled/.test(button),['queued','running','cancelling'].includes(status));
 }
});
test('opening confirmation does not delete anything and escapes the task title',()=>{
 const {c,calls,run}=setup();
 run("state.overview.tasks[0].case_id='<img src=x>';confirmTaskDeletion('one')");
 assert.equal(calls.length,0);
 assert.match(c.modal[2],/&lt;img src=x&gt;/);
 assert.match(c.modal[2],/remain on disk/);
 assert.match(c.modal[3],/confirm-delete-task/);
});
test('confirmed deletion updates the list and clears only that task selection',async()=>{
 const {c,calls,run}=setup();
 run("confirmTaskDeletion('one')");
 await run('deleteTaskEntry(target)');
 assert.equal(calls.length,1);
 assert.equal(calls[0].path,'/tasks/one');
 assert.equal(calls[0].options.method,'DELETE');
 assert.equal(run('state.overview.tasks.length'),1);
 assert.equal(run('state.task'),null);
 assert.equal(c.localStorage.getItem('kea-task'),null);
 assert.equal(c.sessionStorage.getItem('kea-last-review:one'),null);
 assert.equal(c.sessionStorage.getItem('kea-last-review:two'),'diagnosis');
 assert.equal(c.readingCache.has('task:one:patch'),false);
 assert.equal(c.readingCache.has('task:two:diagnosis'),true);
});
test('a rejected deletion keeps the entry and shows the server reason',async()=>{
 const {c,error,run}=setup();
 c.api=async()=>{throw new Error('This task is still running.')};
 run("confirmTaskDeletion('one')");
 await run('deleteTaskEntry(target)');
 assert.equal(run('state.overview.tasks.length'),2);
 assert.equal(run('state.modal'),'delete-task');
 assert.equal(error.hidden,false);
 assert.equal(error.textContent,'This task is still running.');
 assert.equal(c.target.disabled,false);
});
