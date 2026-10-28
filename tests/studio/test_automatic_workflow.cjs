const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {join}=require('node:path');
const vm=require('node:vm');
const source=readFileSync(join(__dirname,'../../studio/web/workflow.js'),'utf8');
function run(expression,task){const c=vm.createContext({state:{task},active:['queued','running','cancelling']});vm.runInContext(source,c);return vm.runInContext(expression,c);}
test('automatic view follows native validation within the repair worker',()=>{
 const t={automatic:true,status:'running',stage:'repair',runtime:{validation_progress:{running:true,candidate_id:'1'}}};
 assert.equal(run('workflowTab()',t),'validation');
 t.runtime.progress={activity:{kind:'generation',candidate_id:2}};
 assert.equal(run('workflowTab()',t),'patch');
 t.runtime.validation_progress={running:true,candidate_id:'2'};
 assert.equal(run('workflowTab()',t),'validation');
 t.status='completed';assert.equal(run('workflowTab()',t),'report');
 t.status='failed';assert.notEqual(run('workflowTab()',t),'report');
});
