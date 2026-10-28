const {test} = require('node:test');
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {join} = require('node:path');
const vm = require('node:vm');

const source = readFileSync(join(__dirname, '../../studio/web/legacy-messages.js'), 'utf8') + '\n' + readFileSync(join(__dirname, '../../studio/web/results-review.js'), 'utf8');
function model(candidate, status = 'running', validationMode = 'full') {
  const context = vm.createContext({candidate, state: {task: {status, mode: 'live', repair_request:{validation_mode:validationMode}}}, active: ['queued', 'running', 'cancelling']});
  vm.runInContext(source, context);
  return vm.runInContext('resultValidationModel(candidate)', context);
}
function candidate(preparation) {
  return {live_validation_progress: {
    running: true,
    stage_status: {patch_apply: 'passed', compile: 'not_run', poc: 'not_run', unit: 'not_run', source_prepare: preparation.status},
    stage_details: {
      patch_apply: {operation: 'exact_original_source_application', duration_seconds: .0006},
      source_prepare: preparation,
    },
  }};
}
const applied = {step: 'build_and_poc', status: 'passed', boundary: 'apply', declared_covers: ['compile', 'poc']};
const preparing = {status: 'running', steps: [{step: 'build_and_poc', status: 'running'}]};

test('local diff precheck does not pass the container application card', () => {
  const input = candidate(preparing), before = JSON.stringify(input);
  const result = model(input), stage = result.stages[1];
  assert.equal(result.stages[0].status, 'running');
  assert.equal(stage.status, 'queued');
  assert.equal(stage.duration, null);
  assert.equal(result.passed, 0);
  assert.equal(stage.detail.duration_seconds, .0006);
  assert.equal(JSON.stringify(input), before);
});

test('a verified current container install boundary passes application without borrowing host timing', () => {
  const stage = model(candidate({status: 'passed', steps: [applied]})).stages[1];
  assert.equal(stage.status, 'passed');
  assert.equal(stage.duration, null);
  assert.equal(stage.stepName, 'build_and_poc');
});

test('unit container preparation cannot inherit the build container install', () => {
  const input = candidate({status: 'running', steps: [applied, {step: 'unit', status: 'running'}]});
  Object.assign(input.live_validation_progress.stage_status, {compile: 'passed', poc: 'passed'});
  let result = model(input);
  assert.equal(result.stages[1].status, 'queued');
  assert.equal(result.stages[1].stepName, 'unit');
  assert.equal(result.stages[2].status, 'passed');
  assert.equal(result.stages[3].status, 'passed');
  const prep = input.live_validation_progress.stage_details.source_prepare;
  Object.assign(prep.steps[1], {status: 'passed', boundary: 'apply'});
  prep.status = 'passed';
  input.live_validation_progress.stage_status.source_prepare = 'passed';
  result = model(input);
  assert.equal(result.stages[1].status, 'passed');
});

test('missing install evidence cannot imply application success', () => {
  for (const prep of [{status: 'error', steps: []}, {status: 'passed', steps: []}, {status: 'passed', steps: [{status: 'passed'}]}]) {
    assert.equal(model(candidate(prep)).stages[1].status, 'not_run');
  }
});

test('native application failures and errors remain visible', () => {
  for (const status of ['failed', 'error']) {
    const input = candidate(preparing);
    input.live_validation_progress.stage_status.patch_apply = status;
    assert.equal(model(input).stages[1].status, status);
  }
});

test('completed saved validations use install evidence with immutable native metrics', () => {
  const input = candidate({status: 'passed', steps: [applied]});
  const result = {success: true, stage_details: input.live_validation_progress.stage_details,
    stage_status: {patch_apply: 'passed', compile: 'passed', poc: 'passed', unit: 'passed'}};
  const before = JSON.stringify(result), output = model({validation_result: result}, 'completed');
  assert.equal(output.passed, 4);
  assert.equal(output.stages[1].duration, null);
  assert.equal(JSON.stringify(result), before);
});

test('local or historical records without container preparation retain their native meaning', () => {
  const validation_result = {stage_status: {patch_apply: 'passed'}, stage_details: {
    patch_apply: {operation: 'exact_original_source_application', duration_seconds: .0006},
  }};
  const result = model({validation_result}, 'completed');
  assert.equal(result.stages[0].status, 'not_recorded');
  assert.equal(result.stages[1].status, 'passed');
  assert.equal(result.stages[1].duration, .0006);
});

test('shared command focus follows the actual running boundary', () => {
  const input=candidate({status:'passed',steps:[applied]});
  Object.assign(input.live_validation_progress.stage_status,{compile:'running',poc:'running'});
  const context=vm.createContext({state:{task:{status:'running'}},active:['running'],candidate:input});
  vm.runInContext(source,context);
  assert.equal(vm.runInContext('validationFocus(resultValidationModel(candidate)).id',context),'compile');
  assert.equal(vm.runInContext("resultValidationModel(candidate).stages.filter(s=>s.status==='running').length",context),2);
  input.live_validation_progress.stage_status.source_prepare='running';
  input.live_validation_progress.stage_details.source_prepare={status:'running',steps:[applied,{step:'unit',status:'running'}]};
  Object.assign(input.live_validation_progress.stage_status,{compile:'passed',poc:'passed',unit:'not_run'});
  assert.equal(vm.runInContext('validationFocus(resultValidationModel(candidate)).id',context),'source_prepare');
});

test('cancelled and interrupted snapshots preserve finished stages and stop active ones', () => {
  for(const status of ['cancelled','interrupted']){
    const input=candidate({status:'passed',steps:[applied]});
    input.live_validation_progress.stage_status.compile='running';
    const output=model(input,status);
    assert.equal(output.working,false);
    assert.equal(output.stages[1].status,'passed');
    assert.equal(output.stages[2].status,status);
    assert.equal(output.title,'Validation interrupted');
    assert.ok(!output.stages.some(s=>s.status==='running'));
  }
});

test('retry progress takes precedence over earlier successful result', () => {
  const input=candidate(preparing);
  input.validation_result={success:true,stage_status:{compile:'passed',poc:'passed',unit:'passed',patch_apply:'passed'}};
  const output=model(input);
  assert.equal(output.result.success,false);
  assert.equal(output.passed,0);
  assert.equal(output.progress,input.live_validation_progress);
});

test('output panel can hide duplicate logs without removing native log evidence', () => {
  const detail={stdout:'saved output',stderr:'saved diagnostic',command:'make check',exit_code:0};
  const context=vm.createContext({stage:{id:'unit',detail},icon:()=>'',esc:s=>String(s??'')});
  vm.runInContext(source,context);
  const html=vm.runInContext('reviewOutput(stage,{logs:false})',context);
  assert.ok(!html.includes('review-log-block'));
  assert.ok(html.includes('saved output')&&html.includes('saved diagnostic'));
  assert.equal(detail.stdout,'saved output');
});

function scopedCandidate() {
  return {patch:'--- a/source.c\n+++ b/source.c\n@@ -1 +1 @@\n-old\n+new\n',
    validation_result:{success:false,selected_checks_passed:true,
      stage_status:{patch_apply:'passed',compile:'passed',poc:'passed',unit:'not_run'},stage_details:{}}};
}

function render(candidate, mode, expression='validationReviewPanel()') {
  const context = vm.createContext({candidate,state:{task:{status:'completed',mode:'live',file:'source.c',source:'old\n',repair_request:{validation_mode:mode}}},
    active:['queued','running','cancelling'],esc:s=>String(s??''),icon:()=>'',pill:s=>String(s??''),
    currentCandidate:()=>candidate,activeValidationCandidate:()=>null,candidateBar:()=>'',
    empty:(title,summary)=>`${title} ${summary}`});
  vm.runInContext(source,context);
  return vm.runInContext(expression,context);
}

test('PoC scope displays only the selected checks without claiming full success', () => {
  const candidate=scopedCandidate(),before=JSON.stringify(candidate),result=model(candidate,'completed','poc');
  assert.equal(result.mode,'poc');
  assert.equal(result.selectedPassed,true);
  assert.equal(result.checkCount,3);
  assert.equal(result.passed,3);
  assert.deepEqual(Array.from(result.stages,s=>s.id),['source_prepare','patch_apply','compile','poc']);
  assert.equal(result.title,'PoC checks passed');
  assert.equal(result.result.success,false);
  assert.equal(JSON.stringify(candidate),before);
  const html=render(candidate,'poc');
  assert.ok(html.includes('PoC checks passed')&&html.includes('<small> / 3</small>'));
  assert.ok(html.includes('3 / 4 steps passed'));
  assert.ok(!html.includes('Unit Tests')&&!html.includes('All configured checks passed'));
  const patch=render(candidate,'poc','patchReviewPanel()');
  assert.ok(patch.includes('3 / 3 selected checks passed'));
  assert.ok(!patch.includes('4 / 4')&&!patch.includes('Unit Tests'));
});

test('a scoped success flag cannot hide a missing or failed requested check', () => {
  for(const status of ['failed','not_run']){
    const candidate=scopedCandidate();candidate.validation_result.stage_status.poc=status;
    const result=model(candidate,'completed','poc');
    assert.equal(result.selectedPassed,false);
    assert.notEqual(result.title,'PoC checks passed');
  }
});

test('PoC retry progress hides previously successful evidence and unrequested unit progress', () => {
  const input=candidate(preparing);
  input.validation_result=scopedCandidate().validation_result;
  input.live_validation_progress.stage_status.unit='running';
  const result=model(input,'running','poc');
  assert.equal(result.selectedPassed,false);
  assert.equal(result.passed,0);
  assert.ok(!result.stages.some(s=>s.id==='unit'));
});

test('patch-only displays no check timeline, action or historical pass claim', () => {
  const candidate=scopedCandidate();
  candidate.validation_result.success=true;
  candidate.validation_result.stage_status.unit='passed';
  const before=JSON.stringify(candidate),result=model(candidate,'completed','patch_only');
  assert.equal(result.notRequested,true);
  assert.equal(result.checkCount,0);
  assert.equal(result.selectedPassed,false);
  assert.equal(result.stages.length,0);
  assert.equal(result.title,'Validation not requested');
  for(const html of [render(candidate,'patch_only'),render(candidate,'patch_only','patchReviewPanel()')]){
    assert.ok(html.includes('No validation checks are included'));
    assert.ok(!html.includes('Validate Patch')&&!html.includes('validate-candidate'));
    assert.ok(!html.includes('Unit Tests')&&!html.includes('Checks passed'));
  }
  assert.equal(JSON.stringify(candidate),before);
});

test('full validation still requires the unit check and retains four-check display', () => {
  const candidate=scopedCandidate();
  assert.equal(model(candidate,'completed').selectedPassed,false);
  candidate.validation_result.success=true;
  candidate.validation_result.stage_status.unit='passed';
  const result=model(candidate,'completed');
  assert.equal(result.selectedPassed,true);
  assert.equal(result.checkCount,4);
  assert.equal(result.title,'All configured checks passed');
  const html=render(candidate,'full');
  assert.ok(html.includes('Unit Tests')&&html.includes('<small> / 4</small>'));
});
