const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {join}=require('node:path');
const vm=require('node:vm');

function setup(){
 const nodes=new Map(),calls=[],modals=[],notices=[],opened=[];
 const c=vm.createContext({setTimeout,clearTimeout,URL,console,btoa:value=>Buffer.from(value,'binary').toString('base64')});
 vm.runInContext(readFileSync(join(__dirname,'../../studio/web/app.js'),'utf8'),c);
 Object.assign(c,{
  document:{querySelector:s=>nodes.get(s)||null,getElementById:id=>nodes.get('#'+id)||null},
  requestAnimationFrame:fn=>fn(),
  openModal:(...args)=>modals.push(args),
  closeModal:()=>vm.runInContext('state.modal=null',c),
  openTask:async id=>opened.push(id),toast:s=>notices.push(s),fail:e=>{throw e},
  api:async(path,options)=>{calls.push({path,options});return path==='/repositories'?{items:[]}:{id:'new-run'}}
 });
 vm.runInContext(readFileSync(join(__dirname,'../../studio/web/repository-task.js'),'utf8'),c);
 const run=code=>vm.runInContext(code,c);
 const target={id:'target-one',case_key:'Vul4c:CVE-1234',file:'src/parser.c',revision:'deadbeef',language:'C',target_label:'Parser integer overflow',poc_file:'/tests/crash.bin',unit_test:'/tests/unit',replay_source_id:'recorded-run',validation_modes:['patch_only','poc','full']};
 const resolved={repository_url:'https://github.com/project/parser',project:'project/parser',targets:[target]};
 c.fixture=resolved;
 async function configure(){await run('openRepositoryTask()');run("repositoryTaskState.resolved=fixture;repositoryTaskState.url=fixture.repository_url;repositoryApplyTarget('target-one')");}
 return {c,run,nodes,calls,modals,notices,opened,target,resolved,configure};
}

test('repository entry replaces the CVE picker and starts with a required URL',async()=>{
 const {run,modals,calls}=setup();await run('openRepositoryTask()');
 assert.match(modals[0][2],/Git repository URL/);
 assert.match(modals[0][2],/id="repo-url"[^>]*required/);
 assert.doesNotMatch(modals[0][2],/Search CVE|case-option|Available repositories|repo-suggestions|repository-suggestion/);
 assert.equal(calls.length,0);
 assert.equal(run('repositoryTaskState.validationMode'),'patch_only');
});

test('multiple source targets require selection instead of silently choosing the first CVE',async()=>{
 const {c,run,resolved,modals}=setup();await run('openRepositoryTask()');
 resolved.targets.push({...resolved.targets[0],id:'target-two',target_label:'Separate decode boundary'});
 c.api=async()=>resolved;run("repositoryTaskState.url='https://github.com/project/parser'");await run('resolveRepositoryTask()');
 assert.equal(run('repositoryTaskState.targetId'),'');
 assert.equal(run('repositoryTaskValuesComplete()'),false);
 assert.match(modals.at(-1)[2],/selection required/);
 assert.match(modals.at(-1)[2],/Separate decode boundary/);
});

test('one target fills its pinned source and uses a matching saved run when available',async()=>{
 const {c,run,resolved}=setup();await run('openRepositoryTask()');c.api=async()=>resolved;
 run("repositoryTaskState.url='https://github.com/project/parser'");await run('resolveRepositoryTask()');
 assert.equal(run('repositoryTaskState.file'),'src/parser.c');
 assert.equal(run('repositoryTaskState.revision'),'deadbeef');
 assert.equal(run('repositoryTaskState.mode'),'replay');
 assert.equal(run('repositoryTaskValidationError()'),'');
});

test('the configured libtiff baseline is selected on every connection without a CVE or picker',async()=>{
 const {c,run,resolved,target,modals,calls}=setup();
 Object.assign(target,{id:'target-libtiff',case_key:'Vul4c:CVE-2016-10267',file:'libtiff/tif_ojpeg.c',revision:'b28076b056eba9d665881bab139d21b21137fd2d',target_label:'libtiff/tif_ojpeg.c',demo_source_task_id:'successful-run',replay_source_id:'successful-run'});
 Object.assign(resolved,{repository_url:'https://github.com/vadz/libtiff',project:'libtiff'});
 c.api=async(path,options)=>{calls.push({path,options});return path==='/repositories'?{items:[]}:path==='/repositories/resolve'?resolved:{id:'new-run'}};
 for(const url of ['https://github.com/vadz/libtiff','https://github.com/vadz/libtiff.git/']){
  await run('openRepositoryTask()');c.inputUrl=url;run('repositoryTaskState.url=inputUrl');await run('resolveRepositoryTask()');
  assert.equal(run('repositoryTaskState.targetId'),'target-libtiff');
  assert.equal(run('repositoryTaskState.file'),'libtiff/tif_ojpeg.c');
  assert.equal(run('repositoryTaskState.validationMode'),'full');
  assert.equal(run('repositoryTaskState.testSource'),'upload');
  assert.equal(run('repositoryTaskState.mode'),'live');
  assert.equal(run('repositoryTaskValuesComplete()'),false);
  assert.doesNotMatch(modals.at(-1)[2],/CVE-|Choose a source baseline|selection required|repository-target/);
  assert.doesNotMatch(modals.at(-1)[2]+modals.at(-1)[3],/Full workflow demo|Start Demo|Saved successful patch|Saved run selected/);
  assert.match(modals.at(-1)[3],/Start Repair/);
  assert.match(modals.at(-1)[2],/Patch \+ PoC/);
  assert.match(modals.at(-1)[2],/Patch \+ full tests/);
  assert.match(modals.at(-1)[2],/id="repo-poc-upload"/);
  assert.match(modals.at(-1)[2],/id="repo-unit-upload"/);
  await run("repositoryTaskClick({dataset:{action:'repository-test-source',source:'prepared'}})");
  assert.equal(run('repositoryTaskValuesComplete()'),true);
  await run('startRepositoryTask()');
  const body=JSON.parse(calls.filter(call=>call.path==='/tasks').at(-1).options.body);
  assert.equal(body.target_id,'target-libtiff');assert.equal(body.vulnerable_file,'libtiff/tif_ojpeg.c');
  assert.equal(body.mode,'live');assert.equal(body.validation_mode,'full');assert.equal(body.automatic,true);
  assert.equal(body.poc_file,target.poc_file);assert.equal(body.unit_test,target.unit_test);
  assert.ok(!body.poc_upload_id&&!body.unit_upload_id);
 }
});

test('the fixed sample accepts PoC and unit uploads through the normal repair form',async()=>{
 const {c,configure,run,calls,target}=setup();
 Object.assign(target,{demo_source_task_id:'successful-run',uploaded_poc_data:true});
 await configure();
 c.api=async(path,options)=>{calls.push({path,options});return path==='/test-inputs'?{id:JSON.parse(options.body).kind+'-receipt',filename:JSON.parse(options.body).filename,size:3}:{id:'new-run'}};
 c.pocFile={name:'crash.tiff',size:3,arrayBuffer:async()=>Uint8Array.from([1,2,3]).buffer};
 c.unitFile={name:'unit.sh',size:3,arrayBuffer:async()=>Uint8Array.from([97,98,99]).buffer};
 await run("uploadRepositoryInput('poc',pocFile)");
 assert.equal(run('repositoryTaskValuesComplete()'),false);
 await run("uploadRepositoryInput('unit',unitFile)");
 assert.equal(run('repositoryTaskValuesComplete()'),true);
 await run('startRepositoryTask()');
 const body=JSON.parse(calls.find(call=>call.path==='/tasks').options.body);
 assert.equal(body.poc_upload_id,'poc-receipt');assert.equal(body.unit_upload_id,'unit-receipt');
 assert.equal(body.validation_mode,'full');assert.equal(body.poc_file,'');assert.equal(body.unit_test,'');
});

test('required PoC and unit references follow the selected validation scope',async()=>{
 const {configure,run}=setup();await configure();
 run("repositoryTaskState.testSource='prepared';repositoryTaskState.poc='';repositoryTaskState.unit=''");
 assert.equal(run('repositoryTaskValuesComplete()'),true);
 run("repositoryTaskState.validationMode='poc'");assert.equal(run('repositoryTaskValuesComplete()'),false);
 run("repositoryTaskState.poc='/tests/crash.bin'");assert.equal(run('repositoryTaskValuesComplete()'),true);
 run("repositoryTaskState.validationMode='full'");assert.equal(run('repositoryTaskValuesComplete()'),false);
 run("repositoryTaskState.unit='/tests/unit'");assert.equal(run('repositoryTaskValuesComplete()'),true);
 assert.match(run('repositoryTestInputsHtml()'),/PoC file or test entry/);
 assert.match(run('repositoryTestInputsHtml()'),/Unit-test suite \/ entry/);
});

test('patch-only submission includes source identity, scope and automatic execution without unused test inputs',async()=>{
 const {configure,run,calls,opened}=setup();await configure();await run('startRepositoryTask()');
 const request=calls.find(call=>call.path==='/tasks');assert.ok(request);
 const body=JSON.parse(request.options.body);
 assert.deepEqual(body,{repository_url:'https://github.com/project/parser',target_id:'target-one',vulnerable_file:'src/parser.c',revision:'deadbeef',validation_mode:'patch_only',poc_file:'',unit_test:'',variant:'full',mode:'replay',automatic:true});
 assert.deepEqual(opened,['new-run']);
});

test('the prepared-test option rejects an arbitrary path and points to actual uploads',async()=>{
 const {configure,run,calls}=setup();await configure();
 run("repositoryTaskState.testSource='prepared';repositoryTaskState.validationMode='poc';repositoryTaskState.poc='/home/user/new-poc.bin'");await run('startRepositoryTask()');
 assert.equal(calls.filter(call=>call.path==='/tasks').length,0);
 assert.match(run('repositoryTaskState.error'),/Choose Upload files/);
});

test('a changed vulnerable revision cannot silently use a different baseline',async()=>{
 const {configure,run,calls}=setup();await configure();
 run("repositoryTaskState.revision='main'");await run('startRepositoryTask()');
 assert.equal(calls.filter(call=>call.path==='/tasks').length,0);
 assert.match(run('repositoryTaskState.error'),/revision must match/);
});

test('input edits update drafts without rebuilding the modal or dropping focus',async()=>{
 const {configure,run,modals,nodes}=setup();await configure();
 const submit={disabled:false};nodes.set('#repo-start',submit);const count=modals.length;
 run("repositoryTaskInput({target:{id:'repo-file',value:''}})");
 assert.equal(modals.length,count);assert.equal(submit.disabled,true);
 assert.equal(run('repositoryTaskState.file'),'');
});

test('a non-full repair strategy switches to live execution',async()=>{
 const {configure,run}=setup();await configure();
 run("repositoryTaskChange({target:{id:'repo-variant',value:'df_only'}})");
 assert.equal(run('repositoryTaskState.mode'),'live');
 assert.equal(run('repositoryTaskCanUseSaved()'),false);
});

test('a closed modal ignores an in-flight repository resolution response',async()=>{
 const {c,run,resolved,modals}=setup();await run('openRepositoryTask()');
 let finish;c.api=()=>new Promise(resolve=>finish=resolve);
 run("repositoryTaskState.url='https://github.com/project/parser'");const pending=run('resolveRepositoryTask()');
 const count=modals.length;run('state.modal=null');finish(resolved);await pending;
 assert.equal(modals.length,count);assert.equal(run('repositoryTaskState.resolved'),null);
});

test('rendered repository metadata is escaped',async()=>{
 const {configure,run,resolved}=setup();await configure();
 resolved.targets.push({...resolved.targets[0],id:'target-two',file:'<img src=x>',target_label:'<script>alert(1)</script>'});
 const html=run('repositoryTargetOptions()');
 assert.match(html,/&lt;img src=x&gt;/);assert.match(html,/&lt;script&gt;/);assert.doesNotMatch(html,/<script>/);
});

test('a new aligned task reuses the stored repository request and selects the exact case',async()=>{
 const {c,run,resolved}=setup();const paths=[];
 run("state.task={case_key:'Vul4c:CVE-1234',repair_request:{repository_url:'https://github.com/project/parser'}}");
 resolved.targets.push({...resolved.targets[0],id:'different',case_key:'Vul4c:CVE-4567'});
 c.api=async(path)=>{paths.push(path);return path==='/repositories'?{items:[]}:resolved};
 await run("openRepositoryTask('Vul4c:CVE-1234')");
 assert.equal(run('repositoryTaskState.targetId'),'target-one');assert.ok(!paths.includes('/cases'));
});

test('a legacy aligned task uses authoritative case repository metadata, not its package label',async()=>{
 const {c,run,resolved}=setup();
 c.api=async(path)=>path==='/repositories'?{items:[]}:path==='/cases'?{items:[{key:'Vul4c:CVE-1234',project:'parser',repository_url:resolved.repository_url}]}:resolved;
 await run("openRepositoryTask('Vul4c:CVE-1234')");
 assert.equal(run('repositoryTaskState.url'),resolved.repository_url);
 assert.equal(run('repositoryTaskState.targetId'),'target-one');
});

test('an unmapped package name never triggers a guessed repository resolution',async()=>{
 const {c,run}=setup();const paths=[];
 c.api=async(path)=>{paths.push(path);return path==='/repositories'?{items:[]}:{items:[{key:'Vul4c:CVE-1234',project:'parser'}]}};
 await run("openRepositoryTask('Vul4c:CVE-1234')");
 assert.equal(run('repositoryTaskState.url'),'');assert.ok(!paths.includes('/repositories/resolve'));
});

test('PoC mode defaults to required uploads and forces live execution',async()=>{
 const {configure,run}=setup();await configure();
 run("repositoryTaskChange({target:{name:'repo-validation-mode',value:'poc'}})");
 assert.equal(run('repositoryTaskState.testSource'),'upload');
 assert.equal(run('repositoryTaskState.mode'),'live');
 assert.equal(run('repositoryTaskValuesComplete()'),false);
 assert.match(run('repositoryTestInputsHtml()'),/type="file" id="repo-poc-upload"/);
 assert.equal(run('repositoryTaskCanUseSaved()'),false);
});

test('a real upload sends base64 file bytes and the task uses its receipt ID',async()=>{
 const {c,configure,run,calls}=setup();await configure();
 run("repositoryTaskChange({target:{name:'repo-validation-mode',value:'poc'}})");
 c.file={name:'check.sh',size:3,arrayBuffer:async()=>Uint8Array.from([97,98,99]).buffer};
 c.api=async(path,options)=>{calls.push({path,options});return path==='/test-inputs'?{id:'upload-poc',kind:'poc',filename:'check.sh',size:3,sha256:'sha'}:{id:'new-run'}};
 await run("uploadRepositoryInput('poc',file)");
 const upload=calls.find(call=>call.path==='/test-inputs');
 assert.deepEqual(JSON.parse(upload.options.body),{kind:'poc',filename:'check.sh',content_base64:'YWJj'});
 assert.equal(run('repositoryTaskValuesComplete()'),true);
 await run('startRepositoryTask()');const task=JSON.parse(calls.find(call=>call.path==='/tasks').options.body);
 assert.equal(task.poc_upload_id,'upload-poc');assert.equal(task.poc_file,'');assert.equal(task.mode,'live');assert.ok(!('unit_upload_id' in task));
});

test('full validation requires both uploaded files before the task can start',async()=>{
 const {configure,run}=setup();await configure();
 run("repositoryTaskChange({target:{name:'repo-validation-mode',value:'full'}});repositoryTaskState.uploads.poc={id:'poc'}");
 assert.equal(run('repositoryTaskValuesComplete()'),false);
 run("repositoryTaskState.uploads.unit={id:'unit'}");assert.equal(run('repositoryTaskValuesComplete()'),true);
});

test('unsupported unit inputs and oversized files are rejected before upload',async()=>{
 const {c,configure,run,calls}=setup();await configure();
 c.file={name:'tests.zip',size:100};await run("uploadRepositoryInput('unit',file)");
 assert.match(run('repositoryTaskState.uploadErrors.unit'),/\.sh or \.py/);
 c.file={name:'large.sh',size:11*1024*1024};await run("uploadRepositoryInput('poc',file)");
 assert.match(run('repositoryTaskState.uploadErrors.poc'),/10 MiB/);
 assert.equal(calls.filter(call=>call.path==='/test-inputs').length,0);
});

test('raw PoC data is allowed only when the matched target provides a data runner',async()=>{
 const {c,configure,run,target}=setup();await configure();
 c.file={name:'crash.tiff',size:1,arrayBuffer:async()=>Uint8Array.from([1]).buffer};
 await run("uploadRepositoryInput('poc',file)");assert.match(run('repositoryTaskState.uploadErrors.poc'),/\.sh or \.py/);
 target.uploaded_poc_data=true;c.api=async()=>({id:'raw-poc',filename:'crash.tiff',size:1,kind:'poc'});
 await run("uploadRepositoryInput('poc',file)");assert.equal(run('repositoryTaskState.uploads.poc.id'),'raw-poc');
});

test('switching source baselines clears uploaded tests and invalidates pending results',async()=>{
 const {c,configure,run,target}=setup();await configure();
 c.file={name:'check.sh',size:1,arrayBuffer:async()=>Uint8Array.from([1]).buffer};
 let finish;c.api=()=>new Promise(resolve=>finish=resolve);
 const pending=run("uploadRepositoryInput('poc',file)");await new Promise(resolve=>setImmediate(resolve));
 run("repositoryApplyTarget('target-one')");finish({id:'old-upload',filename:'check.sh',size:1,kind:'poc'});await pending;
 assert.equal(run('repositoryTaskState.uploads.poc'),null);assert.equal(run('repositoryTaskState.uploading.poc'),false);
});
