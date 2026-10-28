const {test} = require('node:test');
const assert = require('node:assert/strict');
const {readFileSync, readdirSync} = require('node:fs');
const {join} = require('node:path');
const vm = require('node:vm');
const web = join(__dirname, '../../studio/web');

test('interface templates use English, including document language and labels', () => {
  for (const name of readdirSync(web).filter(n => /\.(js|html)$/.test(n) && n !== 'legacy-messages.js')) {
    assert.doesNotMatch(readFileSync(join(web, name), 'utf8'), /[\u3400-\u9fff]/, name);
  }
  assert.match(readFileSync(join(web, 'index.html'), 'utf8'), /<html lang="en"/);
});

test('historical platform messages retain their identifiers and timing in English', () => {
  const c = vm.createContext({});
  vm.runInContext(readFileSync(join(web, 'legacy-messages.js'), 'utf8'), c);
  const cases = [
    ['候选 2 的修复与验证记录已保存', 'Repair and validation records saved for candidate 2'],
    ['候选 8 · 全部验证通过', 'Candidate 8 · All checks passed'],
    ['候选补丁 8 已进入验证队列', 'Candidate patch 8 queued for validation'],
    ['build_and_poc 源码准备超时（600s）', 'build_and_poc Source preparation timed out (600s)'],
    ['回放 · 编译检查', 'Build Check'],
    ['演示回放：复用真实历史任务 abc123，不调用模型或容器', 'Demo replay: using real historical task abc123 without model or container calls'],
  ];
  for (const [original, expected] of cases) {
    c.message = original;
    assert.equal(vm.runInContext('uiMessage(message)', c), expected);
    assert.equal(c.message, original);
  }
});

test('display translation preserves unknown text and does not return unescaped markup', () => {
  const c = vm.createContext({});
  for (const name of ['legacy-messages.js', 'app.js']) vm.runInContext(readFileSync(join(web, name), 'utf8'), c);
  for (const message of ['Unknown native failure: E42', '用户代码标识符', '<img src=x onerror=alert(1)>']) {
    c.message = message;
    assert.equal(vm.runInContext('uiMessage(message)', c), message);
  }
  assert.equal(vm.runInContext('esc(uiMessage(message))', c), '&lt;img src=x onerror=alert(1)&gt;');
});
