// Run with: node tests/test_autopilot_ui.js (no browser dependencies required).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
class Element {
  constructor(tag, className, text) { Object.assign(this, {tag, className, textContent: text, children: [], events: {}, value: '', disabled: false}); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  addEventListener(event, handler) { this.events[event] = handler; }
  all() { return [this, ...this.children.flatMap(c => c.all())]; }
}
const elements = new Map();
const $ = selector => { if (!elements.has(selector)) elements.set(selector, new Element('div')); return elements.get(selector); };
const calls = [];
let scan = {id: 'scan-a', status: 'completed', config: {target: 'https://example.test/'}};
const context = vm.createContext({
  $, current: scan,
  node: (tag, className, text) => new Element(tag, className, text),
  loadModels() {}, renderFindings() {}, renderAssessment() {},
  async api(path, body) {
    calls.push({path, body});
    if (!body) return scan;
    if (body.action === 'plan') return {proposal: {id: 'next', action: 'done', reason: 'Finished'}, history: []};
    if (body.action === 'repair') return {proposal: {id: 'prepared', action: 'run', command: 'printf prepared'}, history: []};
    scan = {...scan, autopilot: {steps: [], proposal: null}};
    return {added: 0};
  }
});
const source = fs.readFileSync('spidy/static/app.js', 'utf8');
vm.runInContext(source.slice(source.indexOf('let autopilotBusy'), source.indexOf('let llmModelsLoaded')), context);
const proposal = {id: 'proposal-a', action: 'run', command: 'printf original', reason: 'Local check'};
const find = (tag, text) => $('#autopilot-proposal').all().find(e => e.tag === tag && (text === undefined || e.textContent === text));
(async () => {
  $('#autopilot-model').value = 'local';
  context.renderProposal(proposal);
  assert.equal(calls.length, 0, 'rendering must never execute');
  assert.equal(find('textarea'), undefined);
  assert.equal(find('pre').textContent, 'printf original');
  await find('button', 'Approve & run').events.click();
  const run = calls.find(c => c.body?.action === 'run');
  assert.equal(run.path, '/api/scans/scan-a/autopilot');
  assert.equal(run.body.command, 'printf original');
  assert.equal(run.body.approved, true);
  assert.equal(run.body.proposal_id, 'proposal-a');
  assert.equal(calls.filter(c => c.body?.action === 'run').length, 1);
  context.renderProposal({id: 'manual', action: 'manual', instructions: 'Investigate this'});
  assert.equal(find('button', 'Approve & run'), undefined);
  assert.equal(find('button', 'Prepare runnable action').disabled, false);
  assert.equal(find('textarea'), undefined);
  await find('button', 'Prepare runnable action').events.click();
  assert.equal(calls.at(-1).body.action, 'repair');
  assert.equal(calls.at(-1).body.proposal_id, 'manual');
  assert.equal(find('button', 'Approve & run').disabled, false);
  assert.equal(find('pre').textContent, 'printf prepared');
  assert.equal(calls.filter(c => c.body?.action === 'run').length, 1, 'preparation must not execute');
  await find('button', 'Stop').events.click();
  assert.equal(calls.at(-2).body.action, 'stop');
  assert.equal(calls.filter(c => c.body?.action === 'run').length, 1, 'stop must not run');
  context.renderProposal({id: 'paused', action: 'paused', reason: 'The model kept repeating completed work.'});
  assert.equal(find('button', 'Approve & run'), undefined);
  assert.equal(find('button', 'Prepare runnable action'), undefined);
  assert.equal(find('p').textContent, 'The model kept repeating completed work.');
  context.renderProposal(proposal);
  context.current = {...scan, id: 'scan-b'};
  const before = calls.length;
  await find('button', 'Approve & run').events.click();
  assert.equal(calls.length, before, 'a proposal must not execute against a newly selected assessment');
  console.log('Autopilot UI checks passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
