// Run with: node tests/test_autopilot_ui.js (no browser dependencies required).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
class Element {
  constructor(tag, className, text) { Object.assign(this, {tag, className, textContent: text, children: [], events: {}, value: '', disabled: false, classList: {toggle() {}}}); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  insertBefore(child, before) {
    if (this.children.includes(child)) this.removeChild(child);
    this.children.splice(before ? this.children.indexOf(before) : this.children.length, 0, child);
  }
  addEventListener(event, handler) { this.events[event] = handler; }
  setAttribute(name, value) { this[name] = value; }
  all() { return [this, ...this.children.flatMap(c => c.all())]; }
}
const elements = new Map();
const $ = selector => { if (!elements.has(selector)) elements.set(selector, new Element('div')); return elements.get(selector); };
const calls = [];
const scan = {id: 'scan-a', status: 'completed', config: {target: 'https://example.test/'}};
let releaseRequest = null;
let backendConfig = {planner_protocol: 2, restart_required: false, instance_id: 'server-1'};
const context = vm.createContext({
  $, config: backendConfig, current: {...scan}, guideHint() {}, scheduleRefresh() {},
  node: (tag, className, text) => new Element(tag, className, text),
  loadModels() {}, renderFindings() {}, renderAssessment() {},
  async api(path, body) {
    calls.push({path, body});
    if (path === '/api/config') return backendConfig;
    if (releaseRequest && body?.action === 'run') await new Promise(resolve => { releaseRequest = resolve; });
    if (!body) return {...context.current, autopilot: {steps: [], proposal: null}};
    return {task: {status: 'running', kind: body.action === 'run' ? 'run' : 'plan'}};
  }
});
const source = fs.readFileSync('spidy/static/app.js', 'utf8');
vm.runInContext(source.slice(source.indexOf('function autopilotTaskRunning()'), source.indexOf('function scheduleRefresh()')), context);
vm.runInContext(source.slice(source.indexOf('let autoApproveScanId'), source.indexOf('let llmModelsLoaded')), context);
vm.runInContext(source.slice(source.indexOf('function pickGuideModel'), source.indexOf('// Uncensored models worth')), context);
const proposal = {id: 'proposal-a', action: 'run', command: 'printf original', reason: 'Local check'};
const find = (tag, text) => $('#autopilot-proposal').all().find(e => e.tag === tag && (text === undefined || e.textContent === text));
const runs = () => calls.filter(c => c.body?.action === 'run');
function settle(p = proposal) {
  context.current = {...scan, autopilot: {steps: [], proposal: p, task: null}};
  context.renderAutopilot();
}
async function toggle(checked) {
  $('#autopilot-auto-approve').checked = checked;
  await $('#autopilot-auto-approve').events.change({target: $('#autopilot-auto-approve')});
}
(async () => {
  assert.equal(context.pickGuideModel([{name:'topical-storm',size:2}, {name:'llama3.1',size:5}, {name:'executor',size:6}], 'executor'), 'llama3.1', 'guide selection must not prefer name keywords over size');
  assert.equal(context.pickGuideModel([{name:'executor',size:6}], 'executor'), '', 'one installed model needs no duplicate guide');
  $('#autopilot-model').value = 'local';
  settle();
  assert.equal(calls.length, 0, 'rendering must never execute');
  assert.equal(find('textarea'), undefined);
  assert.equal(find('pre').textContent, 'printf original');
  await find('button', 'Approve & run').events.click();
  assert.equal(runs()[0].path, '/api/scans/scan-a/autopilot');
  assert.equal(runs()[0].body.command, 'printf original');
  assert.equal(runs()[0].body.approved, true);
  assert.equal(runs()[0].body.approval_mode, 'manual');
  assert.equal(runs()[0].body.proposal_id, 'proposal-a');
  settle({id: 'manual', action: 'manual', instructions: 'Investigate this'});
  assert.equal(find('button', 'Approve & run'), undefined);
  await find('button', 'Prepare runnable action').events.click();
  assert.equal(calls.at(-1).body.action, 'repair');
  assert.equal(calls.at(-1).body.proposal_id, 'manual');
  assert.equal(runs().length, 1, 'preparation must not execute');
  settle();
  await find('button', 'Stop').events.click();
  assert.equal(calls.at(-2).body.action, 'stop');
  assert.equal(runs().length, 1, 'stop must not run');
  settle();
  context.current = {...scan, id: 'scan-b'};
  await find('button', 'Approve & run').events.click();
  assert.equal(runs().length, 1, 'stale proposals cannot run on another scan');

  settle();
  releaseRequest = true;
  const enabling = toggle(true);
  context.autoApprovePending();
  await new Promise(setImmediate);
  assert.equal(runs().length, 2, 'overlapping auto submissions run once');
  assert.equal(runs().at(-1).body.approval_mode, 'automatic');
  releaseRequest(); releaseRequest = null;
  await enabling;
  assert.equal(context.autoApprovalEnabled(), true);
  settle({id: 'next', action: 'run', tool: 'katana', options: {depth: '3'}});
  await context.autoApprovePending();
  assert.equal(runs().at(-1).body.options.depth, '3');
  await toggle(false);
  settle();
  context.autopilotSettled({kind: 'plan'});
  assert.equal(runs().length, 3, 'turning off before a proposal settles prevents execution');
  for (const p of [{id: 'draft', action: 'manual'}, {id: 'paused', action: 'paused'},
                   {id: 'done', action: 'done'}, {id: 'prep', action: 'run', needs_preparation: true}]) {
    settle(p);
    const beforePlan = calls.filter(c => ['plan', 'repair'].includes(c.body?.action)).length;
    await toggle(true);
    assert.equal(context.autoApprovalEnabled(), true, 'manual or blocked drafts must not uncheck the toggle');
    assert.equal(calls.at(-1).body.action, p.action === 'manual' || p.needs_preparation ? 'repair' : 'plan');
    assert.equal(calls.filter(c => ['plan', 'repair'].includes(c.body?.action)).length, beforePlan + 1, 'explicit enable starts one planning round');
    settle(p);
    await context.autoApprovePending();
    assert.equal(context.autoApprovalEnabled(), true);
    assert.equal(calls.filter(c => ['plan', 'repair'].includes(c.body?.action)).length, beforePlan + 1, 'blocked planning does not spin in a retry loop');
    assert.equal(runs().length, 3, 'non-runnable proposals never execute');
  }
  settle(null); await toggle(true);
  context.current = {...scan, id: 'scan-b', autopilot: {proposal}};
  await context.autoApprovePending();
  assert.equal(runs().length, 3, 'auto permission belongs to one scan');
  settle(null); await toggle(true);
  context.current.autopilot.task = {status: 'error', error: 'failed'};
  context.autopilotSettled({kind: 'plan'});
  assert.equal(context.autoApprovalEnabled(), true, 'task errors pause work without changing the chosen mode');
  assert.match($('#autopilot-status').textContent, /Auto-approve remains on/);
  settle(null); await toggle(true);
  context.current.autopilot.steps = [{outcome: 'failed', command: 'printf test'}];
  context.autopilotSettled({kind: 'run'});
  assert.equal(context.autoApprovalEnabled(), true, 'failed commands retain the mode while the planner prepares a correction');
  await new Promise(setImmediate);
  const running = {proposal_id: 'terminal-1', command: 'printf test', outcome: 'running'};
  context.current = {...scan, autopilot: {steps: [running], task: {kind: 'run', status: 'running',
    terminal: {command: 'printf test', output: '\u001b[32mfirst\u001b[0m\n<script>literal</script>', exit_code: null}}}};
  context.renderAutopilot();
  let panel = $('#autopilot-steps').children.find(el => el.className === 'executor-terminal');
  assert.ok(panel, 'running command has an expanded terminal');
  assert.equal(panel.terminalStatus.textContent, 'Running');
  assert.equal(panel.terminalOutput.textContent, 'first\n<script>literal</script>', 'ANSI is removed, HTML stays literal text');
  assert.equal(panel.terminalOutput.children.length, 0, 'output cannot inject markup');
  assert.equal($('#autopilot-steps').children[0].className, 'autopilot-feed', 'terminal sits below executor feed');
  panel.terminalOutput.scrollTop = 20;
  panel.terminalOutput.scrollHeight = 600;
  panel.terminalOutput.clientHeight = 200;
  context.current.autopilot.task.terminal.output += '\nnext line';
  context.renderAutopilot();
  assert.equal($('#autopilot-steps').children[1], panel, 'polling preserves terminal element');
  assert.equal(panel.terminalOutput.scrollTop, 20, 'reading earlier output disables automatic scroll');
  panel.terminalOutput.scrollTop = 400;
  panel.terminalOutput.events.scroll();
  context.renderAutopilot();
  assert.equal(panel.terminalOutput.scrollTop, 600, 'following output scrolls to newest text');
  panel.followCheckbox.checked = false;
  panel.followCheckbox.events.change();
  panel.terminalOutput.scrollTop = 400;
  context.renderAutopilot();
  assert.equal(panel.terminalOutput.scrollTop, 400, 'explicitly disabling auto-scroll stays off at the bottom');
  panel.followCheckbox.checked = true;
  panel.followCheckbox.events.change();
  assert.equal(panel.terminalOutput.scrollTop, 600, 'auto-scroll toggle jumps to latest output');

  context.current.autopilot.task = {id: 'plan-scroll', kind: 'plan', status: 'running', stage: 'guide', guide_text: 'Long guide message'};
  context.renderAutopilot();
  const feed = $('#autopilot-steps').children[0];
  Object.assign(feed.output, {scrollTop: 400, scrollHeight: 600, clientHeight: 200});
  feed.output.events.scroll();
  context.current.autopilot.task.guide_text += '\nMore text';
  context.renderAutopilot();
  assert.equal($('#autopilot-steps').children[0], feed, 'guide panel survives streaming updates');
  assert.equal(feed.output.scrollTop, 600, 'guide follows new output by default');
  feed.output.scrollTop = 75;
  feed.output.events.scroll();
  context.current.autopilot.task.stage = 'exec';
  context.renderAutopilot();
  assert.equal(feed.output.scrollTop, 75, 'reading the guide is not interrupted by polling or stage changes');
  assert.equal(feed.followCheckbox.checked, false, 'scrolling up pauses following');
  const more = feed.all().find(el => el.tag === 'button' && el.textContent === 'Show more');
  more.events.click();
  context.renderAutopilot();
  assert.equal(more.textContent, 'Show less', 'expanded panel persists across updates');
  assert.equal(more['aria-expanded'], 'true');
  feed.followCheckbox.checked = true;
  feed.followCheckbox.events.change();
  assert.equal(feed.output.scrollTop, 600, 'guide can resume following');
  context.current = {...context.current, id: 'another-scan'};
  context.renderAutopilot();
  assert.notEqual($('#autopilot-steps').children[0], feed, 'scroll state belongs to one assessment');
  context.current.id = scan.id;
  context.current.autopilot.steps[0] = {...running, outcome: 'ran', meta: {output: 'complete', exit_code: 0}};
  context.current.autopilot.task = {kind: 'plan', status: 'running'};
  context.renderAutopilot();
  panel = $('#autopilot-steps').children.find(el => el.className === 'executor-terminal');
  assert.equal(panel.terminalStatus.textContent, 'Preparing', 'terminal follows the current planning state');
  assert.equal(panel.terminalCommand.textContent, 'No command running');
  context.current.autopilot.task.stage = 'guide_review';
  context.renderAutopilot();
  panel = $('#autopilot-steps').children.find(el => el.className === 'executor-terminal');
  assert.equal(panel.terminalStatus.textContent, 'Guide review');
  assert.match(panel.terminalOutput.textContent, /validation feedback/);
  context.current.autopilot.task = null;
  context.current.autopilot.proposal = {id: 'paused-new', action: 'paused', reason: 'No new action available',
    planning_attempts: [{role: 'guide', proposal: {tool: 'httpx'}, issue: 'Already recorded in step 2'}]};
  context.renderAutopilot();
  panel = $('#autopilot-steps').children.find(el => el.className === 'executor-terminal');
  assert.equal(panel.terminalStatus.textContent, 'Paused');
  assert.match(panel.terminalOutput.textContent, /Planning paused before another command could run/);
  assert.match(panel.terminalOutput.textContent, /No new action available/);
  const attempts = $('#autopilot-proposal').all().find(el => el.className === 'planning-attempts');
  assert.equal(attempts.open, true, 'paused proposals expose the cause instead of hiding the rejected action');
  assert.ok(attempts.all().some(el => el.textContent === 'Already recorded in step 2'));
  context.current.autopilot.proposal.pause_reason = 'model_output';
  context.current.autopilot.proposal.planning_attempts.push({role:'guide',proposal:{instructions:'.gitignore,'.repeat(500)},issue:'Malformed JSON'});
  context.renderAutopilot();
  assert.ok($('#autopilot-proposal').all().some(el => /Unusable model output omitted/.test(el.textContent || '')));
  assert.match(context.planningPauseMessage(context.current.autopilot.proposal), /broken responses were discarded/);
  delete context.current.autopilot.proposal.pause_reason;
  context.current.autopilot.proposal.rejected_repeats = [{matched_steps:[1]}];
  context.current.autopilot.steps[0].meta = {exit_code:0,output:'HTTP/2 403\r\nserver: local\r\n\r\n'};
  const beforeRejectedAuto = runs().length;
  const blockedProposal = context.current.autopilot.proposal;
  await toggle(true);
  assert.equal(runs().length, beforeRejectedAuto, 'auto approval never overrides duplicate checks');
  assert.equal(context.autoApprovalEnabled(), true);
  context.current.autopilot.task = null;
  context.current.autopilot.proposal = blockedProposal;
  await context.autoApprovePending();
  assert.match($('#autopilot-status').textContent, /Next proposal blocked/);
  context.renderAutopilot();
  const receipt = $('#autopilot-steps').all().find(el => el.className === 'execution-receipt');
  assert.ok(receipt.all().some(el => /process completed.*exit 0.*HTTP 403/.test(el.textContent || '')), 'execution outcome remains visible when planning stops');
  context.current.autopilot.proposal = null;
  context.current.autopilot.steps.push({proposal_id: 'legacy', tool: 'nikto', outcome: 'ran', added: 0, meta: {count: 0}});
  context.renderAutopilot();
  panel = $('#autopilot-steps').children.find(el => el.className === 'executor-terminal');
  assert.equal(panel.terminalCommand.textContent, '$ nikto {}', 'legacy step replaces older terminal output');
  assert.notEqual(panel.terminalOutput.textContent, 'complete');
  context.current.autopilot.task = {id: 'starting', kind: 'run', status: 'running', submitted_action: {command: 'printf next'}};
  context.renderAutopilot();
  panel = $('#autopilot-steps').children.find(el => el.className === 'executor-terminal');
  assert.equal(panel.terminalStatus.textContent, 'Starting');
  assert.equal(panel.terminalCommand.textContent, '$ printf next');
  settle();
  const priorRuns = runs().length;
  backendConfig = {}; // New HTML can be served by an old Python process.
  await find('button', 'Approve & run').events.click();
  assert.equal(runs().length, priorRuns, 'an outdated backend must not execute a command');
  assert.match($('#runtime-notice').textContent, /out of sync/);
  backendConfig = {planner_protocol: 2, restart_required: true, instance_id: 'server-1'};
  const priorPlans = calls.filter(c => c.body?.action === 'plan').length;
  await context.autopilotPlan();
  assert.equal(calls.filter(c => c.body?.action === 'plan').length, priorPlans, 'changed backend files require restart before planning');
  context.checkBackend({planner_protocol: 2, restart_required: false, instance_id: 'server-1'});
  backendConfig = {planner_protocol: 2, restart_required: false, instance_id: 'server-2'};
  settle(null); await toggle(true);
  await context.ensureCurrentBackend();
  assert.equal(context.autoApprovalEnabled(), false, 'a server restart clears session auto approval');
  settle(null);
  context.current.autopilot.guide_context = 'Saved context';
  $('#autopilot-guide-context').scanId = null;
  context.renderAutopilot();
  assert.equal($('#autopilot-guide-context').value, 'Saved context');
  $('#autopilot-guide-context').value = 'Draft: inspect cookies';
  $('#autopilot-guide-context').events.input({target: $('#autopilot-guide-context')});
  context.renderAutopilot();
  assert.equal($('#autopilot-guide-context').value, 'Draft: inspect cookies', 'polling preserves typing');
  context.current = {...scan, id: 'scan-b', autopilot: {guide_context: 'Other assessment'}};
  context.renderAutopilot();
  assert.equal($('#autopilot-guide-context').value, 'Other assessment');
  context.current = {...scan, autopilot: {guide_context: 'Saved context'}};
  context.renderAutopilot();
  assert.equal($('#autopilot-guide-context').value, 'Draft: inspect cookies', 'switching back preserves a draft');
  await toggle(true);
  context.current.autopilot.task = null;
  const beforeContextRuns = runs().length;
  await $('#autopilot-send-context').events.click();
  assert.equal(calls.at(-1).body.guide_context, 'Draft: inspect cookies');
  assert.equal(calls.at(-1).body.action, 'plan');
  assert.equal(context.autoApprovalEnabled(), true, 'sending context retains the selected approval mode');
  assert.equal(runs().length, beforeContextRuns, 'context cannot execute a command');
  assert.equal($('#autopilot-send-context').disabled, true, 'sending waits for the current planning task');
  context.current.autopilot.task = null;
  $('#autopilot-guide-context').value = 'Unsent edits';
  await context.autopilotPlan(null, false);
  assert.equal(calls.at(-1).body.guide_context, 'Draft: inspect cookies', 'automatic continuation uses submitted context only');
  settle({...proposal, discussion: [
    {role: 'user', text: '<script>context</script>'},
    {role: 'guide', model: 'guide-model', text: 'Inspect recorded cookies.'},
    {role: 'executor', model: 'exec-model', text: 'Prepare local review.'},
    {role: 'checks', text: 'Duplicate rejected.'}
  ]});
  const messages = $('#autopilot-steps').all();
  assert.ok(messages.some(el => el.textContent === 'Guide · guide-model'));
  assert.ok(messages.some(el => el.textContent === 'Executor · exec-model'));
  assert.ok(messages.some(el => el.textContent === '<script>context</script>'), 'user context is rendered as text');
  console.log('Autopilot UI checks passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
