// Native Firefox BiDi + Node WebSocket; invoked by https_management.py --browser.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { once } from 'node:events';

const config = JSON.parse(await readFile(process.argv[2], 'utf8'));
assert.equal(new URL(config.origin).hostname, 'localhost');
assert.equal(new URL(config.origin).protocol, 'https:');
const profile = await mkdtemp(`${tmpdir()}/cat4igp-firefox-`);
let child, ws;
const pending = new Map();
let id = 0;
async function command(method, params = {}) {
  const request = ++id;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(request); reject(Error(`BiDi timeout: ${method}`)); }, 15000);
    pending.set(request, response => {
      clearTimeout(timer);
      if (response.type === 'error') reject(Error(`BiDi ${method}: ${response.error}`));
      else resolve(response.result);
    });
    ws.send(JSON.stringify({ id: request, method, params }));
  });
}
try {
  execFileSync('certutil', ['-N', '--empty-password', '-d', `sql:${profile}`], { stdio: 'ignore' });
  execFileSync('certutil', ['-A', '-d', `sql:${profile}`, '-n', 'cat4igp test CA', '-t', 'C,,', '-i', config.ca], { stdio: 'ignore' });
  child = spawn('firefox', ['--headless', '--no-remote', '--profile', profile, '--remote-debugging-port', '0'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const exited = once(child, 'exit');
  const address = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error('Firefox startup timeout')), 15000);
    child.on('error', reject);
    child.once('exit', () => { clearTimeout(timer); reject(Error('Firefox exited during startup')); });
    child.stderr.on('data', bytes => {
      const match = bytes.toString().match(/WebDriver BiDi listening on (ws:\/\/\S+)/);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    });
  });
  ws = new WebSocket(`${address}/session`);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = () => reject(Error('BiDi connection failed')); });
  ws.onmessage = event => { const response = JSON.parse(event.data); pending.get(response.id)?.(response); pending.delete(response.id); };
  const session = await command('session.new', { capabilities: { alwaysMatch: { acceptInsecureCerts: false } } });
  assert.equal(session.capabilities.acceptInsecureCerts, false);
  const { context } = await command('browsingContext.create', { type: 'tab' });
  const navigate = url => command('browsingContext.navigate', { context, url, wait: 'complete' });
  async function evaluate(expression) {
    const result = await command('script.evaluate', { expression, target: { context }, awaitPromise: true });
    assert.equal(result.type, 'success', 'browser expression failed (details withheld)');
    return result.result.value;
  }
  assert.equal(new URL(config.cross_origin).hostname, '127.0.0.1');
  await navigate(config.cross_origin); // Both distinct sites have trusted SANs, no TLS bypass.
  await navigate(config.origin);
  async function wait(expression) {
    const deadline = Date.now() + 15000;
    while (!await evaluate(expression)) {
      assert.ok(Date.now() < deadline, 'UI assertion timed out (details withheld)');
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  }
  const click = text => evaluate(`Array.from(document.querySelectorAll('button')).find(b => b.textContent === ${JSON.stringify(text)} || b.getAttribute('aria-label') === ${JSON.stringify(text)}).click()`);
  async function keys(values) {
    await command('input.performActions', { context, actions: [{ type: 'key', id: 'keyboard', actions:
      Array.from(values).flatMap(value => [{ type: 'keyDown', value }, { type: 'keyUp', value }]) }] });
  }
  const tab = () => keys('\uE004');
  const enter = () => keys('\uE007');
  const numberInput = name => `.MuiFormControl-root:has(+ input[name=${name}]) input[type=text]`;
  async function replaceNumber(name, value) {
    await tabTo(numberInput(name), true);
    await command('input.performActions', { context, actions: [{ type: 'key', id: 'keyboard', actions: [
      { type: 'keyDown', value: '\uE009' }, { type: 'keyDown', value: 'a' },
      { type: 'keyUp', value: 'a' }, { type: 'keyUp', value: '\uE009' },
    ] }] });
    await keys('\uE003' + value);
  }
  const numberValue = name => evaluate(`new FormData(document.querySelector('input[name=${name}]').form).get(${JSON.stringify(name)})`);
  async function tabTo(selector, backwards = false) {
    for (let i = 0; i < 40; i++) {
      // Firefox can retain a stale activeElement while its chrome owns focus.
      if (await evaluate(`document.hasFocus() && document.activeElement.matches(${JSON.stringify(selector)})`)) return;
      if (backwards) {
        await command('input.performActions', { context, actions: [{ type: 'key', id: 'keyboard', actions: [
          { type: 'keyDown', value: '\uE008' }, { type: 'keyDown', value: '\uE004' },
          { type: 'keyUp', value: '\uE004' }, { type: 'keyUp', value: '\uE008' },
        ] }] });
      } else await tab();
    }
    assert.fail(`Keyboard could not reach ${selector}`);
  }
  async function labels(selector) {
    assert.equal(await evaluate(`Array.from(document.querySelectorAll(${JSON.stringify(selector)})).every(input =>
      input.labels?.length > 0 && Array.from(input.labels).some(label => label.textContent.trim()))`), true);
  }
  async function outlined(selector) {
    assert.equal(await evaluate(`(() => {
      const input = document.querySelector(${JSON.stringify(selector)});
      const root = input.closest('.MuiOutlinedInput-root');
      const label = input.labels[0];
      const border = getComputedStyle(root.querySelector('.MuiOutlinedInput-notchedOutline'));
      return input.classList.contains('MuiInputBase-input') && label.classList.contains('MuiInputLabel-root') &&
        getComputedStyle(label).position === 'absolute' && border.borderTopStyle === 'solid' &&
        parseFloat(border.borderTopWidth) >= 1 && border.display === 'block' && border.paddingTop === '0px';
    })()`), true, 'MUI floating label and outlined fieldset retain component styles');
  }
  async function tableStyles() {
    assert.equal(await evaluate(`(() => {
      const table = document.querySelector('.inventory table');
      return table.parentElement.classList.contains('MuiTableContainer-root') &&
        getComputedStyle(table.parentElement).overflowX === 'auto' &&
        table.tHead.classList.contains('MuiTableHead-root') && table.tBodies[0].classList.contains('MuiTableBody-root') &&
        Array.from(table.rows).every(row => row.classList.contains('MuiTableRow-root')) &&
        Array.from(table.querySelectorAll('th, td')).every(cell => cell.classList.contains('MuiTableCell-root') &&
          getComputedStyle(cell).paddingTop === '16px' && getComputedStyle(cell).textAlign === 'left' &&
          getComputedStyle(cell).borderBottomStyle === 'solid') &&
        table.querySelector('tbody th').scope === 'row';
    })()`), true, 'MUI table components apply cell alignment, padding and borders');
  }
  async function login() {
    await wait(`!!document.querySelector('input[name=password]')`);
    await labels('.login input');
    assert.equal(await evaluate(`getComputedStyle(document.querySelector('.login button[type=submit]')).backgroundColor`), 'rgb(63, 81, 181)', 'Emotion button styles applied under production CSP');
    await tabTo('input[name=username]');
    await outlined('input[name=username]');
    await wait(`getComputedStyle(document.querySelector('input[name=username]').labels[0]).color === 'rgb(63, 81, 181)'`);
    assert.equal(await evaluate(`document.querySelector('input[name=username]').closest('.MuiOutlinedInput-root').classList.contains('Mui-focused') && getComputedStyle(document.querySelector('input[name=username]').labels[0]).color === 'rgb(63, 81, 181)'`), true, 'focused label uses theme primary');
    await keys(config.username);
    await tab();
    assert.equal(await evaluate(`document.activeElement.name`), 'password');
    await keys(config.password);
    await tab();
    assert.equal(await evaluate(`document.activeElement.textContent`), 'Sign in securely');
    await enter();
    await wait(`!!document.querySelector('.inventory')`);
  }
  const cookies = async () => (await command('storage.getCookies', { filter: { name: '__Host-cat4igp' } })).cookies;
  await wait(`!!document.querySelector('input[name=password]')`);
  assert.equal(await evaluate(`getComputedStyle(document.documentElement).colorScheme`),
    await evaluate(`matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'`));
  if (await evaluate(`getComputedStyle(document.documentElement).colorScheme === 'light'`)) {
    await tabTo('button[aria-label="Switch to dark mode"]', true);
    await enter();
  }
  await wait(`getComputedStyle(document.documentElement).colorScheme === 'dark'`);
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('.sidebar')).backgroundColor`), 'rgb(18, 18, 18)');
  await outlined('input[name=username]');
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('input[name=username]')).color`), 'rgb(255, 255, 255)', 'dark input text remains readable');
  const screenshot = await command('browsingContext.captureScreenshot', { context });
  await writeFile('/tmp/cat4igp-dark-login.png', Buffer.from(screenshot.data, 'base64'));
  await tabTo('button[aria-label="Switch to light mode"]');
  await enter();
  await wait(`getComputedStyle(document.documentElement).colorScheme === 'light'`);
  await navigate(config.origin);
  await wait(`!!document.querySelector('input[name=password]')`);
  assert.equal(await evaluate(`localStorage.getItem('cat4igp-theme')`), 'light');
  await login();
  let stored = await cookies();
  assert.equal(stored.length, 1);
  assert.equal(stored[0].secure, true);
  assert.equal(stored[0].httpOnly, true);
  assert.equal(stored[0].sameSite, 'strict');
  assert.equal(stored[0].domain, 'localhost');
  assert.equal(stored[0].path, '/');
  assert.ok(stored[0].expiry > Date.now()/1000 + 850 && stored[0].expiry < Date.now()/1000 + 910);
  assert.equal(await evaluate(`document.cookie.includes('__Host-cat4igp')`), false);
  assert.equal(await evaluate(`fetch('/admin/me').then(r=>r.status)`), 200);
  await navigate(config.cross_origin);
  await tabTo('a');
  await enter();
  await wait(`!!document.body && (document.body.textContent.includes('unauthorized') || document.body.textContent.includes('Unauthorized'))`);
  await navigate(config.cross_origin);
  await tabTo('form button');
  await enter();
  await wait(`!!document.body && document.body.textContent.includes('untrusted origin')`);
  await navigate(config.origin);
  await wait(`!!document.querySelector('.inventory')`);
  assert.equal(await evaluate(`fetch('/admin/me').then(r=>r.status)`), 200, 'cookie retained after cross-site requests');
  const observed = JSON.parse(await evaluate(`fetch('/__observations').then(r=>r.text())`));
  assert.deepEqual(observed, [
    { method: 'GET', path: '/admin/me?cross-site=get', cookie_seen: false, origin: null, status: 401 },
    { method: 'POST', path: '/admin/login?cross-site=post', cookie_seen: false, origin: config.cross_origin, status: 403 },
  ]);
  await navigate(config.origin);
  await wait(`!!document.querySelector('[aria-label="Nodes inventory"]')`);
  await tabTo('a.skip', true);
  await enter();
  assert.equal(await evaluate(`document.activeElement.id === 'main'`), true, 'skip link focuses main');
  assert.equal(await evaluate(`document.querySelector('nav').getAttribute('aria-label')`), 'Inventory views');
  await tabTo('nav button[aria-label="Meshes"]', true);
  await enter();
  await wait(`document.querySelector('[aria-label="Meshes inventory"]').textContent.includes('HTTPS smoke')`);
  assert.equal(await evaluate(`document.activeElement.tagName === 'H1' && document.activeElement.textContent === 'Meshes'`), true);
  await tableStyles();
  await wait(`document.querySelector('main').getAttribute('aria-busy') === 'false'`);
  await wait(`getComputedStyle(document.querySelector('nav button[aria-current=page]')).backgroundColor !== 'rgba(0, 0, 0, 0)'`);
  assert.equal(await evaluate(`(() => {
    const selected = document.querySelector('nav button[aria-current=page]');
    const panel = document.querySelector('.inventory');
    return selected.getAttribute('aria-label') === 'Meshes' && selected.classList.contains('Mui-selected') &&
      !selected.classList.contains('MuiButton-contained') &&
      selected.querySelector('.view-count').getAttribute('aria-label') === 'Meshes count' &&
      getComputedStyle(selected).backgroundColor !== 'rgba(0, 0, 0, 0)' &&
      document.querySelector('.form-grid button[type=submit]').classList.contains('MuiButton-contained') &&
      getComputedStyle(panel).paddingTop === '24px' && getComputedStyle(panel).marginBottom === '24px' &&
      document.querySelector('main').getAttribute('aria-busy') === 'false';
  })()`), true, 'selected navigation, named count, primary submit and theme panel spacing');
  await command('browsingContext.setViewport', { context, viewport: { width: 390, height: 844 }, devicePixelRatio: 1 });
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('.sidebar')).position === 'static' &&
    getComputedStyle(document.querySelector('.inventory')).paddingTop === '16px' &&
    document.documentElement.scrollWidth <= innerWidth &&
    Array.from(document.querySelectorAll('nav button')).every(b => b.getBoundingClientRect().right <= innerWidth)`), true, 'mobile navigation wraps without page overflow');
  await command('browsingContext.setViewport', { context, viewport: { width: 1280, height: 900 }, devicePixelRatio: 1 });
  await labels('input[name=auto]');
  await tabTo('input[name=auto]');
  assert.equal(await evaluate(`(() => {
    const input = document.querySelector('input[name=auto]');
    return input.closest('.MuiSwitch-switchBase').classList.contains('Mui-checked') &&
      getComputedStyle(input.closest('.MuiSwitch-switchBase')).color === 'rgb(63, 81, 181)' &&
      input.labels[0].classList.contains('MuiFormControlLabel-root') &&
      new FormData(input.form).get('auto') === 'on';
  })()`), true, 'MUI checked styling and native switch FormData');
  await keys(' ');
  assert.equal(await evaluate(`!document.querySelector('input[name=auto]').closest('.MuiSwitch-switchBase').classList.contains('Mui-checked') && !new FormData(document.querySelector('input[name=auto]').form).has('auto')`), true);
  assert.equal(await evaluate(`document.querySelector('input[name=mtu]').disabled && !new FormData(document.querySelector('input[name=auto]').form).has('mtu')`), true);
  assert.equal(await evaluate(`document.querySelector(${JSON.stringify(numberInput('mtu'))}).disabled &&
    Array.from(document.querySelectorAll('button[aria-label$="MTU"]')).every(b => b.disabled && b.type === 'button')`), true);
  assert.equal(await evaluate(`(() => {
    const input = document.querySelector(${JSON.stringify(numberInput('mtu'))});
    const root = input.closest('.MuiOutlinedInput-root');
    return root.classList.contains('Mui-disabled') &&
      input.labels[0].classList.contains('Mui-disabled') &&
      Array.from(root.querySelectorAll('button')).every(button =>
        button.classList.contains('Mui-disabled') && getComputedStyle(button).pointerEvents === 'none');
  })()`), true, 'number label and steppers retain native MUI disabled styling');
  await keys(' ');
  await labels(numberInput('mtu'));
  await outlined(numberInput('mtu'));
  assert.equal(await evaluate(`(() => {
    const number = document.querySelector(${JSON.stringify(numberInput('mtu'))}).closest('.MuiOutlinedInput-root');
    const text = document.querySelector('input[name=name]').closest('.MuiOutlinedInput-root');
    const adornment = number.querySelector('.MuiInputAdornment-root');
    const [up, down] = adornment.querySelectorAll('button');
    const a = up.getBoundingClientRect(), b = down.getBoundingClientRect();
    return number.classList.contains('MuiInputBase-sizeSmall') &&
      Math.abs(number.getBoundingClientRect().height - 40) < 1 &&
      Math.abs(number.getBoundingClientRect().height - text.getBoundingClientRect().height) < 1 &&
      getComputedStyle(adornment).flexDirection === 'column' &&
      getComputedStyle(adornment).borderLeftWidth === '1px' &&
      getComputedStyle(number).paddingRight === '0px' &&
      up.getAttribute('aria-label') === 'Increase MTU' &&
      down.getAttribute('aria-label') === 'Decrease MTU' &&
      Math.abs(a.x - b.x) < 1 && Math.abs(a.bottom - b.top) < 1 &&
      a.height <= 20 && b.height <= 20 &&
      !!up.querySelector('svg path') && !!down.querySelector('svg path');
  })()`), true, 'small number field matches adjacent text field height');
  await tabTo(numberInput('mtu'));
  await wait(`getComputedStyle(document.querySelector(${JSON.stringify(numberInput('mtu'))}).labels[0]).color === 'rgb(63, 81, 181)'`);
  assert.equal(await evaluate(`(() => {
    const input = document.querySelector(${JSON.stringify(numberInput('mtu'))});
    return input.labels[0].getAttribute('data-shrink') === 'true' &&
      getComputedStyle(input.labels[0]).color === 'rgb(63, 81, 181)' &&
      getComputedStyle(input.closest('.MuiOutlinedInput-root').querySelector('fieldset')).borderTopWidth === '2px';
  })()`), true, 'focused number field uses MUI floating label and outlined focus border');
  const numberScreenshot = await command('browsingContext.captureScreenshot', { context });
  await writeFile('/tmp/cat4igp-number-field.png', Buffer.from(numberScreenshot.data, 'base64'));
  await keys('\uE013'); // ArrowUp.
  assert.equal(await numberValue('mtu'), '1421');
  await keys('\uE015'); // ArrowDown.
  assert.equal(await numberValue('mtu'), '1420');
  await tabTo('button[aria-label="Increase MTU"]');
  await enter();
  assert.equal(await numberValue('mtu'), '1421', 'stepper activation does not submit the form');
  await replaceNumber('mtu', '1280');
  await keys('\uE015');
  assert.equal(await numberValue('mtu'), '1280');
  await replaceNumber('mtu', '9000');
  await keys('\uE013');
  assert.equal(await numberValue('mtu'), '9000', 'formatted visible input submits raw digits');
  await replaceNumber('mtu', '');
  assert.equal(await numberValue('mtu'), '');
  assert.equal(await evaluate(`document.querySelector('input[name=mtu]').form.checkValidity()`), false, 'auto MTU is required');
  await replaceNumber('mtu', '1420');
  await tab();
  await tabTo('button[aria-label^="Actions for mesh #"]', true);
  const menuLabel = await evaluate(`document.activeElement.getAttribute('aria-label')`);
  assert.equal(await evaluate(`document.activeElement.disabled`), false, 'mesh action remains enabled');
  await enter();
  await wait(`!!document.querySelector('[role=menuitem]')`);
  assert.equal(await evaluate(`document.activeElement.getAttribute('role')`), 'menuitem');
  assert.equal(await evaluate(`document.querySelector('[role=menu]').getAttribute('aria-label')`), menuLabel);
  await keys('\uE015'); // ArrowDown: native MUI menu navigation.
  await keys('\uE00C'); // Escape: no destructive action.
  await wait(`!document.querySelector('[role=menu]')`);
  assert.equal(await evaluate(`document.activeElement.getAttribute('aria-label')`), menuLabel);
  await click(menuLabel);
  await wait(`!!document.querySelector('[role=menuitem]')`);
  await evaluate(`Array.from(document.querySelectorAll('[role=menuitem]')).find(b => b.textContent.startsWith('Rename mesh #')).click()`);
  await wait(`!!document.querySelector('[role=dialog] input[name=name]')`);
  await wait(`document.activeElement.name === 'name'`);
  assert.equal(await evaluate(`(() => {
    const dialog = document.querySelector('[role=dialog]');
    const save = dialog.querySelector('.MuiDialogActions-root button[type=submit]');
    const cancel = dialog.querySelector('.MuiDialogActions-root button:not([type=submit])');
    return save.form === dialog.querySelector('form') && save.classList.contains('MuiButton-contained') &&
      cancel.classList.contains('MuiButton-text') && !dialog.querySelector('.MuiDialogContent-root button');
  })()`), true, 'dialog footer actions retain native form association and secondary hierarchy');
  await keys('\uE00C');
  await wait(`!document.querySelector('[role=dialog]')`);
  await click(menuLabel);
  await wait(`!!document.querySelector('[role=menuitem]')`);
  await evaluate(`Array.from(document.querySelectorAll('[role=menuitem]')).find(b => b.textContent === 'Manage members').click()`);
  await wait(`!!document.querySelector('select[name=node]')`);
  assert.equal(await evaluate(`document.activeElement.tagName === 'H1' && document.activeElement.textContent.includes('HTTPS smoke')`), true);
  await outlined('select[name=node]');
  assert.equal(await evaluate(`(() => {
    const input = document.querySelector('select[name=node]');
    return input.matches(':disabled') && input.closest('.MuiOutlinedInput-root').classList.contains('Mui-disabled') &&
      input.labels[0].classList.contains('Mui-disabled') && getComputedStyle(input.labels[0]).color === 'rgba(0, 0, 0, 0.38)';
  })()`), true, 'empty node inventory disables native select and MUI label state');
  await click('Back to Meshes');
  await wait(`!!document.querySelector('input[name=auto]')`);
  await tabTo('nav button[aria-label="Invites"]', true);
  await enter();
  await wait(`!!document.querySelector('input[name=max]')`);
  await labels('.form-grid input:not([aria-hidden=true]), .form-grid select');
  await outlined(numberInput('max'));
  await outlined('select[name=mesh]');
  assert.equal(await evaluate(`(() => {
    const select = document.querySelector('select[name=mesh]');
    return select.classList.contains('MuiNativeSelect-select') && select.labels[0].dataset.shrink === 'true' &&
      new FormData(select.form).get('mesh') === '' && select.options[0].textContent === 'Use global default';
  })()`), true, 'native select retains options, empty FormData value and non-overlapping label');
  await tabTo(numberInput('max'));
  await keys('\uE015');
  assert.equal(await numberValue('max'), '0', 'unlimited invite limits cannot step below zero');
  await tabTo('button[aria-label^="Increase Maximum uses"]');
  await enter();
  assert.equal(await numberValue('max'), '1');
  await tabTo('button[aria-label^="Decrease Maximum uses"]');
  await enter();
  assert.equal(await numberValue('max'), '0');
  await replaceNumber('max', '9007199254740991');
  await keys('\uE013');
  assert.equal(await numberValue('max'), '9007199254740991');
  await replaceNumber('max', '');
  await tab();
  assert.equal(await numberValue('max'), '', 'optional blank stays empty, not zero');
  assert.equal(await evaluate(`document.querySelector('input[name=max]').form.checkValidity()`), true);
  await tabTo('input[name=expiry]');
  assert.equal(await evaluate(`document.activeElement.name`), 'expiry');
  await tabTo('.form-grid button[type=submit]');
  await enter();
  await wait(`!!document.querySelector('.secret input')`);
  const invite = await evaluate(`document.querySelector('.secret input').value`);
  assert.ok(typeof invite === 'string' && invite.length > 0);
  await wait(`document.querySelector('.inventory tbody').textContent.includes('Unlimited')`);
  console.log('PASS browser: NumberField keyboard/button integer steps, MTU bounds + required validation, disabled controls omitted from FormData, raw unformatted values, optional blank invite saved as unlimited');
  // Browser-local fixtures; authentication and TLS checks still use the real backend.
  await evaluate(`(() => {
    const original = fetch;
    const inventory = {
      nodes: [1, 2].map(id => ({ id, name: 'Fixture node ' + id, created_at: '', last_seen: null })),
      meshes: [1, 2].map(id => ({ id, name: 'Fixture mesh ' + id, auto_wireguard: true, mtu: 1420, fec: id === 2 })),
      memberships: [{ node_id: 1, mesh_id: 1 }, { node_id: 2, mesh_id: 2 }], invites: [], tunnels: []
    };
    window.membershipFixture = { inventory, writes: [], restore: () => { window.fetch = original; } };
    window.fetch = async (path, options) => {
      if (path === '/admin/inventory') return Response.json(inventory);
      if (path === '/admin/actions') {
        const body = JSON.parse(options.body);
        if (!['add_membership', 'remove_membership'].includes(body.action)) throw Error('Unexpected fixture action');
        window.membershipFixture.writes.push({ body, key: options.headers['Idempotency-Key'] });
        if (body.action === 'add_membership') inventory.memberships.push({ node_id: body.node_id, mesh_id: body.mesh_id });
        else inventory.memberships = inventory.memberships.filter(m => m.node_id !== body.node_id || m.mesh_id !== body.mesh_id);
        return Response.json({ committed: true, convergence: 'polling', affected_nodes: [body.node_id] });
      }
      return original(path, options);
    };
  })()`);
  const nav = name => evaluate(`document.querySelector('nav button[aria-label=' + CSS.escape(${JSON.stringify(name)}) + ']').click()`);
  async function manage(label, action) {
    await click(label);
    await wait(`!!document.querySelector('[role=menuitem]')`);
    await evaluate(`Array.from(document.querySelectorAll('[role=menuitem]')).find(b => b.textContent === ${JSON.stringify(action)}).click()`);
  }
  async function add(name, value) {
    await evaluate(`(() => { const select = document.querySelector('select[name=${name}]'); select.value = '${value}'; select.form.requestSubmit(); })()`);
    await wait(`!document.querySelector('.pending') && !document.querySelector('[aria-busy=true]')`);
  }
  async function remove() {
    await manage('Actions for node #1 in mesh #2', 'Remove node #1 from mesh #2');
    await wait(`!!document.querySelector('[role=dialog] #confirmation-warning')`);
    assert.equal(await evaluate(`document.querySelector('[role=dialog] h2').textContent.includes('Remove node #1 from mesh #2')`), true);
    await click('Cancel');
    await wait(`!document.querySelector('[role=dialog]')`);
    assert.equal(await evaluate(`!!document.querySelector('[aria-label="Actions for node #1 in mesh #2"]')`), true);
    await manage('Actions for node #1 in mesh #2', 'Remove node #1 from mesh #2');
    await wait(`!!document.querySelector('[role=dialog] #confirmation-warning')`);
    await click('Confirm');
    await wait(`!document.querySelector('[aria-label="Actions for node #1 in mesh #2"]') && !document.querySelector('.pending')`);
  }
  await click('Refresh');
  await nav('Meshes');
  await wait(`document.querySelector('.inventory tbody').textContent.includes('Fixture mesh 2')`);
  assert.equal(await evaluate(`Array.from(document.querySelectorAll('.inventory thead th')).map(c => c.textContent).join(',')`), 'Mesh,Auto WireGuard,Actions');
  assert.equal(await evaluate(`document.querySelector('.inventory tbody tr:first-child td').textContent.trim()`), 'MTU 1420');
  assert.equal(await evaluate(`document.querySelector('.inventory tbody tr:last-child td').textContent.trim()`), 'MTU 1420 · FEC enabled');
  await nav('Nodes');
  await wait(`!!document.querySelector('[aria-label="Actions for node #1"]')`);
  assert.equal(await evaluate(`document.querySelectorAll('nav button').length === 5 && !document.querySelector('nav').textContent.includes('Memberships')`), true);
  await manage('Actions for node #1', 'Manage memberships');
  await wait(`document.activeElement.tagName === 'H1' && document.activeElement.textContent === 'Memberships · Fixture node 1 · #1'`);
  assert.equal(await evaluate(`document.querySelector('.inventory tbody').textContent.includes('Fixture mesh 1') && !document.querySelector('.inventory tbody').textContent.includes('Fixture mesh 2')`), true);
  await labels('select[name=mesh]');
  assert.equal(await evaluate(`Array.from(document.querySelector('select[name=mesh]').options).map(o => o.value).join(',')`), ',2');
  await add('mesh', 2);
  await wait(`document.querySelector('.inventory tbody').textContent.includes('Fixture mesh 2')`);
  assert.equal(await evaluate(`document.querySelector('select[name=mesh]').matches(':disabled')`), true);
  await click('Back to Nodes');
  await wait(`document.activeElement.tagName === 'H1' && document.activeElement.textContent === 'Nodes'`);
  await nav('Meshes');
  await manage('Actions for mesh #2', 'Manage members');
  await wait(`document.querySelector('h1').textContent === 'Members · Fixture mesh 2 · #2'`);
  await tableStyles();
  await remove();
  assert.equal(await evaluate(`Array.from(document.querySelector('select[name=node]').options).map(o => o.value).join(',')`), ',1');
  await add('node', 1);
  await wait(`!!document.querySelector('[aria-label="Actions for node #1 in mesh #2"]')`);
  await click('Back to Meshes');
  await manage('Actions for mesh #2', 'Manage members');
  await nav('Nodes');
  await wait(`document.querySelector('h1').textContent === 'Nodes'`);
  await manage('Actions for node #1', 'Manage memberships');
  await remove();
  const writes = JSON.parse(await evaluate(`JSON.stringify(window.membershipFixture.writes)`));
  assert.deepEqual(writes.map(w => w.body), [
    { action: 'add_membership', mesh_id: 2, node_id: 1 },
    { action: 'remove_membership', mesh_id: 2, node_id: 1 },
    { action: 'add_membership', mesh_id: 2, node_id: 1 },
    { action: 'remove_membership', mesh_id: 2, node_id: 1 },
  ]);
  assert.ok(writes.every(w => /^[0-9a-f-]{36}$/.test(w.key)));
  await evaluate(`window.membershipFixture.inventory.nodes = window.membershipFixture.inventory.nodes.filter(n => n.id !== 1)`);
  await click('Refresh');
  await wait(`document.querySelector('.inventory').textContent.includes('This node is no longer available.')`);
  await click('Back to Nodes');
  await evaluate(`window.membershipFixture.restore(); delete window.membershipFixture`);
  console.log('PASS browser: scoped membership fixtures, remaining choices, add/remove bodies + keys, confirmations, back/focus, navigation reset, deleted selection');
  await command('storage.setCookie', { cookie: { name: '__Host-cat4igp', value: { type: 'string', value: config.expired }, domain: 'localhost', path: '/', secure: true, httpOnly: true, sameSite: 'strict', expiry: Math.floor(Date.now()/1000)+900 } });
  assert.ok((await cookies())[0].value.value === config.expired, 'synthetic expired token was not retained');
  assert.equal(await evaluate(`fetch('/admin/me').then(r=>r.status)`), 401);
  await click('Refresh');
  await wait(`!!document.querySelector('input[name=password]') && !document.querySelector('.secret') && !document.querySelector('.inventory')`);
  assert.equal(await evaluate(`document.querySelector('input[name=password]').value`), '');
  await login();
  assert.equal(await evaluate(`!!document.querySelector('.secret')`), false);
  assert.equal(await evaluate(`JSON.stringify([localStorage,sessionStorage]).includes(${JSON.stringify(invite)})`), false);
  assert.equal(await evaluate(`localStorage.length === 1 && localStorage.getItem('cat4igp-theme') === 'light' && sessionStorage.length === 0`), true);
  await click('Sign out');
  await wait(`!!document.querySelector('input[name=password]') && !document.querySelector('.inventory')`);
  assert.equal((await cookies()).length, 0);
  assert.equal(await evaluate(`fetch('/admin/me').then(r=>r.status)`), 401);
  console.log('PASS browser: Firefox trusted isolated NSS CA, localhost + 127.0.0.1 SANs, acceptInsecureCerts=false');
  console.log('PASS browser: distinct-site top-level GET /me 401 and form POST /login 403; session cookie_seen=false for both; POST Origin preserved; same-site session still 200');
  console.log('PASS browser: native BiDi Tab/Enter login + invite submission, associated labels, skip-to-main focus, named nav and view heading focus (not a full accessibility audit)');
  console.log('PASS browser: UI login, inventory, reload session, Secure/HttpOnly/Strict host cookie hidden from document.cookie');
  console.log('PASS browser: retained signed expired JWT rejected 401; refresh clears inventory/invite secret; re-login, theme-only storage, logout clears cookie');
  console.log('PASS browser: system theme default, keyboard dark/light toggle, persisted light reload, dark surface screenshot /tmp/cat4igp-dark-login.png; row menu Enter/ArrowDown/Escape restores focus');
  console.log('PASS browser: computed MUI outline/label/focus/dark/disabled styles, table component classes + cell styles, native select and checkbox FormData + keyboard checked state');
  console.log('PASS browser: selected list navigation + named counts, responsive wrapping, theme panel spacing, primary/text button hierarchy, rename dialog footer/form association + keyboard Escape');
  await command('session.end');
  ws.close();
  child.kill();
  await exited;
} finally {
  ws?.close();
  if (child && child.exitCode === null && child.signalCode === null) {
    const exited = once(child, 'exit');
    child.kill('SIGKILL');
    await exited;
  }
  await rm(profile, { recursive: true, force: true });
}