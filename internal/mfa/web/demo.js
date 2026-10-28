const $ = id => document.getElementById(id);
const feedback = $('result');
const tabGroups = [...document.querySelectorAll('[role="tablist"]')]
  .map(list => [...list.children].filter(child => child.getAttribute('role') === 'tab'));

function activateTabs(tabs, id, focus = false) {
  for (const tab of tabs) {
    const active = tab.id === `tab-${id}`;
    tab.setAttribute('aria-selected', String(active));
    tab.tabIndex = active ? 0 : -1;
    $(tab.getAttribute('aria-controls')).hidden = !active;
    if (active && focus) tab.focus();
  }
}
function selectTab(id, focus = false) {
  activateTabs(tabGroups[0], id, focus);
}
for (const tabs of tabGroups) {
  for (const [index, tab] of tabs.entries()) {
    tab.addEventListener('click', () => activateTabs(tabs, tab.id.slice(4)));
    tab.addEventListener('keydown', event => {
      let next = index;
      if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
      else if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length;
      else if (event.key === 'Home') next = 0;
      else if (event.key === 'End') next = tabs.length - 1;
      else return;
      event.preventDefault();
      activateTabs(tabs, tabs[next].id.slice(4), true);
    });
  }
}

const codeFieldIds = ['confirm-code', 'totp-code', 'hotp-confirm-code', 'hotp-code', 'recovery-code'];
const otpFieldIds = ['confirm-code', 'totp-code', 'hotp-confirm-code', 'hotp-code'];
function setCodeVisibility(input, visible) {
  input.type = visible ? 'text' : 'password';
  const toggle = input.nextElementSibling;
  toggle.setAttribute('aria-pressed', String(visible));
  toggle.setAttribute('aria-label', visible ? 'Hide code' : 'Show code');
  toggle.title = visible ? 'Hide code' : 'Show code';
}
for (const id of codeFieldIds) {
  const input = $(id);
  const field = document.createElement('div');
  field.className = 'sensitive-field';
  input.before(field);
  field.append(input);
  const toggle = document.createElement('button');
  toggle.className = 'visibility-toggle';
  toggle.type = 'button';
  toggle.setAttribute('aria-controls', id);
  toggle.innerHTML = '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/><path class="eye-slash" d="M3 21 21 3"/></svg>';
  field.append(toggle);
  setCodeVisibility(input, false);
  toggle.addEventListener('click', () => setCodeVisibility(input, input.type === 'password'));
}
for (const id of otpFieldIds) {
  const input = $(id);
  input.addEventListener('beforeinput', event => {
    if (event.inputType === 'insertText' && event.data && /[^0-9]/.test(event.data)) event.preventDefault();
  });
  input.addEventListener('input', () => {
    const original = input.value;
    const digits = original.replace(/[^0-9]/g, '').slice(0, 6);
    if (digits === original) return;
    const cursor = Math.min(original.slice(0, input.selectionStart ?? original.length).replace(/[^0-9]/g, '').length, digits.length);
    input.value = digits;
    input.setSelectionRange(cursor, cursor);
  });
}

function announce(message, kind = 'info') {
  const dialog = document.querySelector('.setup-dialog[open]');
  const target = dialog?.querySelector('.dialog-feedback') || feedback;
  if (dialog) feedback.hidden = true;
  target.textContent = message;
  target.dataset.kind = kind;
  target.hidden = false;
}
function run(task) {
  Promise.resolve().then(task).then(result => {
    if (typeof result === 'string') announce(result, 'success');
    else if (result?.message) announce(result.message, result.kind || 'info');
  }).catch(error => announce(error.message, 'error'));
}
function userPath(path) {
  return `/v1/users/demo/${path}`;
}
async function api(path, method = 'GET', data, ceremony) {
  const headers = {};
  if (data !== undefined) headers['Content-Type'] = 'application/json';
  if (ceremony) headers['X-Ceremony-ID'] = ceremony;
  const response = await fetch(userPath(path), {
    method, headers, credentials: 'same-origin',
    body: data === undefined ? undefined : JSON.stringify(data), cache: 'no-store'
  });
  const body = await response.json();
  if (response.status === 401) throw Error('Demo access expired. Reload this page to continue.');
  if (!response.ok) throw Error(body.error || `Request failed (HTTP ${response.status}).`);
  return body;
}
function statusText(active) { return active ? 'Active' : 'Not set up'; }
function takeCode(id) {
  const input = $(id);
  const code = input.value.trim();
  input.value = '';
  setCodeVisibility(input, false);
  return code;
}
async function refresh() {
  const state = await api('factors');
  $('status-totp').textContent = statusText(state.totp);
  $('status-hotp').textContent = statusText(state.hotp);
  $('status-passkeys').textContent = String(state.passkeys.length);
  $('status-codes').textContent = String(state.recovery_codes_remaining);
  const list = $('passkeys');
  list.replaceChildren();
  if (state.passkeys.length === 0) {
    const empty = document.createElement('p');
    empty.textContent = 'No passkeys saved for this test user.';
    list.append(empty);
  }
  for (const key of state.passkeys) {
    const row = document.createElement('div');
    row.className = 'saved-item';
    const name = document.createElement('code');
    name.textContent = key.id;
    const button = document.createElement('button');
    button.className = 'button secondary small';
    button.type = 'button';
    button.textContent = 'Remove';
    button.addEventListener('click', () => run(async () => {
      await api(`passkeys/${encodeURIComponent(key.id)}`, 'DELETE');
      await refresh();
      return 'Passkey removed.';
    }));
    row.append(name, button);
    list.append(row);
  }
  return state;
}
function showCodes(codes) {
  $('codes').textContent = codes.join('\n');
  $('recovery-warning').hidden = true;
  $('recovery-created').hidden = false;
  selectTab('recovery', true);
  if (!$('recovery-dialog').open) $('recovery-dialog').showModal();
}
function clearRecoveryDialog() {
  $('codes').textContent = '';
  $('recovery-created').hidden = true;
  $('recovery-warning').hidden = false;
  $('recovery-dialog').querySelector('.dialog-feedback').hidden = true;
}
function clearUserSecrets() {
  for (const [panel, image, secret] of [['enrollment', 'qr', 'secret'], ['hotp-enrollment', 'hotp-qr', 'hotp-secret']]) {
    if ($(panel).open) $(panel).close();
    $(image).removeAttribute('src');
    $(secret).textContent = '';
    $(panel).querySelector('.dialog-feedback').hidden = true;
  }
  if ($('recovery-dialog').open) $('recovery-dialog').close();
  clearRecoveryDialog();
  for (const id of codeFieldIds) {
    $(id).value = '';
    setCodeVisibility($(id), false);
  }
  feedback.hidden = true;
}

const from64 = input => {
  const base = input.replace(/-/g, '+').replace(/_/g, '/');
  const bytes = atob(base.padEnd(Math.ceil(base.length / 4) * 4, '='));
  return Uint8Array.from(bytes, character => character.charCodeAt(0));
};
const to64 = input => {
  let raw = '';
  for (const byte of new Uint8Array(input)) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
function publicOptions(options, register) {
  const publicKey = options.publicKey;
  publicKey.challenge = from64(publicKey.challenge);
  if (register) {
    publicKey.user.id = from64(publicKey.user.id);
    for (const credential of publicKey.excludeCredentials || []) credential.id = from64(credential.id);
  } else {
    for (const credential of publicKey.allowCredentials || []) credential.id = from64(credential.id);
  }
  return publicKey;
}
function credentialJSON(credential, register) {
  const response = {clientDataJSON: to64(credential.response.clientDataJSON)};
  if (register) {
    response.attestationObject = to64(credential.response.attestationObject);
    response.transports = credential.response.getTransports?.() || [];
  } else {
    response.authenticatorData = to64(credential.response.authenticatorData);
    response.signature = to64(credential.response.signature);
    response.userHandle = credential.response.userHandle ? to64(credential.response.userHandle) : null;
  }
  return {id: credential.id, rawId: to64(credential.rawId), type: credential.type, response,
    clientExtensionResults: credential.getClientExtensionResults(), authenticatorAttachment: credential.authenticatorAttachment};
}

$('reset-user').addEventListener('click', () => $('reset-dialog').showModal());
$('reset-close').addEventListener('click', () => $('reset-dialog').close());
$('reset-confirm').addEventListener('click', () => run(async () => {
  $('reset-confirm').disabled = true;
  try {
    const result = await api('lab-reset', 'DELETE');
    $('reset-dialog').close();
    clearUserSecrets();
    if (result.logout_url) window.location.assign(result.logout_url);
    else window.location.reload();
  } finally {
    $('reset-confirm').disabled = false;
  }
}));
async function setupQR(method, open) {
  const totp = method === 'totp';
  const dialog = $(totp ? 'enrollment' : 'hotp-enrollment');
  const enrollment = await api(`${method}/enrollment`, 'POST');
  $(totp ? 'qr' : 'hotp-qr').src = enrollment.qr_png_data_url;
  $(totp ? 'secret' : 'hotp-secret').textContent = enrollment.secret;
  $(totp ? 'confirm-code' : 'hotp-confirm-code').value = '';
  setCodeVisibility($(totp ? 'confirm-code' : 'hotp-confirm-code'), false);
  if (open && !dialog.open) dialog.showModal();
  return open ? 'Scan the QR code, then enter the first code from your app.' : 'New QR code generated. Replace the previous entry in your app.';
}
for (const [method, dialogId, closeId] of [['totp', 'enrollment', 'totp-close'], ['hotp', 'hotp-enrollment', 'hotp-close']]) {
  $(closeId).addEventListener('click', () => $(dialogId).close());
  $(dialogId).addEventListener('close', () => {
    $(method === 'totp' ? 'qr' : 'hotp-qr').removeAttribute('src');
    $(method === 'totp' ? 'secret' : 'hotp-secret').textContent = '';
    $(method === 'totp' ? 'confirm-code' : 'hotp-confirm-code').value = '';
    setCodeVisibility($(method === 'totp' ? 'confirm-code' : 'hotp-confirm-code'), false);
    $(dialogId).querySelector('.dialog-feedback').hidden = true;
  });
}
$('totp-start').addEventListener('click', () => run(() => setupQR('totp', true)));
$('totp-refresh').addEventListener('click', () => run(() => setupQR('totp', false)));
$('totp-confirm').addEventListener('click', () => run(async () => {
  const result = await api('totp/confirm', 'POST', {code: $('confirm-code').value.trim()});
  $('enrollment').close();
  showCodes(result.recovery_codes);
  await refresh();
  return 'TOTP is active. Save the recovery codes shown here.';
}));
$('totp-verify').addEventListener('click', () => run(async () => {
  const result = await api('verify', 'POST', {method: 'totp', code: takeCode('totp-code')});
  return result.valid ? {message: 'TOTP code accepted.', kind: 'success'} : {message: 'TOTP code rejected. It may be expired or already used.', kind: 'error'};
}));
$('hotp-start').addEventListener('click', () => run(() => setupQR('hotp', true)));
$('hotp-refresh').addEventListener('click', () => run(() => setupQR('hotp', false)));
$('hotp-confirm').addEventListener('click', () => run(async () => {
  let result;
  try {
    result = await api('hotp/confirm', 'POST', {code: $('hotp-confirm-code').value.trim()});
  } catch (error) {
    if (error.message === 'invalid code') throw Error('Code did not match. Check that this app entry is HOTP (counter-based), has no 30-second timer, and uses the current QR code.');
    throw error;
  }
  $('hotp-enrollment').close();
  showCodes(result.recovery_codes);
  await refresh();
  return 'HOTP is active. Save the recovery codes shown here.';
}));
$('hotp-verify').addEventListener('click', () => run(async () => {
  const result = await api('verify', 'POST', {method: 'hotp', code: takeCode('hotp-code')});
  return result.valid ? {message: 'HOTP code accepted.', kind: 'success'} : {message: 'HOTP code rejected. It may already have been used.', kind: 'error'};
}));
$('recovery-verify').addEventListener('click', () => run(async () => {
  const result = await api('verify', 'POST', {method: 'recovery_code', code: takeCode('recovery-code')});
  await refresh();
  return result.valid ? {message: 'Recovery code accepted and consumed.', kind: 'success'} : {message: 'Recovery code rejected. It may already have been used.', kind: 'error'};
}));
$('recovery-close').addEventListener('click', () => $('recovery-dialog').close());
$('recovery-dialog').addEventListener('close', clearRecoveryDialog);
$('recovery-rotate').addEventListener('click', () => {
  clearRecoveryDialog();
  $('recovery-dialog').showModal();
});
$('recovery-generate').addEventListener('click', () => run(async () => {
  const result = await api('recovery-codes/rotate', 'POST');
  showCodes(result.recovery_codes);
  await refresh();
  return 'New recovery codes generated. Older codes are now invalid.';
}));
$('copy-codes').addEventListener('click', () => run(async () => {
  await navigator.clipboard.writeText($('codes').textContent);
  return 'Recovery codes copied. Store them in a safe place.';
}));
function passkeyPromptError(error, action) {
  if (error?.name === 'AbortError') return Error('Passkey request cancelled.');
  if (error?.name === 'NotAllowedError') return Error(`Passkey ${action} was cancelled or timed out. Unlock this device or connect a FIDO2 security key, then try again.`);
  if (error?.name === 'SecurityError') return Error('The browser blocked the passkey request. Open the lab at http://localhost:18083/ and try again.');
  if (error?.name === 'NotSupportedError') return Error('This browser or device cannot use the requested passkey. Try a device with a screen lock or a FIDO2 security key.');
  return error;
}
let activePasskeyController = null;
function setPasskeyBusy(controller) {
  activePasskeyController = controller;
  $('passkey-register').disabled = Boolean(controller);
  $('passkey-auth').disabled = Boolean(controller);
  $('passkey-cancel').hidden = !controller;
}
$('passkey-cancel').addEventListener('click', () => activePasskeyController?.abort());
$('passkey-register').addEventListener('click', () => run(async () => {
  if (!navigator.credentials?.create) throw Error('This browser does not support passkey creation.');
  const controller = new AbortController();
  setPasskeyBusy(controller);
  try {
    announce('Preparing the passkey request…');
    const begin = await api('passkeys/register/begin', 'POST');
    if (controller.signal.aborted) throw Error('Passkey request cancelled.');
    announce('Waiting for your browser or device passkey prompt…');
    let credential;
    try {
      credential = await navigator.credentials.create({publicKey: publicOptions(begin.options, true), signal: controller.signal});
    } catch (error) {
      throw passkeyPromptError(error, 'creation');
    }
    if (controller.signal.aborted) throw Error('Passkey request cancelled.');
    if (!credential) throw Error('No passkey was created. Try again with a device screen lock or FIDO2 security key.');
    await api('passkeys/register/finish', 'POST', credentialJSON(credential, true), begin.ceremony_id);
    await refresh();
    return 'Passkey added. You can now verify it with the browser prompt.';
  } finally {
    setPasskeyBusy(null);
  }
}));
$('passkey-auth').addEventListener('click', () => run(async () => {
  if (!navigator.credentials?.get) throw Error('This browser does not support passkey verification.');
  const controller = new AbortController();
  setPasskeyBusy(controller);
  try {
    announce('Preparing the passkey verification…');
    const begin = await api('passkeys/authenticate/begin', 'POST');
    if (controller.signal.aborted) throw Error('Passkey request cancelled.');
    announce('Waiting for your browser or device passkey prompt…');
    let credential;
    try {
      credential = await navigator.credentials.get({publicKey: publicOptions(begin.options, false), signal: controller.signal});
    } catch (error) {
      throw passkeyPromptError(error, 'verification');
    }
    if (controller.signal.aborted) throw Error('Passkey request cancelled.');
    if (!credential) throw Error('No passkey was selected. Try again with your registered device or security key.');
    const result = await api('passkeys/authenticate/finish', 'POST', credentialJSON(credential, false), begin.ceremony_id);
    return result.valid ? {message: 'Passkey verified.', kind: 'success'} : {message: 'Passkey verification failed.', kind: 'error'};
  } finally {
    setPasskeyBusy(null);
  }
}));

refresh().catch(error => announce(error.message, 'error'));
