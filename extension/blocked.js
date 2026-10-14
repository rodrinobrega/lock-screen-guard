'use strict';

const LABELS = {
  sameTabScriptRedirect: 'The page replaced itself with an in-memory document, without a click',
  fastRedirect: 'It did so immediately after loading',
  escapeKeys: 'It blocked keys you would use to leave (Esc, F5, F11, Ctrl+W…)',
  beforeunload: 'It tried to stop you from closing or leaving the page',
  contextmenu: 'It disabled right-click',
  lockApis: 'It tried to take over the screen, keyboard or mouse',
  historyFlood: 'It flooded your Back history so Back would not work',
  dialogLoop: 'It opened pop-up dialogs in a loop',
  lockWording: 'It claimed your computer was locked or infected',
  vendorImpersonation: 'It pretended to be Microsoft, Apple or a security vendor',
  supportPhone: 'It showed a phone number to call',
  urgency: 'It used urgent, pressuring language',
  fakeErrorCode: 'It showed a fake error code',
  systemColor: 'It mimicked a system "blue screen" style',
};

const params = new URLSearchParams(location.search);
const reason = params.get('reason') || 'lockscreen';
document.getElementById('reason').textContent =
  reason === 'user-leave'
    ? 'You chose to leave a page that was blocking your keyboard.'
    : `Several independent signals agreed (score ${params.get('score') || 'n/a'}):`;

const list = document.getElementById('hits');
for (const hit of (params.get('hits') || '').split(',').filter(Boolean)) {
  const li = document.createElement('li');
  li.textContent = LABELS[hit] || hit;
  list.append(li);
}

document.getElementById('new-tab').addEventListener('click', () => {
  chrome.tabs.create({ url: 'chrome://newtab' });
  chrome.tabs.getCurrent((tab) => tab && chrome.tabs.remove(tab.id));
});
