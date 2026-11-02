// Binds consent.js to the DOM. No inline script anywhere (the CSP forbids it); text goes in with textContent only.
import { run } from './consent.js';

const $ = (id) => document.getElementById(id);
const show = (...ids) =>
  ['signin', 'setpassword', 'welcome', 'consent', 'refused', 'denied', 'error'].forEach((
    s,
  ) => ($(s).hidden = !ids.includes(s)));

// The PUBLIC project URL, the PUBLISHABLE key and the public connector URL: nothing else.
const { url, key, mcpUrl } = globalThis.AM_CONFIG;
// The fragment is read here, BEFORE createClient and WITHOUT clearing it: supabase-js needs it to detect the session
// from an invite or recovery link, and clears it itself.
const hash = new URLSearchParams(globalThis.location.hash.slice(1));
const supabase = globalThis.supabase.createClient(url, key, {
  auth: { persistSession: true, autoRefreshToken: false },
});

const ui = {
  showSignIn(submit) {
    show('signin');
    $('signin-form').onsubmit = (e) => {
      e.preventDefault();
      submit($('email').value, $('password').value);
    };
  },
  showConsent(d, actions) {
    $('client').textContent = d.appLabel;
    $('dest').textContent = d.redirectHost;
    $('scopes').textContent = d.scopes.join(', ') || 'none named';
    $('approve').onclick = actions.approve;
    $('deny').onclick = actions.deny;
    show('consent');
  },
  // Deny only: there is no Approve element in this view at all (ADR-022 Amendment 2).
  showRefused(d, actions) {
    $('refused-client').textContent = d.appLabel;
    $('refused-dest').textContent = d.redirectHost;
    $('refused-message').textContent = d.message;
    $('refused-deny').onclick = actions.deny;
    show('refused');
  },
  showDenied(message) {
    $('denied-text').textContent = message;
    show('denied');
  },
  showSetPassword(submit) {
    $('setpassword-message').textContent = '';
    $('setpassword-form').onsubmit = (e) => {
      e.preventDefault();
      submit($('new-password').value, $('new-password2').value);
    };
    show('setpassword');
  },
  setPasswordMessage(message) {
    $('setpassword-message').textContent = message;
  },
  showWelcome(mcpUrl, { passwordSet }) {
    $('welcome-title').textContent = passwordSet ? 'Password set' : 'Connect to agent memory';
    $('mcp-url').textContent = mcpUrl;
    $('mcp-cmd').textContent = `claude mcp add --transport http agent-memory ${mcpUrl}`;
    show('welcome');
  },
  showError(message) {
    $('error-text').textContent = message;
    show('error');
  },
  redirect(url) {
    globalThis.location.replace(url);
  },
};

run({
  supabase,
  ui,
  params: new URLSearchParams(globalThis.location.search),
  hash,
  mcpUrl,
  framed: globalThis.top !== globalThis.self,
});
