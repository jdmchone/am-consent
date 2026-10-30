// Binds consent.js to the DOM. No inline script anywhere (the CSP forbids it); text goes in with textContent only.
import { run } from './consent.js';

const $ = (id) => document.getElementById(id);
const show = (...ids) => ['signin', 'consent', 'error'].forEach((s) => ($(s).hidden = !ids.includes(s)));

const { url, key } = globalThis.AM_CONFIG; // the PUBLIC project URL and the PUBLISHABLE key: nothing else
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
    $('client').textContent = d.clientName;
    $('dest').textContent = d.redirectHost;
    $('scopes').textContent = d.scopes.join(', ') || 'none named';
    $('approve').onclick = actions.approve;
    $('deny').onclick = actions.deny;
    show('consent');
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
  framed: globalThis.top !== globalThis.self,
});
