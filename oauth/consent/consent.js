// The consent page's logic (SPEC-TS-HOST section 5, OD-TS2). Pure over injected `supabase`, `ui` and `params`; main.js
// binds the real DOM. The browser talks to Supabase Auth directly: no token passes through any code of ours.

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

/** A redirect target is https, or http to the loopback (Claude Code's local callback). Anything else is refused. */
export function safeRedirect(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol === 'https:') return u.href;
  if (u.protocol === 'http:' && LOOPBACK.has(u.hostname)) return u.href;
  return null;
}

const CANNOT_LOAD = 'This request could not be loaded. Start the sign-in again from your app.';

const EXPIRED = 'This link has expired or was already used. Ask the person who invited you for a new one.';
const MIN_PASSWORD = 12;

/**
 * `hash` is the URL fragment as URLSearchParams (main.js reads it WITHOUT clearing it: supabase-js needs it to detect
 * the session and clears it itself). `type=invite|recovery` is a link the owner sent by hand (ADR-022 Amendment 1).
 */
export async function run({ supabase, ui, params, framed, hash = new URLSearchParams(), mcpUrl = '' }) {
  // A page that can be framed can be clickjacked into an Approve. CSP frame-ancestors cannot be set from a meta tag
  // on static hosting, so the page refuses to render anything to approve when it is framed.
  if (framed) return ui.showError('This page cannot be shown inside another page. Open it in its own tab.');
  // An expired or already-used link: supabase-js stores no session and leaves the error in the fragment.
  if (hash.get('error_code') || hash.get('error')) return ui.showError(EXPIRED);
  const linkType = hash.get('type');
  if (linkType === 'invite' || linkType === 'recovery') return setPassword(supabase, ui, mcpUrl);
  const id = params.get('authorization_id');
  if (!id) return ui.showWelcome(mcpUrl, { passwordSet: false });

  const { data: { session } } = await supabase.auth.getSession();
  if (!session) {
    // One text for a wrong password, an unknown address and an invite not yet accepted: nothing to enumerate.
    return ui.showSignIn(async (email, password) => {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (error || !data?.session) return ui.showError('Sign-in failed. Check the email and password.');
      return show(supabase, ui, id);
    });
  }
  return show(supabase, ui, id);
}

async function setPassword(supabase, ui, mcpUrl) {
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return ui.showError(EXPIRED);
  return ui.showSetPassword(async (password, again) => {
    if (password !== again || password.length < MIN_PASSWORD) {
      return ui.setPasswordMessage(`Enter the same password twice, at least ${MIN_PASSWORD} characters.`);
    }
    const { error } = await supabase.auth.updateUser({ password });
    if (error) return ui.setPasswordMessage('That password was not accepted. Try a longer one.');
    return ui.showWelcome(mcpUrl, { passwordSet: true });
  });
}

const NOT_MEMBER = 'This sign-in is not a member of this memory service. Ask the person who runs it.';
const NOT_ALLOWED = (host) =>
  `${host} is not on this memory service's approved list. Ask the person who runs it to approve it, then start again.`;
const DENIED = 'Denied. You can close this tab.';

/**
 * Ask the database whether this sign-in may approve an app whose code goes to `uri` (ADR-022 Amendment 2). Resolves to
 * `null` ONLY when `api.consent_check` answered NULL; anything else (a reason, an RPC error, a thrown call, a missing
 * answer) is a refusal, so a missing function or an outage never offers Approve.
 */
async function check(supabase, uri) {
  if (!uri) return 'no_redirect';
  let res;
  try {
    res = await supabase.schema('api').rpc('consent_check', { p_redirect_uri: uri });
  } catch {
    return 'rpc_error';
  }
  if (!res || res.error || !('data' in res)) return 'rpc_error';
  return res.data === null ? null : String(res.data);
}

const hostOf = (uri) => {
  try {
    return new URL(uri).host;
  } catch {
    return '';
  }
};

/** The refusal text for a `check` reason: only `app_not_allowed` is about the app; everything else is the login. */
const refusalText = (reason, uri) => reason === 'app_not_allowed' ? NOT_ALLOWED(hostOf(uri)) : NOT_MEMBER;

/** Scheme, `//` and authority of a URL: everything before its first `/`, `?` or `#` after the `//`. Never the code. */
const base = (url) => /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*/.exec(url)?.[0] ?? '';

async function show(supabase, ui, id) {
  const { data, error } = await supabase.auth.oauth.getAuthorizationDetails(id);
  if (error || !data) return ui.showError(CANNOT_LOAD);
  // A prior consent auto-approves: the answer is a bare `{redirect_url}` (no authorization_id, client or redirect_uri).
  // There is nothing to approve; the page only decides whether to follow it (ADR-022 Amendment 2).
  if (!data.authorization_id) return followApproved(supabase, ui, data.redirect_url);
  const uri = data.redirect_uri ?? '';
  const host = hostOf(uri);
  const loopback = LOOPBACK.has((() => {
    try {
      return new URL(uri).hostname;
    } catch {
      return '';
    }
  })());
  const d = {
    clientName: String(data.client?.name ?? 'An application'),
    appLabel: `An app calling itself \u201c${String(data.client?.name ?? 'An application')}\u201d`,
    redirectHost: loopback ? `this computer (${host})` : host,
    scopes: String(data.scope ?? '').split(/\s+/).filter(Boolean),
  };
  const reason = await check(supabase, uri);
  const finish = async (call) => {
    const res = await call(id, { skipBrowserRedirect: true });
    const target = res?.error ? null : safeRedirect(res?.data?.redirect_url);
    if (target === null) return ui.showError(CANNOT_LOAD);
    return ui.redirect(target);
  };
  if (reason !== null) {
    // Deny only. Deny never navigates: the redirect would send the user to the host that was just refused.
    return ui.showRefused({ ...d, message: refusalText(reason, uri) }, {
      deny: async () => {
        const res = await supabase.auth.oauth.denyAuthorization(id, { skipBrowserRedirect: true });
        return res?.error ? ui.showError(CANNOT_LOAD) : ui.showDenied(DENIED);
      },
    });
  }
  return ui.showConsent(d, {
    approve: () => finish((i, o) => supabase.auth.oauth.approveAuthorization(i, o)),
    deny: () => finish((i, o) => supabase.auth.oauth.denyAuthorization(i, o)),
  });
}

/** The auto-approved shape: check only the BASE of the URL (its path and query carry the code), then follow it or stop. */
async function followApproved(supabase, ui, redirectUrl) {
  const origin = base(String(redirectUrl ?? ''));
  const reason = await check(supabase, origin);
  if (reason !== null) return ui.showError(refusalText(reason, origin));
  const target = safeRedirect(redirectUrl);
  return target === null ? ui.showError(CANNOT_LOAD) : ui.redirect(target);
}
