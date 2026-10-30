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

async function show(supabase, ui, id) {
  const { data, error } = await supabase.auth.oauth.getAuthorizationDetails(id);
  if (error || !data) return ui.showError(CANNOT_LOAD);
  let redirectHost = '';
  try {
    redirectHost = new URL(data.redirect_uri ?? data.redirect_url ?? '').host;
  } catch { /* shown as empty: the user sees that no destination was named */ }
  const finish = async (call) => {
    const res = await call(id, { skipBrowserRedirect: true });
    const target = res?.error ? null : safeRedirect(res?.data?.redirect_url);
    if (target === null) return ui.showError(CANNOT_LOAD);
    return ui.redirect(target);
  };
  return ui.showConsent(
    {
      clientName: String(data.client?.name ?? 'An application'),
      redirectHost,
      scopes: String(data.scope ?? '').split(/\s+/).filter(Boolean),
    },
    {
      approve: () => finish((i, o) => supabase.auth.oauth.approveAuthorization(i, o)),
      deny: () => finish((i, o) => supabase.auth.oauth.denyAuthorization(i, o)),
    },
  );
}
