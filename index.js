// Corkboard backend: Google sign-in, teams, board sync (Cloudflare Workers + D1)
const enc = new TextEncoder(), DAY = 864e5;
const J = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', ...h } });
const rnd = (n = 12) => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(n)))).replace(/[+/=]/g, c => ({ '+': '-', '/': '_', '=': '' }[c]));
const sha = async s => [...new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)))].map(b => b.toString(16).padStart(2, '0')).join('');
const u8 = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const txt = s => new TextDecoder().decode(u8(s));

// Verify a Google ID token (RS256) against Google's published keys.
async function verifyGoogle(cred, env) {
  if (env.DEV_FAKE_AUTH === '1' && cred.startsWith('dev:')) { const n = cred.slice(4); return { sub: 'dev-' + n, email: n + '@dev.local', name: n, picture: '' }; } // local testing only
  const [h, p, sig] = cred.split('.'); if (!sig) throw 0;
  const hd = JSON.parse(txt(h)), pl = JSON.parse(txt(p)); if (hd.alg !== 'RS256') throw 0;
  const jwks = await (await fetch('https://www.googleapis.com/oauth2/v3/certs', { cf: { cacheTtl: 3600, cacheEverything: true } })).json();
  const jwk = jwks.keys.find(k => k.kid === hd.kid); if (!jwk) throw 0;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, u8(sig), enc.encode(h + '.' + p))) throw 0;
  if (!['accounts.google.com', 'https://accounts.google.com'].includes(pl.iss) || pl.aud !== env.GOOGLE_CLIENT_ID || pl.exp * 1000 < Date.now() || !pl.email_verified) throw 0;
  return pl;
}
async function me(req, env) {
  const c = /(?:^|; )sid=([^;]+)/.exec(req.headers.get('cookie') || ''); if (!c) return null;
  return env.DB.prepare('select u.id,u.name,u.email,u.picture from sessions s join users u on u.id=s.uid where s.h=? and s.exp>?').bind(await sha(c[1]), Date.now()).first();
}
async function access(DB, uid, id) {
  const b = await DB.prepare('select * from boards where id=?').bind(id).first(); if (!b) return {};
  let role = null;
  if (b.team_id) { const r = await DB.prepare('select role from members where team_id=? and uid=?').bind(b.team_id, uid).first(); role = r && r.role; }
  else if (b.owner === uid) role = 'owner';
  return { b, role, manage: !!role && (b.owner === uid || role === 'owner') };
}
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    try { return await route(req, env, url); } catch (e) { return J({ error: 'server' }, 500); }
  }
};
async function route(req, env, url) {
  const m = req.method, p = url.pathname.split('/').filter(Boolean).slice(1), DB = env.DB;
  if (m !== 'GET' && (req.headers.get('origin') || url.origin) !== url.origin) return J({ error: 'origin' }, 403);
  const body = m === 'GET' || m === 'DELETE' ? {} : await req.json().catch(() => ({}));
  if (p[0] === 'health') return J({ ok: true, clientId: env.GOOGLE_CLIENT_ID });
  if (p[0] === 'auth' && p[1] === 'google' && m === 'POST') {
    let g; try { g = await verifyGoogle(String(body.credential || ''), env); } catch (e) { return J({ error: 'invalid' }, 401); }
    let u = await DB.prepare('select id from users where sub=?').bind(g.sub).first();
    if (!u) { u = { id: rnd(9) }; await DB.prepare('insert into users(id,sub,email,name,picture,created) values(?,?,?,?,?,?)').bind(u.id, g.sub, g.email, g.name || g.email, g.picture || '', Date.now()).run(); }
    else await DB.prepare('update users set email=?,name=?,picture=? where id=?').bind(g.email, g.name || g.email, g.picture || '', u.id).run();
    const tok = rnd(32);
    await DB.prepare('insert into sessions(h,uid,exp) values(?,?,?)').bind(await sha(tok), u.id, Date.now() + 30 * DAY).run();
    return J({ ok: true }, 200, { 'set-cookie': `sid=${tok}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${30 * 86400}` });
  }
  if (p[0] === 'auth' && p[1] === 'logout' && m === 'POST') {
    const c = /(?:^|; )sid=([^;]+)/.exec(req.headers.get('cookie') || '');
    if (c) await DB.prepare('delete from sessions where h=?').bind(await sha(c[1])).run();
    return J({ ok: true }, 200, { 'set-cookie': 'sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0' });
  }
  const user = await me(req, env); if (!user) return J({ error: 'auth' }, 401);
  const uid = user.id, all = (sql, ...a) => DB.prepare(sql).bind(...a).all().then(r => r.results), one = (sql, ...a) => DB.prepare(sql).bind(...a).first();
  if (p[0] === 'me') return J({ user, teams: await all('select t.id,t.name,m.role from members m join teams t on t.id=m.team_id where m.uid=?', uid) });

  if (p[0] === 'teams') {
    if (!p[1] && m === 'POST') {
      const name = String(body.name || '').trim().slice(0, 30); if (!name) return J({ error: 'name' }, 400);
      const id = rnd(8);
      await DB.batch([DB.prepare('insert into teams(id,name,created) values(?,?,?)').bind(id, name, Date.now()), DB.prepare("insert into members(team_id,uid,role) values(?,?,'owner')").bind(id, uid)]);
      return J({ id, name, role: 'owner' });
    }
    const mem = await one('select role from members where team_id=? and uid=?', p[1], uid); if (!mem) return J({ error: 'forbidden' }, 403);
    if (p[2] === 'members' && !p[3] && m === 'GET') return J(await all('select u.id,u.name,u.email,u.picture,m.role from members m join users u on u.id=m.uid where m.team_id=?', p[1]));
    if (p[2] === 'invite' && m === 'POST') {
      if (mem.role !== 'owner') return J({ error: 'forbidden' }, 403);
      const code = rnd(12); await DB.prepare('insert into invites(code,team_id,exp,by) values(?,?,?,?)').bind(code, p[1], Date.now() + 7 * DAY, uid).run(); return J({ code });
    }
    if (p[2] === 'members' && p[3] && m === 'DELETE') {
      if (p[3] !== uid && mem.role !== 'owner') return J({ error: 'forbidden' }, 403);
      const t = await one('select role from members where team_id=? and uid=?', p[1], p[3]); if (t && t.role === 'owner') return J({ error: 'owner' }, 400);
      await DB.prepare('delete from members where team_id=? and uid=?').bind(p[1], p[3]).run(); return J({ ok: true });
    }
  }
  if (p[0] === 'invites' && p[2] === 'accept' && m === 'POST') {
    const iv = await one('select * from invites where code=? and exp>?', p[1], Date.now()); if (!iv) return J({ error: 'invalid' }, 404);
    await DB.prepare("insert or ignore into members(team_id,uid,role) values(?,?,'member')").bind(iv.team_id, uid).run();
    return J(await one('select id,name from teams where id=?', iv.team_id));
  }
  if (p[0] === 'boards') {
    if (!p[1] && m === 'GET') return J(await all('select id,name,team_id,owner from boards where (team_id is null and owner=?1) or team_id in (select team_id from members where uid=?1)', uid));
    if (!/^[\w-]{6,40}$/.test(p[1] || '')) return J({ error: 'id' }, 400);
    const a = await access(DB, uid, p[1]);
    if (!p[2] && m === 'PUT') {
      const name = String(body.name || 'ボード').slice(0, 40), team = body.team_id || null;
      if (team && !await one('select 1 x from members where team_id=? and uid=?', team, uid)) return J({ error: 'forbidden' }, 403);
      if (!a.b) { await DB.prepare('insert into boards(id,owner,team_id,name,seq) values(?,?,?,?,0)').bind(p[1], uid, team, name).run(); return J({ ok: true }); }
      if (!a.manage) return J({ error: 'forbidden' }, 403);
      await DB.prepare('update boards set name=?,team_id=? where id=?').bind(name, team, p[1]).run(); return J({ ok: true });
    }
    if (!a.role) return J({ error: 'forbidden' }, 403);
    if (!p[2] && m === 'DELETE') {
      if (!a.manage) return J({ error: 'forbidden' }, 403);
      await DB.batch([DB.prepare('delete from items where board_id=?').bind(p[1]), DB.prepare('delete from boards where id=?').bind(p[1])]); return J({ ok: true });
    }
    if (p[2] === 'sync' && m === 'POST') {
      const items = (Array.isArray(body.items) ? body.items : []).slice(0, 500).filter(i => i && typeof i.id === 'string' && i.id.length < 40 && (i.k === 't' || i.k === 'o') && Number.isFinite(i.u));
      if (items.length) await DB.batch([
        DB.prepare('update boards set seq=seq+1 where id=?').bind(p[1]),
        ...items.map(i => DB.prepare('insert into items(board_id,id,k,d,u,gone,s) values(?1,?2,?3,?4,?5,?6,(select seq from boards where id=?1)) on conflict(board_id,id) do update set k=excluded.k,d=excluded.d,u=excluded.u,gone=excluded.gone,s=excluded.s where excluded.u>=items.u')
          .bind(p[1], i.id, i.k, i.gone ? '{}' : String(i.d).slice(0, 20000), i.u, i.gone ? 1 : 0))
      ]);
      const rows = await all('select id,k,d,u,gone,s from items where board_id=? and s>? order by s limit 1000', p[1], Number(body.since) || 0);
      const seq = rows.length === 1000 ? rows[999].s : (await one('select seq from boards where id=?', p[1])).seq;
      return J({ items: rows, seq });
    }
  }
  return J({ error: 'not found' }, 404);
}
