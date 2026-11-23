/*! verificare-dns-email — NBT Host (https://nbt-host.com), MIT licence. English interface.
    DNS and email check (A, AAAA, NS, MX, SPF, DKIM, DMARC, CAA) over DNS-over-HTTPS, and SPF / DMARC generator.
    Runs entirely in the browser: DNS questions go straight to Cloudflare (1.1.1.1), with Google Public DNS as fallback. */
(function () {
'use strict';

var doc = document, win = window;
var main = doc.querySelector('[data-it]');
if (!main) return;
var KIND = main.getAttribute('data-it');
var $ = function (s, c) { return (c || doc).querySelector(s); };
var $$ = function (s, c) { return Array.prototype.slice.call((c || doc).querySelectorAll(s)); };
var GUIDE = 'https://nbt-host.com/en/guides/';
var NBT_IP = '185.230.138.193';        /* docs/ghiduri/mailuri-in-spam-spf-dkim-dmarc.md, pasul 1.6 */
var NBT_NS = /(^|\.)ns[12]\.nbt-host\.ro\.?$/i;

function mk(tag, cls, txt) {
  var e = doc.createElement(tag);
  if (cls) e.className = cls;
  if (txt != null) e.textContent = txt;
  return e;
}
/* rich text: an array of strings and {t, href} / {b} / {c} pieces, never innerHTML with outside data */
function rich(parent, parts) {
  (Array.isArray(parts) ? parts : [parts]).forEach(function (p) {
    if (p == null) return;
    if (typeof p === 'string') { parent.appendChild(doc.createTextNode(p)); return; }
    if (p.href) {
      var a = mk('a', null, p.t);
      a.href = p.href;
      if (/^https?:/.test(p.href)) { a.target = '_blank'; a.rel = 'noopener noreferrer'; }
      parent.appendChild(a);
    } else if (p.b != null) parent.appendChild(mk('b', null, p.b));
    else if (p.c != null) parent.appendChild(mk('code', null, p.c));
  });
  return parent;
}
var ICON = { ok: '✓', warn: '!', bad: '×', info: 'i' };
var WORD = { ok: 'OK', warn: 'Warning', bad: 'Problem', info: 'Info' };
function icon(k) { var i = mk('span', 'it-ic', ICON[k]); i.setAttribute('aria-hidden', 'true'); return i; }
function badge(k) {
  var s = mk('span', 'it-st it-' + k);
  s.appendChild(icon(k));
  s.appendChild(doc.createTextNode(WORD[k]));
  return s;
}
function worst(list) {
  var r = { bad: 4, warn: 3, ok: 2, info: 1 }, w = 'info';
  list.forEach(function (d) { if (r[d.k] > r[w]) w = d.k; });
  return w;
}

/* "https://www.Firma.ro/contact", "ion@firma.ro", "firmă.ro" -> "firma.ro" / "xn--firm-wqa.ro" */
function normDomain(raw) {
  var d = String(raw || '').trim().toLowerCase();
  var note = '';
  if (!d) return null;
  if (d.indexOf('@') >= 0) d = d.slice(d.lastIndexOf('@') + 1);
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[\/?#].*$/, '').replace(/:\d+$/, '').replace(/\.+$/, '');
  if (/^www\./.test(d) && d.split('.').length > 2) { d = d.slice(4); note = 'www'; }
  if (/[^\x00-\x7f]/.test(d)) {
    try { d = new URL('http://' + d).hostname; } catch (e) { return null; }
  }
  if (d.length > 253 || d.split('.').length < 2) return null;
  var ok = d.split('.').every(function (l) { return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l); });
  if (!ok || !/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(d.slice(d.lastIndexOf('.') + 1))) return null;
  return { d: d, note: note };
}

function copyText(txt, btn, okLabel) {
  var lbl = btn.querySelector('i') || btn, t0 = lbl.textContent;
  function done() {
    btn.classList.add('gd-ok');
    lbl.textContent = okLabel || 'Copied';
    setTimeout(function () { btn.classList.remove('gd-ok'); lbl.textContent = t0; }, 1800);
  }
  function legacy() {
    var ta = mk('textarea');
    ta.value = txt;
    ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0';
    doc.body.appendChild(ta);
    ta.select();
    try { if (doc.execCommand('copy')) done(); } catch (e) {}
    doc.body.removeChild(ta);
  }
  if (navigator.clipboard && win.isSecureContext) navigator.clipboard.writeText(txt).then(done, legacy);
  else legacy();
}
function copyBtn(getText, label) {
  var b = mk('button', 'gd-copy', label || 'Copy');
  b.type = 'button';
  b.addEventListener('click', function () { copyText(getText(), b); });
  return b;
}
function setQuery(params) {
  try {
    var u = new URL(location.href);
    Object.keys(params).forEach(function (k) { if (params[k]) u.searchParams.set(k, params[k]); else u.searchParams.delete(k); });
    history.replaceState(null, '', u.pathname + u.search + u.hash);
  } catch (e) {}
}
function getQuery(k) {
  try { return new URL(location.href).searchParams.get(k) || ''; } catch (e) { return ''; }
}

/* =============================================================
   1. DNS + EMAIL CHECK
   ============================================================= */
var T = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };

function getJson(url, headers) {
  var ctl = win.AbortController ? new AbortController() : null;
  var tm = setTimeout(function () { if (ctl) ctl.abort(); }, 9000);
  return fetch(url, { headers: headers || {}, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer',
    signal: ctl ? ctl.signal : undefined })
    .then(function (r) { clearTimeout(tm); if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function (j) { if (!j || typeof j.Status !== 'number') throw new Error('raspuns'); return j; },
          function (e) { clearTimeout(tm); throw e; });
}
var dohCache = {};
function doh(name, type) {
  var key = name + '|' + type;
  if (dohCache[key]) return dohCache[key];
  var q = '?name=' + encodeURIComponent(name) + '&type=' + type;
  var p = getJson('https://cloudflare-dns.com/dns-query' + q, { Accept: 'application/dns-json' })
    .catch(function () { return getJson('https://dns.google/resolve' + q); })
    .then(function (j) {
      var want = T[type];
      return { status: j.Status, ans: (j.Answer || []).filter(function (a) { return a.type === want; })
        .map(function (a) { return String(a.data || ''); }) };
    });
  dohCache[key] = p;
  return p;
}
/* TXT: Cloudflare sends "part1" "part2" (escaped), Google the parts already joined */
function txt(s) {
  s = String(s).trim();
  if (s.charAt(0) !== '"') return s;
  var out = '', m, re = /"((?:[^"\\]|\\.)*)"/g;
  while ((m = re.exec(s))) {
    out += m[1].replace(/\\(\d{3})|\\(.)/g, function (_, d, c) { return d ? String.fromCharCode(+d) : c; });
  }
  return out;
}
function host(s) { return String(s).replace(/\.$/, '').toLowerCase(); }

/* SPF: mechanisms that cost a DNS lookup (RFC 7208 §4.6.4: at most 10) */
var SPF_TERM = /^([+\-~?]?)(all|include|a|mx|ptr|ip4|ip6|exists)(?:([:\/])(.*))?$/i;
function spfOf(list) { return list.filter(function (t) { return /^v=spf1(\s|$)/i.test(t); }); }
function spfCount(domain, budget, seen, depth) {
  /* -> Promise<{n, errs:[]}>: lookups below `domain`'s record (nested includes / redirect), errs = broken targets */
  if (depth > 10 || budget.left <= 0 || seen[domain]) return Promise.resolve({ n: 0, errs: [] });
  seen[domain] = 1;
  budget.left--;
  return doh(domain, 'TXT').then(function (r) {
    var recs = spfOf(r.ans.map(txt));
    if (r.status !== 0 || recs.length !== 1) {
      return { n: 0, errs: [domain + (recs.length > 1 ? ' has more than one SPF record' : ' has no SPF record')] };
    }
    return spfWalk(recs[0], budget, seen, depth);
  }, function () { return { n: 0, errs: [] }; });
}
function spfWalk(rec, budget, seen, depth) {
  var n = 0, errs = [], subs = [], hasAll = false, redirect = '';
  rec.split(/\s+/).slice(1).forEach(function (t) {
    if (!t) return;
    var m = SPF_TERM.exec(t), mod = /^(redirect|exp)=(.+)$/i.exec(t);
    if (mod) { if (mod[1].toLowerCase() === 'redirect') redirect = mod[2]; return; }
    if (!m) return;
    var mech = m[2].toLowerCase(), arg = m[3] === ':' ? m[4] : '';
    if (mech === 'all') hasAll = true;
    if (mech === 'include' || mech === 'a' || mech === 'mx' || mech === 'ptr' || mech === 'exists') n++;
    if (mech === 'include' && arg && arg.indexOf('%') < 0) subs.push(arg.toLowerCase());
  });
  if (redirect && !hasAll) { n++; if (redirect.indexOf('%') < 0) subs.push(redirect.toLowerCase()); }
  return Promise.all(subs.map(function (d) { return spfCount(d, budget, seen, depth + 1); })).then(function (rs) {
    rs.forEach(function (x) { n += x.n; errs = errs.concat(x.errs); });
    return { n: n, errs: errs };
  });
}

/* DKIM: RSA key size from the SubjectPublicKeyInfo (DER) in p= */
function rsaBits(b64) {
  var bin;
  try { bin = atob(b64.replace(/\s+/g, '')); } catch (e) { return 0; }
  var i = 0;
  function len() {
    var l = bin.charCodeAt(i++);
    if (l < 0x80) return l;
    var k = l & 0x7f, v = 0;
    while (k--) v = v * 256 + bin.charCodeAt(i++);
    return v;
  }
  function tag(t) { if (bin.charCodeAt(i++) !== t) throw 0; return len(); }
  try {
    tag(0x30);
    i += tag(0x30);                 /* skip the AlgorithmIdentifier */
    tag(0x03); i++;                 /* BIT STRING, then its unused-bits byte */
    tag(0x30);
    var ml = tag(0x02);
    while (ml > 0 && bin.charCodeAt(i) === 0) { i++; ml--; }
    return ml * 8;
  } catch (e) {
    /* a bare RSAPublicKey (some generators): rough size from the length */
    return bin.length > 250 ? 2048 : bin.length > 120 ? 1024 : 0;
  }
}
function tags(rec) {
  var o = {};
  rec.split(';').forEach(function (p) {
    var k = p.indexOf('=');
    if (k > 0) o[p.slice(0, k).trim().toLowerCase()] = p.slice(k + 1).trim();
  });
  return o;
}

function dnsInit() {
  var form = $('#itForm'), inp = $('#itQ'), sel = $('#itSel'), btn = $('#itGo'), out = $('#itRes'), live = $('#itLive');
  if (!form) return;
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    run(inp.value, sel ? sel.value : '');
  });
  var q = getQuery('domeniu');
  if (q) {
    inp.value = q;
    if (sel && getQuery('selector')) sel.value = getQuery('selector');
    run(q, sel ? sel.value : '');
  }

  function run(raw, selRaw) {
    var nd = normDomain(raw);
    out.hidden = false;
    live.textContent = '';
    if (!nd) {
      live.appendChild(rich(mk('div', 'it-err glass'), [{ b: 'That doesn\'t look like a domain. ' },
        'Enter just the name, for example ', { c: 'firma-ta.ro' }, ' (no spaces; we strip “https://”, “www.” and email addresses for you).']));
      return;
    }
    var d = nd.d;
    var selector = String(selRaw || '').trim().toLowerCase().replace(/\._domainkey.*$/, '') || 'default';
    if (!/^[a-z0-9](?:[a-z0-9._-]{0,62})$/.test(selector)) selector = 'default';
    if (sel) sel.value = selector;
    inp.value = d;
    setQuery({ domeniu: d, selector: selector === 'default' ? '' : selector });
    btn.disabled = true;
    live.appendChild(mk('div', 'it-busy', 'Asking the DNS servers about ' + d + '…'));
    var sels = [selector, 'hostingcp', 'default', 'google', 'selector1', 'selector2']
      .filter(function (s, i, a) { return a.indexOf(s) === i; });
    var jobs = {
      ns: doh(d, 'NS'), a: doh(d, 'A'), aaaa: doh(d, 'AAAA'), mx: doh(d, 'MX'), txt: doh(d, 'TXT'),
      dmarc: doh('_dmarc.' + d, 'TXT'), caa: doh(d, 'CAA')
    };
    sels.forEach(function (s) { jobs['dk_' + s] = doh(s + '._domainkey.' + d, 'TXT'); });
    var keys = Object.keys(jobs);
    Promise.all(keys.map(function (k) { return jobs[k].then(function (v) { return v; }, function () { return null; }); }))
      .then(function (vals) {
        var R = {};
        keys.forEach(function (k, i) { R[k] = vals[i]; });
        return analyse(d, nd.note, selector, sels, R);
      })
      .then(function (rep) { render(rep); }, function () {
        live.textContent = '';
        live.appendChild(rich(mk('div', 'it-err glass'), [{ b: 'We couldn\'t reach the DNS servers. ' },
          'Check your internet connection, or whether an ad blocker is stopping requests to cloudflare-dns.com and dns.google, then try again.']));
      })
      .then(function () { btn.disabled = false; });
  }

  function analyse(d, note, selector, sels, R) {
    var base = R.a || R.ns || R.mx;
    if (!base) throw new Error('fara raspuns');
    var rep = { d: d, note: note, sections: [], nx: false };
    if (base.status === 3) { rep.nx = true; return rep; }
    var S = function (id, title, sub, recs, dx, wide) {
      rep.sections.push({ id: id, title: title, sub: sub, recs: recs, dx: dx, wide: !!wide });
    };
    var fail = function (r) { return !r || r.status !== 0; };
    var servfail = [R.ns, R.a, R.mx].some(function (r) { return r && r.status === 2; });
    if (servfail) rep.servfail = true;

    /* --- NS --- */
    var ns = R.ns ? R.ns.ans.map(host) : [], dx = [];
    if (fail(R.ns)) dx.push({ k: 'bad', t: 'No answer for the nameservers (SERVFAIL). Usually: nameservers that are down, or a wrong DNSSEC setting at the registrar.' });
    else if (!ns.length) dx.push({ k: 'info', t: 'This name has no nameservers of its own. If it\'s a subdomain (for example mail.firma.ro), that\'s normal: it inherits them from the domain.' });
    else {
      if (ns.length === 1) dx.push({ k: 'warn', t: 'Only one nameserver. Registries usually require at least two, so the domain keeps working when one goes down.' });
      else dx.push({ k: 'ok', t: ns.length + ' nameservers respond.' });
      if (ns.some(function (n) { return NBT_NS.test(n); })) {
        dx.push({ k: 'info', t: ['The domain uses the NBT Host nameservers: SPF, DKIM and DMARC are set up automatically for email addresses hosted with us (', { t: 'how to check them', href: GUIDE + 'spf-dkim-dmarc' }, ').'] });
      }
    }
    S('ns', 'Nameservers', 'NS', ns, dx);

    /* --- A / AAAA --- */
    var a = R.a ? R.a.ans : [], aaaa = R.aaaa ? R.aaaa.ans : [];
    dx = [];
    if (!a.length) dx.push({ k: 'warn', t: 'No A record: ' + d + ' doesn\'t lead to any server, so the website won\'t open on the bare domain.' });
    else dx.push({ k: 'ok', t: 'The domain has ' + (a.length === 1 ? 'one IPv4 address' : a.length + ' IPv4 addresses') + '.' });
    if (a.indexOf(NBT_IP) >= 0) dx.push({ k: 'info', t: 'The address ' + NBT_IP + ' is the NBT Host server.' });
    if (!aaaa.length) dx.push({ k: 'info', t: 'No IPv6 (AAAA). That\'s not a mistake: visitors reach the website over IPv4.' });
    S('a', 'Website address', 'A / AAAA', a.map(function (x) { return 'A    ' + x; }).concat(aaaa.map(function (x) { return 'AAAA ' + x; })), dx);

    /* --- MX --- */
    var mx = (R.mx ? R.mx.ans : []).map(function (x) {
      var p = x.split(/\s+/);
      return { pr: +p[0], h: host(p[1] || '') };
    }).sort(function (x, y) { return x.pr - y.pr; });
    dx = [];
    if (!mx.length) dx.push({ k: 'warn', t: ['No MX: no server is set up to receive email for @' + d + '. If you want addresses on the domain, see ', { t: 'email on your domain', href: 'https://nbt-host.com/en/email-hosting' }, '.'] });
    else if (mx.length === 1 && mx[0].h === '') dx.push({ k: 'info', t: 'Null MX (“0 .”): the domain explicitly says it doesn\'t receive email.' });
    else {
      dx.push({ k: 'ok', t: mx.length === 1 ? 'One mail server receives the messages.' : mx.length + ' mail servers, in order of priority (the lower number is tried first).' });
      if (mx.some(function (m) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(m.h); })) dx.push({ k: 'bad', t: 'An MX record points to an IP address. MX must be a name (for example mail.' + d + '), not an IP.' });
    }
    S('mx', 'Receiving email', 'MX', mx.map(function (m) { return m.pr + ' ' + (m.h || '.'); }), dx);

    /* --- SPF --- */
    var txts = (R.txt ? R.txt.ans : []).map(txt), spf = spfOf(txts);
    var spfP = Promise.resolve(null);
    dx = [];
    if (fail(R.txt)) dx.push({ k: 'bad', t: 'We couldn\'t read the TXT records.' });
    else if (!spf.length) dx.push({ k: 'bad', t: ['SPF is missing: the servers receiving your messages have no way of knowing who is allowed to send on behalf of the domain. ', { t: 'Generate one', href: 'spf-dmarc-generator.html?domeniu=' + encodeURIComponent(d) }, '.'] });
    else if (spf.length > 1) dx.push({ k: 'bad', t: 'More than one SPF record (' + spf.length + '). A domain may have only one: with two, the check fails (permerror) and SPF no longer counts. Merge them into one.' });
    else {
      var rec = spf[0], terms = rec.split(/\s+/).slice(1).filter(Boolean), all = null, afterAll = false, unknown = [], ptr = false;
      terms.forEach(function (t) {
        var m = SPF_TERM.exec(t);
        if (/^(redirect|exp)=/i.test(t)) return;
        if (!m) { unknown.push(t); return; }
        if (all) afterAll = true;
        if (m[2].toLowerCase() === 'all') all = m[1] || '+';
        if (m[2].toLowerCase() === 'ptr') ptr = true;
      });
      var redir = /(^|\s)redirect=/i.test(rec);
      if (unknown.length) dx.push({ k: 'bad', t: ['A term SPF doesn\'t recognize: ', { c: unknown.join(' ') }, '. A single typo makes the whole record invalid.'] });
      if (all === '+') dx.push({ k: 'bad', t: ['Ends with ', { c: '+all' }, ': anyone in the world may send in your name. Replace it with ', { c: '~all' }, '.'] });
      else if (all === '?') dx.push({ k: 'warn', t: ['Ends with ', { c: '?all' }, ' (neutral): messages from other sources aren\'t flagged in any way. Safer is ', { c: '~all' }, '.'] });
      else if (all === '~') dx.push({ k: 'ok', t: ['Ends with ', { c: '~all' }, ': messages from unlisted sources are treated as suspicious.'] });
      else if (all === '-') dx.push({ k: 'ok', t: ['Ends with ', { c: '-all' }, ': messages from unlisted sources are rejected.'] });
      else if (redir) dx.push({ k: 'ok', t: ['No “all” of its own: ', { c: 'redirect=' + (/(?:^|\s)redirect=(\S+)/i.exec(rec) || ['', ''])[1] }, ' takes the rules from there.'] });
      else dx.push({ k: 'warn', t: ['No ', { c: '~all' }, ' or ', { c: '-all' }, ' at the end: SPF doesn\'t say what happens with all other servers.'] });
      if (afterAll) dx.push({ k: 'warn', t: 'Anything after “all” is ignored by the checking servers.' });
      if (ptr) dx.push({ k: 'warn', t: ['Uses ', { c: 'ptr' }, ', a slow mechanism the standard discourages. Replace it with ip4: / include:.'] });
      spfP = spfWalk(rec, { left: 20 }, {}, 0).then(function (c) {
        var o = [];
        if (c.n > 10) o.push({ k: 'bad', t: 'Too many DNS lookups: ' + c.n + ' (the limit is 10, nested includes included). Over the limit, SPF returns an error. Remove the services you no longer use.' });
        else o.push({ k: c.n > 8 ? 'warn' : 'ok', t: c.n + ' of the 10 DNS lookups allowed (a, mx, include, nested ones included).' });
        c.errs.forEach(function (e) { o.push({ k: 'bad', t: 'An include leads to a domain without a valid SPF record: ' + e + '.' }); });
        return o;
      }, function () { return []; });
    }
    var spfSec = { id: 'spf', title: 'SPF', sub: 'TXT on ' + d, recs: spf, dx: dx, wide: true };
    rep.sections.push(spfSec);

    /* --- DMARC --- */
    var dm = R.dmarc ? (R.dmarc.ans || []).map(txt).filter(function (t) { return /^v\s*=\s*DMARC1\s*(;|$)/i.test(t); }) : [];
    dx = [];
    if (R.dmarc && R.dmarc.status === 2) dx.push({ k: 'bad', t: 'No answer for _dmarc.' + d + ' (SERVFAIL).' });
    else if (!dm.length) dx.push({ k: 'warn', t: ['DMARC is missing. Gmail and Yahoo require it from bulk senders, and without it the domain is easier to use for fakes. ', { t: 'Generate one', href: 'spf-dmarc-generator.html?domeniu=' + encodeURIComponent(d) }, ' (start with p=none).'] });
    else if (dm.length > 1) dx.push({ k: 'bad', t: 'More than one DMARC record (' + dm.length + '): servers ignore all of them. Keep just one.' });
    else {
      var tg = tags(dm[0]), p = (tg.p || '').toLowerCase();
      if (!p) dx.push({ k: 'bad', t: ['Missing policy ', { c: 'p=' }, ': the record isn\'t valid.'] });
      else if (p === 'none') dx.push({ k: 'warn', t: [{ c: 'p=none' }, ': monitor only. It\'s the right first step, but it doesn\'t stop fakes. ', { t: 'How to move to quarantine and reject', href: GUIDE + 'dmarc-step-by-step' }, '.'] });
      else if (p === 'quarantine') dx.push({ k: 'ok', t: [{ c: 'p=quarantine' }, ': messages that fail the checks go to spam.'] });
      else if (p === 'reject') dx.push({ k: 'ok', t: [{ c: 'p=reject' }, ': messages that fail the checks are rejected.'] });
      else dx.push({ k: 'bad', t: ['The policy ', { c: 'p=' + p }, ' doesn\'t exist; the valid values are none, quarantine and reject.'] });
      if (tg.pct && +tg.pct < 100 && p && p !== 'none') dx.push({ k: 'info', t: ['The policy applies to only ' + tg.pct + '% of messages (', { c: 'pct=' + tg.pct }, ').'] });
      if (tg.sp) dx.push({ k: 'info', t: ['Subdomains have their own policy: ', { c: 'sp=' + tg.sp }, '.'] });
      if (!tg.rua) dx.push({ k: 'info', t: ['No ', { c: 'rua=' }, ': you don\'t get the daily reports, so you can\'t see who sends on behalf of the domain.'] });
      else dx.push({ k: 'ok', t: ['Reports go to ', { c: tg.rua.replace(/mailto:/gi, '') }, '.'] });
    }
    S('dmarc', 'DMARC', 'TXT on _dmarc.' + d, dm, dx, false);

    /* --- DKIM --- */
    var found = [];
    dx = [];
    sels.forEach(function (s) {
      var r = R['dk_' + s];
      if (!r || r.status !== 0) return;
      var k = r.ans.map(txt).filter(function (t) { return /(^|;)\s*p\s*=/i.test(t) || /^v=DKIM1/i.test(t); })[0];
      if (k) found.push({ s: s, rec: k });
    });
    if (!found.length) {
      dx.push({ k: 'warn', t: ['No DKIM key at the selectors we tried: ', { c: sels.join(', ') }, '. DKIM may exist under another selector: you can see it in the header of a message sent from the domain, in ', { c: 'DKIM-Signature' }, ', after ', { c: 's=' }, ', and enter it above, under “DKIM selector”. Without DKIM, ', { t: 'messages land in spam more easily', href: GUIDE + 'spf-dkim-dmarc' }, '.'] });
    } else if (!found.some(function (f) { return f.s === selector; })) {
      dx.push({ k: 'info', t: ['No key at the selector ', { c: selector }, '; we found it at the ' + (found.length === 1 ? 'selector above.' : 'selectors above.')] });
    }
    found.forEach(function (f) {
      var tg = tags(f.rec), kt = (tg.k || 'rsa').toLowerCase();
      if (!tg.p) { dx.push({ k: 'warn', t: ['Selector ', { c: f.s }, ': revoked key (empty p=). Messages signed with it no longer pass DKIM.'] }); return; }
      if (kt === 'ed25519') { dx.push({ k: 'ok', t: ['Selector ', { c: f.s }, ': Ed25519 key.'] }); return; }
      var bits = rsaBits(tg.p);
      if (bits && bits < 1024) dx.push({ k: 'bad', t: ['Selector ', { c: f.s }, ': RSA key of ' + bits + ' bits, too short. Generate a new 2048-bit key.'] });
      else if (bits && bits < 2048) dx.push({ k: 'warn', t: ['Selector ', { c: f.s }, ': RSA key of ' + bits + ' bits. It works, but the current recommendation is 2048.'] });
      else dx.push({ k: 'ok', t: ['Selector ', { c: f.s }, ': RSA key' + (bits ? ' of ' + bits + ' bits' : '') + '.'] });
    });
    S('dkim', 'DKIM', 'TXT on <selector>._domainkey.' + d, found.map(function (f) {
      return f.s + '  ' + (f.rec.length > 120 ? f.rec.slice(0, 117) + '…' : f.rec);
    }), dx, false);

    /* --- CAA --- */
    var caa = R.caa ? R.caa.ans : [];
    dx = [];
    if (!caa.length) dx.push({ k: 'info', t: 'No CAA: any authority may issue SSL certificates for the domain. That\'s the case for most domains.' });
    else {
      var issue = caa.filter(function (c) { return /^\d+\s+issue\s/i.test(c); });
      var le = issue.some(function (c) { return /letsencrypt\.org/i.test(c); });
      if (issue.length && !le) dx.push({ k: 'warn', t: ['CAA doesn\'t allow Let’s Encrypt: ', { t: 'the free SSL certificate', href: GUIDE + 'free-ssl-certificate' }, ' on your hosting can\'t be issued. Add ', { c: '0 issue "letsencrypt.org"' }, '.'] });
      else dx.push({ k: 'ok', t: 'CAA allows Let’s Encrypt, so the free SSL certificate can be issued.' });
    }
    S('caa', 'Allowed SSL certificates', 'CAA', caa, dx, false);

    return spfP.then(function (extra) {
      if (extra) spfSec.dx = spfSec.dx.concat(extra);
      return rep;
    });
  }

  function render(rep) {
    live.textContent = '';
    if (rep.nx) {
      live.appendChild(rich(mk('div', 'it-err glass'), [{ b: rep.d + ' doesn\'t exist in DNS. ' },
        'It isn\'t registered or it has expired (the answer is NXDOMAIN). If you want it, ',
        { t: 'check whether it\'s available', href: 'https://nbt-host.com/en/tools/domain-checker?domeniu=' + encodeURIComponent(rep.d) }, '.']));
      return;
    }
    var all = [];
    rep.sections.forEach(function (s) { all = all.concat(s.dx); });
    var n = { ok: 0, warn: 0, bad: 0 };
    all.forEach(function (x) { if (n[x.k] != null) n[x.k]++; });
    var sum = mk('div', 'it-sum glass');
    var sd = mk('div', 'it-sum-d');
    sd.appendChild(mk('small', null, 'Result for'));
    sd.appendChild(mk('b', null, rep.d));
    var verdict = n.bad ? n.bad + (n.bad === 1 ? ' problem to fix' : ' problems to fix') + (n.warn ? ', ' + n.warn + ' to check.' : '.')
      : n.warn ? 'No errors, ' + n.warn + (n.warn === 1 ? ' thing to check.' : ' things to check.') : 'Everything looks good.';
    sd.appendChild(mk('p', null, verdict + (rep.note === 'www' ? ' We checked the domain without “www.”: that\'s where MX, SPF and DMARC live.' : '')));
    sum.appendChild(sd);
    var sn = mk('div', 'it-sum-n');
    [['ok', 'OK'], ['warn', 'to check'], ['bad', 'to fix']].forEach(function (x) {
      var s = mk('span', 'it-' + x[0]);
      s.appendChild(icon(x[0]));
      s.appendChild(mk('b', null, String(n[x[0]])));
      s.appendChild(doc.createTextNode(x[1]));
      sn.appendChild(s);
    });
    sum.appendChild(sn);
    var sa = mk('div', 'it-sum-a');
    var cb = mk('button', 'btn sm ghost');
    cb.type = 'button';
    cb.innerHTML = '<span class="lbl"><i data-l="Copy the report">Copy the report</i></span>';
    cb.addEventListener('click', function () { copyText(report(rep), cb, 'Copied'); });
    sa.appendChild(cb);
    sum.appendChild(sa);
    live.appendChild(sum);

    /* two columns: NS + A, MX + CAA, then SPF across, then DMARC + DKIM (no hole in the grid) */
    var ORD = ['ns', 'a', 'mx', 'caa', 'spf', 'dmarc', 'dkim'];
    rep.sections.sort(function (x, y) { return ORD.indexOf(x.id) - ORD.indexOf(y.id); });
    var grid = mk('div', 'it-grid');
    rep.sections.forEach(function (s) {
      var c = mk('section', 'it-card glass' + (s.wide ? ' it-card-wide' : ''));
      c.setAttribute('aria-labelledby', 'it-h-' + s.id);
      var h = mk('div', 'it-card-h'), h3 = mk('h3', null, s.title);
      h3.id = 'it-h-' + s.id;
      h3.appendChild(mk('small', null, s.sub));
      h.appendChild(h3);
      h.appendChild(badge(worst(s.dx)));
      c.appendChild(h);
      if (s.recs.length) {
        var ul = mk('ul', 'it-recs');
        s.recs.forEach(function (r) { ul.appendChild(mk('li', null, r)); });
        c.appendChild(ul);
      } else c.appendChild(mk('p', 'it-recs-e', 'No records.'));
      var dl = mk('ul', 'it-dx');
      s.dx.forEach(function (x) {
        var li = mk('li', 'it-' + x.k);
        li.appendChild(icon(x.k));
        var sp = mk('span');
        sp.appendChild(mk('span', 'sr-only', WORD[x.k] + ': '));
        rich(sp, x.t);
        li.appendChild(sp);
        dl.appendChild(li);
      });
      c.appendChild(dl);
      grid.appendChild(c);
    });
    live.appendChild(grid);
    var top = out.getBoundingClientRect().top;
    if (top > win.innerHeight * .8 || top < 0) out.scrollIntoView({ behavior: win.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  }

  function flat(t) {
    return (Array.isArray(t) ? t : [t]).map(function (p) { return typeof p === 'string' ? p : (p.t || p.b || p.c || ''); }).join('');
  }
  function report(rep) {
    var L = ['DNS and email check for ' + rep.d + ' — ' + new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC',
      'https://nbt-host.com/en/tools/dns-email-checker?domeniu=' + encodeURIComponent(rep.d), ''];
    rep.sections.forEach(function (s) {
      L.push('== ' + s.title + ' (' + s.sub + ') — ' + WORD[worst(s.dx)]);
      s.recs.forEach(function (r) { L.push('   ' + r); });
      s.dx.forEach(function (x) { L.push(' [' + WORD[x.k] + '] ' + flat(x.t)); });
      L.push('');
    });
    return L.join('\n');
  }
}

/* =============================================================
   2. SPF / DMARC GENERATOR (local only)
   ============================================================= */
function genInit() {
  var f = $('#itGen');
  if (!f) return;
  var q = getQuery('domeniu');
  if (q && normDomain(q)) $('#gDom').value = normDomain(q).d;
  var IP4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}(\/([0-9]|[12]\d|3[0-2]))?$/;
  var IP6 = /^[0-9a-f:]+(\/(\d|[1-9]\d|1[01]\d|12[0-8]))?$/i;
  var EMAIL = /^[^\s@,;]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;
  function val(id) { var e = $('#' + id); return e ? String(e.value || '').trim() : ''; }
  function on(id) { var e = $('#' + id); return !!(e && e.checked); }
  function radio(name) { var e = $('input[name="' + name + '"]:checked', f); return e ? e.value : ''; }
  function list(s) { return s.split(/[\s,;]+/).map(function (x) { return x.trim(); }).filter(Boolean); }
  function msgs(ul, items) {
    ul.textContent = '';
    items.forEach(function (x) {
      var li = mk('li', 'it-' + x.k);
      li.appendChild(icon(x.k));
      var sp = mk('span');
      sp.appendChild(mk('span', 'sr-only', WORD[x.k] + ': '));
      rich(sp, x.t);
      li.appendChild(sp);
      ul.appendChild(li);
    });
  }
  function build() {
    var nd = normDomain(val('gDom')), d = nd ? nd.d : '';
    $$('[data-g-dom]').forEach(function (e) { e.textContent = d || 'your-domain.com'; });
    $$('[data-g-at]').forEach(function (e) { e.textContent = d ? d + ' (or @)' : '@ (the bare domain)'; });
    $$('[data-g-dmarc]').forEach(function (e) { e.textContent = d ? '_dmarc.' + d + ' (or _dmarc)' : '_dmarc'; });

    /* SPF */
    var t = ['v=spf1'], m = [], look = 0, seen = {};
    function add(x) { if (!seen[x.toLowerCase()]) { seen[x.toLowerCase()] = 1; t.push(x); } }
    if (on('gNbt')) { add('a'); add('mx'); look += 2; }
    if (on('gNbtIp')) add('ip4:' + NBT_IP);
    if (on('gGoogle')) { add('include:_spf.google.com'); look++; }
    if (on('gMs')) { add('include:spf.protection.outlook.com'); look++; }
    var badIp = [];
    list(val('gIp')).forEach(function (ip) {
      if (IP4.test(ip)) add('ip4:' + ip);
      else if (ip.indexOf(':') > 0 && IP6.test(ip)) add('ip6:' + ip);
      else badIp.push(ip);
    });
    var badInc = [];
    list(val('gInc')).forEach(function (x) {
      var h = x.replace(/^include:/i, '').toLowerCase();
      if (normDomain(h) && normDomain(h).d === h) { add('include:' + h); look++; } else badInc.push(x);
    });
    var allQ = radio('gAll') || '~all';
    t.push(allQ);
    var spf = t.join(' ');
    $('#gSpf').textContent = spf;
    if (t.length === 2) m.push({ k: 'bad', t: ['No source ticked: ', { c: 'v=spf1 ' + allQ }, ' says that no server may send on behalf of the domain. Tick at least your mail server.'] });
    if (badIp.length) m.push({ k: 'bad', t: ['Not valid IP addresses (left out): ', { c: badIp.join(' ') }] });
    if (badInc.length) m.push({ k: 'bad', t: ['Not valid domain names (left out): ', { c: badInc.join(' ') }] });
    m.push({ k: look > 10 ? 'bad' : 'ok', t: [look + ' top-level DNS lookups (the limit is 10). Each include can add a few more: once published, check the total with the ', { t: 'DNS and email check', href: 'index.html' + (d ? '?domeniu=' + encodeURIComponent(d) : '') }, '.'] });
    if (allQ === '-all') m.push({ k: 'info', t: [{ c: '-all' }, ' rejects everything not on the list. Use it only once you\'re sure you\'ve listed every service that sends on your behalf.'] });
    if (allQ === '?all') m.push({ k: 'warn', t: [{ c: '?all' }, ' doesn\'t flag messages from other sources in any way. The usual choice is ', { c: '~all' }, '.'] });
    if (spf.length > 255) m.push({ k: 'info', t: 'It\'s longer than 255 characters: some DNS editors require you to split it into quoted chunks. The Enhance editor and Cloudflare split it automatically.' });
    m.push({ k: 'info', t: 'A domain may have only one SPF record. If one already exists, edit that one instead of adding another.' });
    msgs($('#gSpfMsg'), m);

    /* DMARC */
    var p = radio('gP') || 'none', d2 = ['v=DMARC1', 'p=' + p], m2 = [];
    var sp = val('gSp');
    if (sp && sp !== p) d2.push('sp=' + sp);
    var pct = parseInt(val('gPct'), 10);
    if (p !== 'none' && pct >= 1 && pct < 100) d2.push('pct=' + pct);
    var rua = list(val('gRua')), badRua = [];
    rua = rua.map(function (x) { return x.replace(/^mailto:/i, ''); }).filter(function (x) {
      if (EMAIL.test(x)) return true;
      badRua.push(x);
      return false;
    });
    if (rua.length) d2.push('rua=' + rua.map(function (x) { return 'mailto:' + x; }).join(','));
    if (radio('gAdkim') === 's') d2.push('adkim=s');
    if (radio('gAspf') === 's') d2.push('aspf=s');
    var dm = d2.join('; ');
    $('#gDmarc').textContent = dm;
    if (badRua.length) m2.push({ k: 'bad', t: ['Not valid email addresses (left out): ', { c: badRua.join(' ') }] });
    if (p === 'none') m2.push({ k: 'info', t: [{ c: 'p=none' }, ' only monitors: it blocks nothing, so it\'s the safe start. ', { t: 'How to move gradually to quarantine and reject', href: GUIDE + 'dmarc-step-by-step' }, '.'] });
    if (p === 'reject') m2.push({ k: 'warn', t: [{ c: 'p=reject' }, ' rejects any message that fails SPF and DKIM. Move here only after a few weeks of reports with no surprises.'] });
    if (!rua.length) m2.push({ k: 'warn', t: 'Without a report address you won\'t find out who sends on behalf of the domain. We recommend a separate mailbox, for example dmarc@' + (d || 'your-domain.com') + '.' });
    else if (d) {
      rua.forEach(function (x) {
        var h = x.split('@')[1].toLowerCase();
        if (h === d || h.slice(-(d.length + 1)) === '.' + d) return;
        m2.push({ k: 'info', t: ['Reports for ' + x + ' go to another domain: ' + h + ' has to accept them, with a TXT record ', { c: d + '._report._dmarc.' + h }, ' that contains ', { c: 'v=DMARC1' }, '. DMARC analysis services set it up themselves.'] });
      });
    }
    if (p !== 'none' && pct >= 1 && pct < 100) m2.push({ k: 'info', t: 'The policy applies to ' + pct + '% of failing messages; the rest are treated as with ' + (p === 'reject' ? 'p=quarantine (they go to spam).' : 'p=none.') });
    msgs($('#gDmarcMsg'), m2);
    $$('[data-g-check]').forEach(function (a) { a.href = 'index.html' + (d ? '?domeniu=' + encodeURIComponent(d) : ''); });
  }
  f.addEventListener('input', build);
  f.addEventListener('change', build);
  f.addEventListener('submit', function (e) { e.preventDefault(); build(); });
  $$('[data-g-copy]').forEach(function (b) {
    b.addEventListener('click', function () { copyText($('#' + b.getAttribute('data-g-copy')).textContent, b); });
  });
  build();
}


if (KIND === 'dns') dnsInit();
else if (KIND === 'gen') genInit();
})();
