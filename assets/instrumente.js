/*! verificare-dns-email — NBT Host (https://nbt-host.com), licență MIT.
    Verificare DNS și email (A, AAAA, NS, MX, SPF, DKIM, DMARC, CAA) prin DNS-over-HTTPS și generator SPF / DMARC.
    Rulează în întregime în browser: întrebările DNS pleacă direct la Cloudflare (1.1.1.1), cu Google Public DNS ca rezervă. */
(function () {
'use strict';

var doc = document, win = window;
var main = doc.querySelector('[data-it]');
if (!main) return;
var KIND = main.getAttribute('data-it');
var $ = function (s, c) { return (c || doc).querySelector(s); };
var $$ = function (s, c) { return Array.prototype.slice.call((c || doc).querySelectorAll(s)); };
var GUIDE = 'https://nbt-host.com/ghiduri/';
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
var WORD = { ok: 'În regulă', warn: 'Atenție', bad: 'Problemă', info: 'Info' };
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
    lbl.textContent = okLabel || 'Copiat';
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
  var b = mk('button', 'gd-copy', label || 'Copiază');
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
      return { n: 0, errs: [domain + (recs.length > 1 ? ' are mai multe înregistrări SPF' : ' nu are înregistrare SPF')] };
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
      live.appendChild(rich(mk('div', 'it-err glass'), [{ b: 'Adresa nu arată ca un domeniu. ' },
        'Scrie doar numele, de exemplu ', { c: 'firma-ta.ro' }, ' (fără spații; „https://”, „www.” și o adresă de email le curățăm noi).']));
      return;
    }
    var d = nd.d;
    var selector = String(selRaw || '').trim().toLowerCase().replace(/\._domainkey.*$/, '') || 'default';
    if (!/^[a-z0-9](?:[a-z0-9._-]{0,62})$/.test(selector)) selector = 'default';
    if (sel) sel.value = selector;
    inp.value = d;
    setQuery({ domeniu: d, selector: selector === 'default' ? '' : selector });
    btn.disabled = true;
    live.appendChild(mk('div', 'it-busy', 'Întrebăm serverele DNS despre ' + d + '…'));
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
        live.appendChild(rich(mk('div', 'it-err glass'), [{ b: 'Nu am putut întreba serverele DNS. ' },
          'Verifică legătura la internet sau dacă un blocant de reclame oprește cererile spre cloudflare-dns.com și dns.google, apoi încearcă din nou.']));
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
    if (fail(R.ns)) dx.push({ k: 'bad', t: 'Nu am primit răspuns la nameservere (SERVFAIL). De obicei: nameservere oprite sau DNSSEC greșit la registrar.' });
    else if (!ns.length) dx.push({ k: 'info', t: 'Numele nu are nameservere proprii. Dacă e un subdomeniu (de exemplu mail.firma.ro), e normal: le moștenește de la domeniu.' });
    else {
      if (ns.length === 1) dx.push({ k: 'warn', t: 'Un singur nameserver. Registrele cer de obicei cel puțin două, ca domeniul să meargă și când unul cade.' });
      else dx.push({ k: 'ok', t: ns.length + ' nameservere răspund.' });
      if (ns.some(function (n) { return NBT_NS.test(n); })) {
        dx.push({ k: 'info', t: ['Domeniul folosește nameserverele NBT Host: SPF, DKIM și DMARC se pun automat la adresele de email găzduite la noi (', { t: 'cum le verifici', href: GUIDE + 'mailuri-in-spam-spf-dkim-dmarc' }, ').'] });
      }
    }
    S('ns', 'Nameservere', 'NS', ns, dx);

    /* --- A / AAAA --- */
    var a = R.a ? R.a.ans : [], aaaa = R.aaaa ? R.aaaa.ans : [];
    dx = [];
    if (!a.length) dx.push({ k: 'warn', t: 'Fără înregistrare A: adresa ' + d + ' nu duce la niciun server, deci site-ul nu se deschide pe domeniul gol.' });
    else dx.push({ k: 'ok', t: 'Domeniul are ' + (a.length === 1 ? 'o adresă IPv4' : a.length + ' adrese IPv4') + '.' });
    if (a.indexOf(NBT_IP) >= 0) dx.push({ k: 'info', t: 'Adresa ' + NBT_IP + ' e serverul NBT Host.' });
    if (!aaaa.length) dx.push({ k: 'info', t: 'Fără IPv6 (AAAA). Nu e o greșeală: vizitatorii ajung la site prin IPv4.' });
    S('a', 'Adresa site-ului', 'A / AAAA', a.map(function (x) { return 'A    ' + x; }).concat(aaaa.map(function (x) { return 'AAAA ' + x; })), dx);

    /* --- MX --- */
    var mx = (R.mx ? R.mx.ans : []).map(function (x) {
      var p = x.split(/\s+/);
      return { pr: +p[0], h: host(p[1] || '') };
    }).sort(function (x, y) { return x.pr - y.pr; });
    dx = [];
    if (!mx.length) dx.push({ k: 'warn', t: ['Fără MX: nu e configurat niciun server care să primească emailurile pentru @' + d + '. Dacă vrei adrese pe domeniu, vezi ', { t: 'emailul pe domeniu', href: 'https://nbt-host.com/email' }, '.'] });
    else if (mx.length === 1 && mx[0].h === '') dx.push({ k: 'info', t: 'MX nul („0 .”): domeniul spune explicit că nu primește emailuri.' });
    else {
      dx.push({ k: 'ok', t: mx.length === 1 ? 'Un server de email primește mesajele.' : mx.length + ' servere de email, în ordinea priorității (numărul mai mic e încercat primul).' });
      if (mx.some(function (m) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(m.h); })) dx.push({ k: 'bad', t: 'Un MX arată spre o adresă IP. MX trebuie să fie un nume (de exemplu mail.' + d + '), nu un IP.' });
    }
    S('mx', 'Primirea emailului', 'MX', mx.map(function (m) { return m.pr + ' ' + (m.h || '.'); }), dx);

    /* --- SPF --- */
    var txts = (R.txt ? R.txt.ans : []).map(txt), spf = spfOf(txts);
    var spfP = Promise.resolve(null);
    dx = [];
    if (fail(R.txt)) dx.push({ k: 'bad', t: 'Nu am putut citi înregistrările TXT.' });
    else if (!spf.length) dx.push({ k: 'bad', t: ['SPF lipsește: serverele care primesc mesajele tale nu au de unde ști cine are voie să trimită în numele domeniului. ', { t: 'Generează unul', href: 'generator-spf-dmarc.html?domeniu=' + encodeURIComponent(d) }, '.'] });
    else if (spf.length > 1) dx.push({ k: 'bad', t: 'Mai multe înregistrări SPF (' + spf.length + '). Un domeniu are voie la una singură: cu două, verificarea dă eroare (permerror) și SPF nu mai contează. Unește-le într-una.' });
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
      if (unknown.length) dx.push({ k: 'bad', t: ['Termen pe care SPF nu-l cunoaște: ', { c: unknown.join(' ') }, '. O greșeală de scriere face toată înregistrarea invalidă.'] });
      if (all === '+') dx.push({ k: 'bad', t: ['Se termină cu ', { c: '+all' }, ': oricine din lume are voie să trimită în numele tău. Înlocuiește cu ', { c: '~all' }, '.'] });
      else if (all === '?') dx.push({ k: 'warn', t: ['Se termină cu ', { c: '?all' }, ' (neutru): mesajele din alte surse nu sunt marcate în niciun fel. Mai sigur e ', { c: '~all' }, '.'] });
      else if (all === '~') dx.push({ k: 'ok', t: ['Se termină cu ', { c: '~all' }, ': mesajele din surse nelistate sunt tratate ca suspecte.'] });
      else if (all === '-') dx.push({ k: 'ok', t: ['Se termină cu ', { c: '-all' }, ': mesajele din surse nelistate sunt respinse.'] });
      else if (redir) dx.push({ k: 'ok', t: ['Fără „all” propriu: ', { c: 'redirect=' + (/(?:^|\s)redirect=(\S+)/i.exec(rec) || ['', ''])[1] }, ' preia regulile de acolo.'] });
      else dx.push({ k: 'warn', t: ['Fără ', { c: '~all' }, ' sau ', { c: '-all' }, ' la final: SPF nu spune ce se întâmplă cu restul serverelor.'] });
      if (afterAll) dx.push({ k: 'warn', t: 'Ce urmează după „all” e ignorat de serverele care verifică.' });
      if (ptr) dx.push({ k: 'warn', t: ['Folosește ', { c: 'ptr' }, ', un mecanism lent, pe care standardul îl descurajează. Înlocuiește-l cu ip4: / include:.'] });
      spfP = spfWalk(rec, { left: 20 }, {}, 0).then(function (c) {
        var o = [];
        if (c.n > 10) o.push({ k: 'bad', t: 'Prea multe căutări DNS: ' + c.n + ' (limita e 10, cu include-urile imbricate). Peste limită, SPF dă eroare. Scoate serviciile pe care nu le mai folosești.' });
        else o.push({ k: c.n > 8 ? 'warn' : 'ok', t: c.n + ' din 10 căutări DNS permise (a, mx, include, cu tot cu cele imbricate).' });
        c.errs.forEach(function (e) { o.push({ k: 'bad', t: 'Un include duce la un domeniu fără SPF valid: ' + e + '.' }); });
        return o;
      }, function () { return []; });
    }
    var spfSec = { id: 'spf', title: 'SPF', sub: 'TXT pe ' + d, recs: spf, dx: dx, wide: true };
    rep.sections.push(spfSec);

    /* --- DMARC --- */
    var dm = R.dmarc ? (R.dmarc.ans || []).map(txt).filter(function (t) { return /^v\s*=\s*DMARC1\s*(;|$)/i.test(t); }) : [];
    dx = [];
    if (R.dmarc && R.dmarc.status === 2) dx.push({ k: 'bad', t: 'Nu am primit răspuns pentru _dmarc.' + d + ' (SERVFAIL).' });
    else if (!dm.length) dx.push({ k: 'warn', t: ['DMARC lipsește. Gmail și Yahoo îl cer celor care trimit multe mesaje, iar fără el domeniul poate fi folosit mai ușor în falsuri. ', { t: 'Generează unul', href: 'generator-spf-dmarc.html?domeniu=' + encodeURIComponent(d) }, ' (pornești cu p=none).'] });
    else if (dm.length > 1) dx.push({ k: 'bad', t: 'Mai multe înregistrări DMARC (' + dm.length + '): serverele le ignoră pe toate. Păstrează una singură.' });
    else {
      var tg = tags(dm[0]), p = (tg.p || '').toLowerCase();
      if (!p) dx.push({ k: 'bad', t: ['Lipsește politica ', { c: 'p=' }, ': înregistrarea nu e validă.'] });
      else if (p === 'none') dx.push({ k: 'warn', t: [{ c: 'p=none' }, ': doar observă. E pasul bun de început, dar nu oprește falsurile. ', { t: 'Cum treci la quarantine și reject', href: GUIDE + 'dmarc-pas-cu-pas' }, '.'] });
      else if (p === 'quarantine') dx.push({ k: 'ok', t: [{ c: 'p=quarantine' }, ': mesajele care pică verificările ajung în spam.'] });
      else if (p === 'reject') dx.push({ k: 'ok', t: [{ c: 'p=reject' }, ': mesajele care pică verificările sunt respinse.'] });
      else dx.push({ k: 'bad', t: ['Politica ', { c: 'p=' + p }, ' nu există; valorile corecte sunt none, quarantine și reject.'] });
      if (tg.pct && +tg.pct < 100 && p && p !== 'none') dx.push({ k: 'info', t: ['Politica se aplică doar la ' + tg.pct + '% din mesaje (', { c: 'pct=' + tg.pct }, ').'] });
      if (tg.sp) dx.push({ k: 'info', t: ['Subdomeniile au politica lor: ', { c: 'sp=' + tg.sp }, '.'] });
      if (!tg.rua) dx.push({ k: 'info', t: ['Fără ', { c: 'rua=' }, ': nu primești rapoartele zilnice, deci nu vezi cine trimite în numele domeniului.'] });
      else dx.push({ k: 'ok', t: ['Rapoartele merg la ', { c: tg.rua.replace(/mailto:/gi, '') }, '.'] });
    }
    S('dmarc', 'DMARC', 'TXT pe _dmarc.' + d, dm, dx, false);

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
      dx.push({ k: 'warn', t: ['Nicio cheie DKIM la selectoarele încercate: ', { c: sels.join(', ') }, '. DKIM poate exista sub alt selector: îl vezi în antetul unui mesaj trimis de pe domeniu, la ', { c: 'DKIM-Signature' }, ', după ', { c: 's=' }, ', și îl scrii sus, la „Selector DKIM”. Fără DKIM, ', { t: 'mesajele ajung mai ușor în spam', href: GUIDE + 'mailuri-in-spam-spf-dkim-dmarc' }, '.'] });
    } else if (!found.some(function (f) { return f.s === selector; })) {
      dx.push({ k: 'info', t: ['Nicio cheie la selectorul ', { c: selector }, '; am găsit-o la ' + (found.length === 1 ? 'selectorul de mai sus.' : 'selectoarele de mai sus.')] });
    }
    found.forEach(function (f) {
      var tg = tags(f.rec), kt = (tg.k || 'rsa').toLowerCase();
      if (!tg.p) { dx.push({ k: 'warn', t: ['Selectorul ', { c: f.s }, ': cheie revocată (p= gol). Mesajele semnate cu ea nu mai trec DKIM.'] }); return; }
      if (kt === 'ed25519') { dx.push({ k: 'ok', t: ['Selectorul ', { c: f.s }, ': cheie Ed25519.'] }); return; }
      var bits = rsaBits(tg.p);
      if (bits && bits < 1024) dx.push({ k: 'bad', t: ['Selectorul ', { c: f.s }, ': cheie RSA de ' + bits + ' de biți, prea scurtă. Generează una nouă, de 2048.'] });
      else if (bits && bits < 2048) dx.push({ k: 'warn', t: ['Selectorul ', { c: f.s }, ': cheie RSA de ' + bits + ' de biți. Merge, dar recomandarea actuală e 2048.'] });
      else dx.push({ k: 'ok', t: ['Selectorul ', { c: f.s }, ': cheie RSA' + (bits ? ' de ' + bits + ' de biți' : '') + '.'] });
    });
    S('dkim', 'DKIM', 'TXT pe <selector>._domainkey.' + d, found.map(function (f) {
      return f.s + '  ' + (f.rec.length > 120 ? f.rec.slice(0, 117) + '…' : f.rec);
    }), dx, false);

    /* --- CAA --- */
    var caa = R.caa ? R.caa.ans : [];
    dx = [];
    if (!caa.length) dx.push({ k: 'info', t: 'Fără CAA: orice autoritate poate emite certificate SSL pentru domeniu. E situația celor mai multe domenii.' });
    else {
      var issue = caa.filter(function (c) { return /^\d+\s+issue\s/i.test(c); });
      var le = issue.some(function (c) { return /letsencrypt\.org/i.test(c); });
      if (issue.length && !le) dx.push({ k: 'warn', t: ['CAA nu permite Let’s Encrypt: ', { t: 'certificatul SSL gratuit', href: GUIDE + 'certificat-ssl-gratuit' }, ' de pe găzduire nu se poate emite. Adaugă ', { c: '0 issue "letsencrypt.org"' }, '.'] });
      else dx.push({ k: 'ok', t: 'CAA permite Let’s Encrypt, deci certificatul SSL gratuit se poate emite.' });
    }
    S('caa', 'Certificate SSL permise', 'CAA', caa, dx, false);

    return spfP.then(function (extra) {
      if (extra) spfSec.dx = spfSec.dx.concat(extra);
      return rep;
    });
  }

  function render(rep) {
    live.textContent = '';
    if (rep.nx) {
      live.appendChild(rich(mk('div', 'it-err glass'), [{ b: rep.d + ' nu există în DNS. ' },
        'Nu e înregistrat sau a expirat (răspunsul e NXDOMAIN). Dacă vrei să-l iei, ',
        { t: 'verifică dacă e liber', href: 'https://nbt-host.com/instrumente/verificare-domeniu?domeniu=' + encodeURIComponent(rep.d) }, '.']));
      return;
    }
    var all = [];
    rep.sections.forEach(function (s) { all = all.concat(s.dx); });
    var n = { ok: 0, warn: 0, bad: 0 };
    all.forEach(function (x) { if (n[x.k] != null) n[x.k]++; });
    var sum = mk('div', 'it-sum glass');
    var sd = mk('div', 'it-sum-d');
    sd.appendChild(mk('small', null, 'Rezultat pentru'));
    sd.appendChild(mk('b', null, rep.d));
    var verdict = n.bad ? n.bad + (n.bad === 1 ? ' problemă de reparat' : ' probleme de reparat') + (n.warn ? ', ' + n.warn + ' de verificat.' : '.')
      : n.warn ? 'Nicio eroare, ' + n.warn + (n.warn === 1 ? ' lucru de verificat.' : ' lucruri de verificat.') : 'Totul arată bine.';
    sd.appendChild(mk('p', null, verdict + (rep.note === 'www' ? ' Am verificat domeniul fără „www.”: acolo stau MX, SPF și DMARC.' : '')));
    sum.appendChild(sd);
    var sn = mk('div', 'it-sum-n');
    [['ok', 'în regulă'], ['warn', 'de verificat'], ['bad', 'de reparat']].forEach(function (x) {
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
    cb.innerHTML = '<span class="lbl"><i data-l="Copiază raportul">Copiază raportul</i></span>';
    cb.addEventListener('click', function () { copyText(report(rep), cb, 'Copiat'); });
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
      } else c.appendChild(mk('p', 'it-recs-e', 'Nicio înregistrare.'));
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
    var L = ['Verificare DNS și email pentru ' + rep.d + ' — ' + new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC',
      'https://nbt-host.com/instrumente/verificare-dns-email?domeniu=' + encodeURIComponent(rep.d), ''];
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
    $$('[data-g-dom]').forEach(function (e) { e.textContent = d || 'domeniul-tau.ro'; });
    $$('[data-g-at]').forEach(function (e) { e.textContent = d ? d + ' (sau @)' : '@ (domeniul gol)'; });
    $$('[data-g-dmarc]').forEach(function (e) { e.textContent = d ? '_dmarc.' + d + ' (sau _dmarc)' : '_dmarc'; });

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
    if (t.length === 2) m.push({ k: 'bad', t: ['Nicio sursă bifată: ', { c: 'v=spf1 ' + allQ }, ' spune că niciun server nu are voie să trimită în numele domeniului. Bifează măcar serverul tău de email.'] });
    if (badIp.length) m.push({ k: 'bad', t: ['Nu sunt adrese IP valide (le-am lăsat afară): ', { c: badIp.join(' ') }] });
    if (badInc.length) m.push({ k: 'bad', t: ['Nu sunt nume de domeniu valide (le-am lăsat afară): ', { c: badInc.join(' ') }] });
    m.push({ k: look > 10 ? 'bad' : 'ok', t: [look + ' căutări DNS la primul nivel (limita e 10). Fiecare include poate adăuga și el câteva: după publicare, verifică totalul cu ', { t: 'verificarea DNS și email', href: 'index.html' + (d ? '?domeniu=' + encodeURIComponent(d) : '') }, '.'] });
    if (allQ === '-all') m.push({ k: 'info', t: [{ c: '-all' }, ' respinge tot ce nu e în listă. Pune-l doar după ce ești sigur că ai trecut toate serviciile care trimit în numele tău.'] });
    if (allQ === '?all') m.push({ k: 'warn', t: [{ c: '?all' }, ' nu marchează în niciun fel mesajele din alte surse. Varianta obișnuită e ', { c: '~all' }, '.'] });
    if (spf.length > 255) m.push({ k: 'info', t: 'Are peste 255 de caractere: unele editoare DNS cer să o împarți în bucăți între ghilimele. Editorul din Enhance și Cloudflare o împart singure.' });
    m.push({ k: 'info', t: 'Un domeniu are voie la o singură înregistrare SPF. Dacă există deja una, o modifici pe aceea, nu adaugi încă una.' });
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
    if (badRua.length) m2.push({ k: 'bad', t: ['Nu sunt adrese de email valide (le-am lăsat afară): ', { c: badRua.join(' ') }] });
    if (p === 'none') m2.push({ k: 'info', t: [{ c: 'p=none' }, ' doar observă: nu blochează nimic, deci e începutul sigur. ', { t: 'Cum treci treptat la quarantine și reject', href: GUIDE + 'dmarc-pas-cu-pas' }, '.'] });
    if (p === 'reject') m2.push({ k: 'warn', t: [{ c: 'p=reject' }, ' respinge orice mesaj care pică SPF și DKIM. Treci aici doar după câteva săptămâni de rapoarte fără surprize.'] });
    if (!rua.length) m2.push({ k: 'warn', t: 'Fără adresă de rapoarte nu afli cine trimite în numele domeniului. Recomandăm o căsuță separată, de exemplu dmarc@' + (d || 'domeniul-tau.ro') + '.' });
    else if (d) {
      rua.forEach(function (x) {
        var h = x.split('@')[1].toLowerCase();
        if (h === d || h.slice(-(d.length + 1)) === '.' + d) return;
        m2.push({ k: 'info', t: ['Rapoartele pentru ' + x + ' merg pe alt domeniu: ' + h + ' trebuie să le accepte, cu o înregistrare TXT ', { c: d + '._report._dmarc.' + h }, ' care conține ', { c: 'v=DMARC1' }, '. Serviciile de analiză DMARC o pun singure.'] });
      });
    }
    if (p !== 'none' && pct >= 1 && pct < 100) m2.push({ k: 'info', t: 'Politica se aplică la ' + pct + '% din mesajele care pică; restul sunt tratate ca la ' + (p === 'reject' ? 'p=quarantine (ajung în spam).' : 'p=none.') });
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
