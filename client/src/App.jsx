import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldCheck, Plus, RefreshCw, Trash2, Bell, Pause, Play, X, History,
  Globe, LogOut, Link2, AlertTriangle, ChevronDown, ChevronUp
} from 'lucide-react';
import { api, fmtDate } from './api.js';

const STATUS_STYLES = {
  green: 'bg-emerald-500',
  yellow: 'bg-amber-400',
  red: 'bg-red-500',
  paused: 'bg-zinc-600'
};

function Login({ onOk }) {
  const [pw, setPw] = useState('');
  const [err, setErr] = useState('');
  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <motion.form initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-sm bg-zinc-900/50 border border-zinc-800 rounded-2xl p-8 space-y-4"
        onSubmit={async (e) => {
          e.preventDefault();
          try { await api.login(pw); onOk(); } catch (x) { setErr(x.message); }
        }}>
        <div className="flex items-center gap-3">
          <div className="bg-sky-600/20 border border-sky-500/30 rounded-xl p-2.5"><ShieldCheck className="text-sky-400" size={22} /></div>
          <div>
            <h1 className="text-lg font-semibold">Certwatch</h1>
            <p className="text-xs text-zinc-500">No more 2am expired-cert pages.</p>
          </div>
        </div>
        <input type="password" placeholder="admin password" value={pw} onChange={(e) => setPw(e.target.value)} autoFocus />
        {err && <p className="text-xs text-red-400">{err}</p>}
        <button className="btn-primary w-full justify-center">Sign in</button>
      </motion.form>
    </div>
  );
}

function DomainModal({ initial, onSave, onClose }) {
  const [f, setF] = useState({
    hostname: initial?.hostname || '', port: initial?.port || 443,
    thresholds: initial?.thresholds || '30,14,7,1',
    alert_email: initial?.alert_email || '', alert_webhook_url: initial?.alert_webhook_url || '',
    check_whois: initial ? !!initial.check_whois : true
  });
  const [err, setErr] = useState('');
  const set = (k, v) => setF((x) => ({ ...x, [k]: v }));
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <motion.div initial={{ opacity: 0, scale: 0.96 }} animate={{ opacity: 1, scale: 1 }}
        className="bg-zinc-900 border border-zinc-800 rounded-2xl w-full max-w-md p-6 space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold">{initial ? 'Edit domain' : 'Add domain'}</h2>
          <button className="btn-ghost p-1.5!" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="flex gap-2">
          <input placeholder="example.com" value={f.hostname} onChange={(e) => set('hostname', e.target.value)} autoFocus />
          <input className="w-24!" type="number" placeholder="443" value={f.port} onChange={(e) => set('port', e.target.value)} />
        </div>
        <input placeholder="alert thresholds, days (30,14,7,1)" value={f.thresholds} onChange={(e) => set('thresholds', e.target.value)} />
        <input placeholder="alert email (optional, needs SMTP in .env)" value={f.alert_email} onChange={(e) => set('alert_email', e.target.value)} />
        <input placeholder="alert webhook URL (optional)" value={f.alert_webhook_url} onChange={(e) => set('alert_webhook_url', e.target.value)} />
        <label className="flex items-center gap-2 text-sm text-zinc-400">
          <input type="checkbox" className="w-4!" checked={f.check_whois} onChange={(e) => set('check_whois', e.target.checked)} />
          also check domain (WHOIS) expiry — best effort
        </label>
        {err && <p className="text-xs text-red-400">{err}</p>}
        <button className="btn-primary w-full justify-center" onClick={async () => {
          try { await onSave(f); } catch (x) { setErr(x.message); }
        }}>Save & check now</button>
      </motion.div>
    </div>
  );
}

function DomainRow({ d, onChanged, say }) {
  const [open, setOpen] = useState(false);
  const [hist, setHist] = useState(null);
  const [busy, setBusy] = useState(false);
  const [edit, setEdit] = useState(false);
  const lc = d.last_check;

  return (
    <motion.div layout className="bg-zinc-900/60 border border-zinc-800 rounded-xl overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3">
        <span className={`w-3 h-3 rounded-full shrink-0 ${STATUS_STYLES[d.status]} ${d.status === 'red' ? 'animate-pulse' : ''}`} />
        <div className="min-w-0 w-64">
          <div className="text-sm font-medium truncate">{d.hostname}{d.port !== 443 ? `:${d.port}` : ''}</div>
          <div className="text-xs text-zinc-500 truncate">{lc ? (lc.ok ? lc.issuer : lc.error) : 'checking…'}</div>
        </div>
        <div className="text-sm w-28">
          {d.days_left != null && (
            <span className={d.days_left < 7 ? 'text-red-400' : d.days_left <= 30 ? 'text-amber-400' : 'text-emerald-400'}>
              {d.days_left < 0 ? 'EXPIRED' : `${d.days_left}d left`}
            </span>
          )}
          {lc && !lc.ok && <span className="text-red-400 text-xs flex items-center gap-1"><AlertTriangle size={12} /> unreachable</span>}
        </div>
        <div className="text-xs text-zinc-500 w-32 hidden md:block">cert: {lc?.ok ? fmtDate(lc.expires_at) : '—'}</div>
        <div className="text-xs text-zinc-500 w-36 hidden lg:block">
          domain: {d.whois?.expires_at ? `${fmtDate(d.whois.expires_at)} (${d.whois.days_left}d)` : d.whois?.error ? 'whois n/a' : '—'}
        </div>
        {lc?.ok && !lc.chain_valid && <span className="text-[10px] px-2 py-0.5 rounded-full border border-red-800 text-red-400">invalid chain</span>}
        {lc?.ok && !!lc.weak_key && <span className="text-[10px] px-2 py-0.5 rounded-full border border-amber-800 text-amber-400">weak key</span>}
        <div className="flex-1" />
        <button className="btn-ghost px-2! py-1!" title="Check now" disabled={busy} onClick={async () => {
          setBusy(true);
          try { await api.checkNow(d.id); onChanged(); say(`${d.hostname} re-checked`); } finally { setBusy(false); }
        }}><RefreshCw size={13} className={busy ? 'animate-spin' : ''} /></button>
        <button className="btn-ghost px-2! py-1!" title="Test alert" onClick={async () => {
          try { const r = await api.testAlert(d.id); say(r.ok ? 'Test alert delivered' : 'Test alert failed — check channels'); }
          catch (e) { say(e.message); }
        }}><Bell size={13} /></button>
        <button className="btn-ghost px-2! py-1!" title={d.paused ? 'Resume' : 'Pause'} onClick={async () => { await api.pauseDomain(d.id); onChanged(); }}>
          {d.paused ? <Play size={13} /> : <Pause size={13} />}
        </button>
        <button className="btn-ghost px-2! py-1!" title="Edit" onClick={() => setEdit(true)}><Globe size={13} /></button>
        <button className="btn-ghost px-2! py-1!" title="Details" onClick={async () => {
          if (!open) setHist(await api.history(d.id));
          setOpen(!open);
        }}>{open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}</button>
        <button className="btn-danger px-2! py-1!" title="Delete" onClick={async () => {
          if (confirm(`Stop monitoring ${d.hostname}?`)) { await api.deleteDomain(d.id); onChanged(); }
        }}><Trash2 size={13} /></button>
      </div>

      <AnimatePresence>
        {open && (
          <motion.div initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }} className="overflow-hidden border-t border-zinc-800/70">
            <div className="p-4 grid md:grid-cols-2 gap-4 text-xs">
              <div>
                <h4 className="text-zinc-400 mb-2 flex items-center gap-1"><Link2 size={12} /> Certificate chain</h4>
                {lc?.chain?.length ? lc.chain.map((c, i) => (
                  <div key={i} className="mono bg-zinc-950 rounded-lg p-2 mb-1.5">
                    <div className="text-sky-300">{'  '.repeat(i)}↳ {c.subject}</div>
                    <div className="text-zinc-500">{'  '.repeat(i)}  issued by {c.issuer} · until {c.valid_to}</div>
                  </div>
                )) : <p className="text-zinc-600">no chain data</p>}
                {lc?.ok && (
                  <p className="text-zinc-500 mt-2">
                    key: {lc.key_type} · chain: {lc.chain_valid ? <span className="text-emerald-400">valid</span> : <span className="text-red-400">{lc.chain_error}</span>}
                    {!!lc.self_signed && ' · self-signed'}
                  </p>
                )}
              </div>
              <div>
                <h4 className="text-zinc-400 mb-2 flex items-center gap-1"><History size={12} /> Check history</h4>
                <div className="max-h-48 overflow-y-auto space-y-1">
                  {(hist || []).map((h) => (
                    <div key={h.id} className="flex gap-3 text-zinc-500">
                      <span className="w-32 shrink-0">{new Date(h.checked_at).toLocaleString()}</span>
                      {h.ok
                        ? <span className="text-emerald-500">ok · expires {fmtDate(h.expires_at)}</span>
                        : <span className="text-red-400">{h.error}</span>}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {edit && (
        <DomainModal initial={d} onClose={() => setEdit(false)} onSave={async (f) => {
          await api.updateDomain(d.id, f);
          setEdit(false);
          onChanged();
        }} />
      )}
    </motion.div>
  );
}

export default function App() {
  const [phase, setPhase] = useState('loading');
  const [domains, setDomains] = useState([]);
  const [modal, setModal] = useState(false);
  const [alerts, setAlerts] = useState(null);
  const [toast, setToast] = useState('');

  const say = (m) => { setToast(m); setTimeout(() => setToast(''), 2500); };
  const load = () => api.domains().then(setDomains);

  useEffect(() => {
    api.me().then(() => { setPhase('app'); load(); }).catch(() => setPhase('login'));
  }, []);

  useEffect(() => {
    if (phase !== 'app') return;
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [phase]);

  if (phase === 'loading') return <div className="min-h-screen flex items-center justify-center"><RefreshCw className="animate-spin text-zinc-600" /></div>;
  if (phase === 'login') return <Login onOk={() => { setPhase('app'); load(); }} />;

  const counts = { green: 0, yellow: 0, red: 0, paused: 0 };
  domains.forEach((d) => counts[d.status]++);

  return (
    <div className="min-h-screen max-w-6xl mx-auto p-6">
      <header className="flex items-center gap-3 mb-6">
        <div className="bg-sky-600/20 border border-sky-500/30 rounded-xl p-2"><ShieldCheck className="text-sky-400" size={18} /></div>
        <h1 className="font-semibold">Certwatch</h1>
        <div className="flex gap-3 ml-4 text-xs">
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-500" />{counts.green} healthy</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-amber-400" />{counts.yellow} expiring</span>
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-500" />{counts.red} critical</span>
        </div>
        <div className="flex-1" />
        <button className="btn-ghost" onClick={async () => setAlerts(alerts ? null : await api.alerts())}><Bell size={14} /> Alert log</button>
        <button className="btn-primary" onClick={() => setModal(true)}><Plus size={15} /> Add domain</button>
        <button className="btn-ghost" onClick={async () => { await api.logout(); setPhase('login'); }}><LogOut size={14} /></button>
      </header>

      {alerts && (
        <div className="mb-6 bg-zinc-900/60 border border-zinc-800 rounded-xl divide-y divide-zinc-800/70 max-h-64 overflow-y-auto">
          {alerts.map((a) => (
            <div key={a.id} className="px-4 py-2 text-xs flex gap-3">
              <span className="text-zinc-500 w-36 shrink-0">{new Date(a.sent_at).toLocaleString()}</span>
              <span className="w-40 shrink-0 text-sky-300">{a.hostname}</span>
              <span className={a.ok ? 'text-zinc-300' : 'text-red-400'}>
                {a.kind}{a.threshold ? ` (${a.threshold}d)` : ''} via {a.channel} {a.ok ? '✓' : `✗ ${a.error || ''}`}
              </span>
            </div>
          ))}
          {alerts.length === 0 && <p className="p-4 text-xs text-zinc-500">No alerts sent yet.</p>}
        </div>
      )}

      <div className="grid gap-2">
        {domains.map((d) => <DomainRow key={d.id} d={d} onChanged={load} say={say} />)}
        {domains.length === 0 && (
          <div className="text-center text-zinc-500 py-20">
            <ShieldCheck className="mx-auto mb-3 text-zinc-700" size={40} />
            Add your first domain. Certwatch checks the TLS handshake, chain validity, key strength and (best-effort) WHOIS domain expiry.
          </div>
        )}
      </div>

      <AnimatePresence>
        {modal && (
          <DomainModal onClose={() => setModal(false)} onSave={async (f) => {
            await api.createDomain(f);
            setModal(false);
            load();
            say('Domain added — first check running');
          }} />
        )}
        {toast && (
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="fixed bottom-6 left-1/2 -translate-x-1/2 bg-zinc-800 border border-zinc-700 rounded-full px-4 py-2 text-sm shadow-xl">
            {toast}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
