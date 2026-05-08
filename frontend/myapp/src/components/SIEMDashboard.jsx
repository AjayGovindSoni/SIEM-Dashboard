import React, { useState, useEffect } from 'react';
import {
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import { AlertCircle, Shield, Activity, RefreshCw, Terminal } from 'lucide-react';

// With vite proxy configured, all /api calls go through localhost — no CORS issues
const API_URL = '/api';

// ── Design tokens ──────────────────────────────────────────────────────────────
const C = {
  bg:         '#0f1117',
  surface:    '#161b27',
  surfaceAlt: '#1c2336',
  border:     '#252d3d',
  borderHov:  '#334155',
  text:       '#e2e8f0',
  textMuted:  '#64748b',
  textDim:    '#94a3b8',
  accent:     '#3b82f6',
  accentGlow: 'rgba(59,130,246,0.12)',
  critical:   '#ef4444',
  high:       '#f97316',
  medium:     '#eab308',
  low:        '#3b82f6',
  info:       '#6b7280',
  green:      '#22c55e',
};

const SEVERITY_COLORS = {
  critical: C.critical, high: C.high, medium: C.medium, low: C.low, info: C.info,
};

// ── Shared style helpers ───────────────────────────────────────────────────────
const card = {
  background: C.surface,
  border: `1px solid ${C.border}`,
  borderRadius: 12,
  padding: '24px',
};

const mkBadge = (color, bg) => ({
  display: 'inline-flex', alignItems: 'center',
  padding: '2px 10px', borderRadius: 999,
  fontSize: 11, fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase',
  color, background: bg, border: `1px solid ${color}33`,
});

const severityBadge = (sev) => {
  const map = {
    critical: [C.critical, '#ef444422'], high:   [C.high,     '#f9731622'],
    medium:   [C.medium,   '#eab30822'], low:    [C.low,      '#3b82f622'],
    info:     [C.info,     '#6b728022'],
  };
  const [color, bg] = map[sev] || map.info;
  return mkBadge(color, bg);
};

const statusBadge = (status) => {
  const map = {
    open:          [C.critical, '#ef444422'],
    investigating: [C.medium,   '#eab30822'],
    resolved:      [C.green,    '#22c55e22'],
    false_positive:[C.textMuted,'#6b728022'],
  };
  const [color, bg] = map[status] || map.open;
  return mkBadge(color, bg);
};

// ── Custom tooltip ─────────────────────────────────────────────────────────────
const ChartTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: C.surfaceAlt, border: `1px solid ${C.border}`, borderRadius: 8, padding: '10px 14px', fontSize: 13 }}>
      <p style={{ color: C.textDim, marginBottom: 4 }}>{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color || C.accent, fontWeight: 600 }}>{p.name}: {p.value}</p>
      ))}
    </div>
  );
};

// ── Stat card ──────────────────────────────────────────────────────────────────
const StatCard = ({ label, value, icon: Icon, color }) => (
  <div style={{ ...card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
    <div>
      <p style={{ color: C.textMuted, fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>{label}</p>
      <p style={{ fontSize: 36, fontWeight: 700, color: C.text, lineHeight: 1 }}>{value ?? '—'}</p>
    </div>
    <div style={{ width: 52, height: 52, borderRadius: 12, background: `${color}18`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
      <Icon size={24} color={color} />
    </div>
  </div>
);

// ── Section wrapper ────────────────────────────────────────────────────────────
const Section = ({ title, children }) => (
  <div style={{ ...card }}>
    <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, marginBottom: 20, textTransform: 'uppercase', letterSpacing: '0.06em', color: C.textDim }}>{title}</h3>
    {children}
  </div>
);

// ── Table header helper ────────────────────────────────────────────────────────
const TH = ({ children }) => (
  <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 600, color: C.textMuted, textTransform: 'uppercase', letterSpacing: '0.07em', whiteSpace: 'nowrap', borderBottom: `1px solid ${C.border}`, background: C.surfaceAlt }}>
    {children}
  </th>
);

// ── Main component ─────────────────────────────────────────────────────────────
const SIEMDashboard = () => {
  const [events, setEvents]           = useState([]);
  const [incidents, setIncidents]     = useState([]);
  const [stats, setStats]             = useState(null);
  const [timeline, setTimeline]       = useState([]);
  const [topSources, setTopSources]   = useState([]);
  const [selectedTab, setSelectedTab] = useState('dashboard');
  const [timeRange, setTimeRange]     = useState('24h');
  const [loading, setLoading]         = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);

  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 30000);
    return () => clearInterval(iv);
  }, [timeRange]);

  const getStartTime = (range) => {
    const offsets = { '1h': 3600000, '24h': 86400000, '7d': 604800000 };
    return new Date(Date.now() - (offsets[range] || offsets['24h'])).toISOString();
  };

  const fetchData = async () => {
    setLoading(true);
    try {
      const t = getStartTime(timeRange);
      const [evR, incR, stR, tlR, srcR] = await Promise.all([
        fetch(`${API_URL}/events?start_time=${t}&limit=100`),
        fetch(`${API_URL}/incidents?limit=50`),
        fetch(`${API_URL}/events/stats/summary?start_time=${t}`),
        fetch(`${API_URL}/events/stats/timeline?start_time=${t}&interval=hour`),
        fetch(`${API_URL}/stats/top-sources?start_time=${t}&limit=10`),
      ]);
      const [evD, incD, stD, tlD, srcD] = await Promise.all([evR.json(), incR.json(), stR.json(), tlR.json(), srcR.json()]);
      setEvents(evD.events || []);
      setIncidents(incD.incidents || []);
      setStats(stD);
      setTimeline(Object.entries(tlD.timeline || {}).map(([time, count]) => ({ time, events: count })));
      setTopSources(srcD);
      setLastUpdated(new Date());
    } catch (e) {
      console.error('Fetch error:', e);
    }
    setLoading(false);
  };

  // ── Dashboard tab ────────────────────────────────────────────────────────────
  const DashboardOverview = () => {
    if (!stats) return (
      <div style={{ textAlign: 'center', padding: 80, color: C.textMuted }}>
        <Activity size={40} style={{ margin: '0 auto 16px', opacity: 0.3 }} />
        <p>Loading data...</p>
      </div>
    );

    const severityData = Object.entries(stats.by_severity || {}).map(([name, value]) => ({ name, value, color: SEVERITY_COLORS[name] }));
    const categoryData = Object.entries(stats.by_category || {}).map(([name, value]) => ({ name, value }));
    const criticalCount = incidents.filter(i => i.severity === 'critical').length;
    const openCount     = incidents.filter(i => i.status === 'open').length;

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
          <StatCard label="Total Events"   value={stats.total_events}              icon={Activity}    color={C.accent}   />
          <StatCard label="Open Incidents" value={openCount}                        icon={AlertCircle} color={C.high}     />
          <StatCard label="Critical"       value={criticalCount}                   icon={Shield}      color={C.critical} />
          <StatCard label="High Severity"  value={stats.by_severity?.high || 0}   icon={AlertCircle} color={C.medium}   />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 24 }}>
          <Section title="Event Timeline">
            <ResponsiveContainer width="100%" height={240}>
              <LineChart data={timeline}>
                <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
                <XAxis dataKey="time" tick={{ fontSize: 10, fill: C.textMuted }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 10, fill: C.textMuted }} tickLine={false} axisLine={false} />
                <Tooltip content={<ChartTooltip />} />
                <Line type="monotone" dataKey="events" stroke={C.accent} strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </Section>

          <Section title="Events by Severity">
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie data={severityData} cx="50%" cy="50%" innerRadius={55} outerRadius={90} dataKey="value" paddingAngle={3}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  labelLine={{ stroke: C.border }}
                >
                  {severityData.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
                <Tooltip content={<ChartTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </Section>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 24 }}>
          <Section title="Events by Category">
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={categoryData} barSize={24}>
                <CartesianGrid strokeDasharray="3 3" stroke={C.border} vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: C.textMuted }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 10, fill: C.textMuted }} tickLine={false} axisLine={false} />
                <Tooltip content={<ChartTooltip />} />
                <Bar dataKey="value" fill={C.accent} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </Section>

          <Section title="Top Source IPs">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {topSources.length === 0 && <p style={{ color: C.textMuted, textAlign: 'center', padding: 32 }}>No data</p>}
              {topSources.map((src, i) => {
                const pct = ((src.count / (topSources[0]?.count || 1)) * 100).toFixed(0);
                return (
                  <div key={i} style={{ background: C.surfaceAlt, borderRadius: 8, padding: '10px 14px', border: `1px solid ${C.border}` }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: C.text }}>{src.source_ip}</span>
                      <span style={{ fontSize: 13, fontWeight: 600, color: C.accent }}>{src.count}</span>
                    </div>
                    <div style={{ height: 4, background: C.border, borderRadius: 2 }}>
                      <div style={{ height: '100%', width: `${pct}%`, background: C.accent, borderRadius: 2 }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </Section>
        </div>
      </div>
    );
  };

  // ── Events tab ───────────────────────────────────────────────────────────────
  const EventsView = () => (
    <div style={{ ...card, padding: 0, overflow: 'hidden' }}>
      <div style={{ padding: '18px 24px', borderBottom: `1px solid ${C.border}` }}>
        <h2 style={{ fontSize: 15, fontWeight: 600, color: C.text }}>Security Events</h2>
        <p style={{ fontSize: 12, color: C.textMuted, marginTop: 2 }}>{events.length} events in range</p>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead><tr><TH>Time</TH><TH>Severity</TH><TH>Event Type</TH><TH>Source</TH><TH>Message</TH></tr></thead>
          <tbody>
            {events.map((ev, i) => (
              <tr key={ev.id} style={{ borderBottom: `1px solid ${C.border}`, background: i % 2 === 0 ? C.surface : C.surfaceAlt }}
                onMouseEnter={e => e.currentTarget.style.background = '#1e2a40'}
                onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? C.surface : C.surfaceAlt}
              >
                <td style={{ padding: '11px 16px', fontSize: 12, color: C.textMuted, whiteSpace: 'nowrap', fontFamily: "'JetBrains Mono', monospace" }}>
                  {new Date(ev.timestamp).toLocaleString()}
                </td>
                <td style={{ padding: '11px 16px', whiteSpace: 'nowrap' }}>
                  <span style={severityBadge(ev.severity)}>{ev.severity}</span>
                </td>
                <td style={{ padding: '11px 16px', fontSize: 13, color: C.textDim, whiteSpace: 'nowrap' }}>{ev.event_type}</td>
                <td style={{ padding: '11px 16px', fontSize: 12, color: C.accent, whiteSpace: 'nowrap', fontFamily: "'JetBrains Mono', monospace" }}>
                  {ev.source_ip || ev.hostname || '—'}
                </td>
                <td style={{ padding: '11px 16px', fontSize: 13, color: C.text, maxWidth: 380, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {ev.message}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {events.length === 0 && (
          <div style={{ padding: 64, textAlign: 'center', color: C.textMuted }}>
            <Terminal size={36} style={{ margin: '0 auto 12px', opacity: 0.3 }} />
            <p>No events found for this time range</p>
          </div>
        )}
      </div>
    </div>
  );

  // ── Incidents tab ─────────────────────────────────────────────────────────────
  const IncidentsView = () => (
    <div style={{ ...card, padding: 0, overflow: 'hidden' }}>
      <div style={{ padding: '18px 24px', borderBottom: `1px solid ${C.border}` }}>
        <h2 style={{ fontSize: 15, fontWeight: 600, color: C.text }}>Security Incidents</h2>
        <p style={{ fontSize: 12, color: C.textMuted, marginTop: 2 }}>{incidents.length} incidents loaded</p>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead><tr><TH>ID</TH><TH>Title</TH><TH>Severity</TH><TH>Status</TH><TH>Risk Score</TH><TH>Events</TH><TH>Last Seen</TH></tr></thead>
          <tbody>
            {incidents.map((inc, i) => (
              <tr key={inc.id} style={{ borderBottom: `1px solid ${C.border}`, background: i % 2 === 0 ? C.surface : C.surfaceAlt }}
                onMouseEnter={e => e.currentTarget.style.background = '#1e2a40'}
                onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? C.surface : C.surfaceAlt}
              >
                <td style={{ padding: '11px 16px', fontSize: 12, color: C.textMuted, fontFamily: "'JetBrains Mono', monospace" }}>#{inc.id}</td>
                <td style={{ padding: '11px 16px', fontSize: 13, color: C.text, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inc.title}</td>
                <td style={{ padding: '11px 16px', whiteSpace: 'nowrap' }}><span style={severityBadge(inc.severity)}>{inc.severity}</span></td>
                <td style={{ padding: '11px 16px', whiteSpace: 'nowrap' }}><span style={statusBadge(inc.status)}>{inc.status}</span></td>
                <td style={{ padding: '11px 16px', fontSize: 13, fontWeight: 600, color: inc.risk_score >= 80 ? C.critical : inc.risk_score >= 50 ? C.medium : C.green }}>
                  {inc.risk_score}
                </td>
                <td style={{ padding: '11px 16px', fontSize: 13, color: C.textDim }}>{inc.event_count}</td>
                <td style={{ padding: '11px 16px', fontSize: 12, color: C.textMuted, whiteSpace: 'nowrap', fontFamily: "'JetBrains Mono', monospace" }}>
                  {new Date(inc.last_seen).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {incidents.length === 0 && (
          <div style={{ padding: 64, textAlign: 'center', color: C.textMuted }}>
            <Shield size={36} style={{ margin: '0 auto 12px', opacity: 0.3 }} />
            <p>No incidents found</p>
          </div>
        )}
      </div>
    </div>
  );

  // ── Shell ────────────────────────────────────────────────────────────────────
  return (
    <div style={{ minHeight: '100vh', background: C.bg, color: C.text }}>
      {/* Header */}
      <header style={{ background: C.surface, borderBottom: `1px solid ${C.border}`, position: 'sticky', top: 0, zIndex: 100 }}>
        <div style={{ maxWidth: 1400, margin: '0 auto', padding: '0 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', height: 60 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 36, height: 36, borderRadius: 10, background: C.accentGlow, display: 'flex', alignItems: 'center', justifyContent: 'center', border: `1px solid ${C.accent}44` }}>
              <Shield size={18} color={C.accent} />
            </div>
            <div>
              <h1 style={{ fontSize: 15, fontWeight: 700, color: C.text }}>SIEM Dashboard</h1>
              <p style={{ fontSize: 11, color: C.textMuted }}>Security Information & Event Management</p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: C.green, display: 'block', boxShadow: `0 0 6px ${C.green}` }} />
              <span style={{ fontSize: 12, color: C.textMuted }}>
                {lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : 'Connecting...'}
              </span>
            </div>

            <select value={timeRange} onChange={e => setTimeRange(e.target.value)}
              style={{ background: C.surfaceAlt, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text, padding: '6px 12px', fontSize: 13, cursor: 'pointer', outline: 'none' }}
            >
              <option value="1h">Last Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
            </select>

            <button onClick={fetchData} disabled={loading}
              style={{ background: C.accentGlow, border: `1px solid ${C.accent}44`, borderRadius: 8, color: C.accent, padding: '7px 10px', display: 'flex', alignItems: 'center', opacity: loading ? 0.5 : 1, transition: 'opacity 0.2s' }}
            >
              <RefreshCw size={14} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div style={{ maxWidth: 1400, margin: '0 auto', padding: '0 24px', display: 'flex', gap: 2 }}>
          {['dashboard', 'events', 'incidents'].map(tab => (
            <button key={tab} onClick={() => setSelectedTab(tab)}
              style={{
                padding: '10px 18px', fontSize: 13, fontWeight: 500,
                color: selectedTab === tab ? C.accent : C.textMuted,
                background: 'transparent',
                borderBottom: selectedTab === tab ? `2px solid ${C.accent}` : '2px solid transparent',
                transition: 'all 0.15s', textTransform: 'capitalize',
              }}
            >
              {tab}
            </button>
          ))}
        </div>
      </header>

      <main style={{ maxWidth: 1400, margin: '0 auto', padding: '28px 24px' }}>
        {selectedTab === 'dashboard' && <DashboardOverview />}
        {selectedTab === 'events'    && <EventsView />}
        {selectedTab === 'incidents' && <IncidentsView />}
      </main>

      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
};

export default SIEMDashboard;
