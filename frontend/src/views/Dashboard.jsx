import React, { useEffect, useState } from "react";
import api from "../api";
import { Shield, ShieldAlert, ShieldCheck, Activity, Terminal, AlertTriangle, Link2, Mail, Globe, Server, Key } from "lucide-react";

export default function Dashboard({ setView }) {
  const [stats, setStats] = useState({
    total_scans: 0,
    by_type: { URL: 0, EMAIL: 0, IP: 0, DOMAIN: 0 },
    by_severity: { Safe: 0, Suspicious: 0, Malicious: 0 }
  });
  const [recentLogs, setRecentLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchData() {
      try {
        const statsResp = await api.get("/api/stats");
        setStats(statsResp.data);

        const logsResp = await api.get("/api/logs");
        setRecentLogs(logsResp.data.slice(0, 5)); // show latest 5
      } catch (err) {
        console.error("Failed to load dashboard metrics", err);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-96 text-cyber-primary">
        <Activity className="animate-spin mb-4 text-glow-cyber" size={48} />
        <span className="font-mono text-sm tracking-widest text-glow-cyber">INITIALIZING TACTICAL SYSTEM FEED...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-wider text-white uppercase text-glow-cyber font-mono">
          CYBER THREAT COMMAND CENTER
        </h1>
        <p className="text-xs text-slate-400 font-mono">
          STATION ID: CC-UNIT-42 // INCOMING INTEL INTEGRITY: ONLINE
        </p>
      </div>

      {/* Grid of Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Total Scans */}
        <div className="cyber-card cyber-card-corners p-4 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 font-mono uppercase block">Total Operations</span>
            <span className="text-3xl font-black font-mono text-cyan-400 text-glow-cyber">{stats.total_scans}</span>
          </div>
          <Activity className="text-cyan-500" size={32} />
        </div>

        {/* Malicious Logs */}
        <div className="cyber-card cyber-card-corners p-4 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 font-mono uppercase block">Malicious Flags</span>
            <span className="text-3xl font-black font-mono text-red-500 text-glow-danger">{stats.by_severity.Malicious}</span>
          </div>
          <ShieldAlert className="text-red-500 led-blink-red rounded-full" size={28} />
        </div>

        {/* Suspicious Logs */}
        <div className="cyber-card cyber-card-corners p-4 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 font-mono uppercase block">Suspicious Flags</span>
            <span className="text-3xl font-black font-mono text-amber-500">{stats.by_severity.Suspicious}</span>
          </div>
          <AlertTriangle className="text-amber-500" size={28} />
        </div>

        {/* Safe Logs */}
        <div className="cyber-card cyber-card-corners p-4 flex items-center justify-between">
          <div>
            <span className="text-xs text-slate-400 font-mono uppercase block">Clean Audits</span>
            <span className="text-3xl font-black font-mono text-emerald-500">{stats.by_severity.Safe}</span>
          </div>
          <ShieldCheck className="text-emerald-500" size={32} />
        </div>
      </div>

      {/* Main section: Radar and Operations Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Operations Radar */}
        <div className="cyber-card cyber-card-corners p-6 lg:col-span-1 flex flex-col items-center justify-center space-y-4">
          <div className="w-full border-b border-slate-800 pb-2 mb-2">
            <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider block">Local Network Radar</span>
          </div>
          
          <div className="relative w-48 h-48 border-2 border-slate-800 rounded-full flex items-center justify-center bg-slate-950 overflow-hidden">
            {/* Concentric circles */}
            <div className="absolute w-36 h-36 border border-cyan-900/30 rounded-full"></div>
            <div className="absolute w-24 h-24 border border-cyan-900/30 rounded-full"></div>
            <div className="absolute w-12 h-12 border border-cyan-900/30 rounded-full"></div>
            {/* Radar Crosshairs */}
            <div className="absolute w-full h-[1px] bg-cyan-950/40"></div>
            <div className="absolute h-full w-[1px] bg-cyan-950/40"></div>
            {/* Sweep hand */}
            <div className="absolute top-0 left-0 w-full h-full rounded-full border-r-2 border-cyan-500/80 scan-line pointer-events-none opacity-20"></div>
            {/* Blips */}
            <div className="absolute w-2 h-2 bg-red-500 rounded-full top-1/4 left-1/3 led-blink-red"></div>
            <div className="absolute w-2 h-2 bg-amber-500 rounded-full bottom-1/3 right-1/4 led-blink-yellow"></div>
            <div className="absolute w-2 h-2 bg-emerald-500 rounded-full bottom-1/4 left-1/4"></div>

            <Activity className="text-cyan-500/30 radar-glow" size={40} />
          </div>
          <span className="text-[10px] text-slate-400 font-mono text-center">
            ACTIVE SCAN SWEEP // 4800 BAUD // PORT MONITOR ENGAGED
          </span>
        </div>

        {/* Quick Launch & Active Investigations */}
        <div className="cyber-card cyber-card-corners p-6 lg:col-span-2 space-y-4 flex flex-col justify-between">
          <div>
            <div className="border-b border-slate-800 pb-2 mb-4">
              <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider block">Tactical Investigations Modules</span>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* URL Scanner */}
              <button 
                onClick={() => setView("url")} 
                className="flex items-center space-x-3 p-3 bg-slate-950 border border-slate-800 hover:border-cyan-500 rounded-md transition text-left group"
              >
                <div className="p-2 bg-cyan-950/40 rounded border border-cyan-900 group-hover:border-cyan-500">
                  <Link2 className="text-cyan-400" size={18} />
                </div>
                <div>
                  <div className="text-sm font-bold text-white font-mono">URL Threat Scanner</div>
                  <div className="text-xs text-slate-400">Scan phishing links, SSL, VirusTotal</div>
                </div>
              </button>

              {/* Email Spoof */}
              <button 
                onClick={() => setView("email")}
                className="flex items-center space-x-3 p-3 bg-slate-950 border border-slate-800 hover:border-cyan-500 rounded-md transition text-left group"
              >
                <div className="p-2 bg-cyan-950/40 rounded border border-cyan-900 group-hover:border-cyan-500">
                  <Mail className="text-cyan-400" size={18} />
                </div>
                <div>
                  <div className="text-sm font-bold text-white font-mono">Email Spoof Analyzer</div>
                  <div className="text-xs text-slate-400">Trace mail headers, SPF/DKIM validation</div>
                </div>
              </button>

              {/* IP reputation */}
              <button 
                onClick={() => setView("ip")}
                className="flex items-center space-x-3 p-3 bg-slate-950 border border-slate-800 hover:border-cyan-500 rounded-md transition text-left group"
              >
                <div className="p-2 bg-cyan-950/40 rounded border border-cyan-900 group-hover:border-cyan-500">
                  <Server className="text-cyan-400" size={18} />
                </div>
                <div>
                  <div className="text-sm font-bold text-white font-mono">IP Reputation Checker</div>
                  <div className="text-xs text-slate-400">GeoIP, ISP, AbuseIPDB report counts</div>
                </div>
              </button>

              {/* Domain Intelligence */}
              <button 
                onClick={() => setView("domain")}
                className="flex items-center space-x-3 p-3 bg-slate-950 border border-slate-800 hover:border-cyan-500 rounded-md transition text-left group"
              >
                <div className="p-2 bg-cyan-950/40 rounded border border-cyan-900 group-hover:border-cyan-500">
                  <Globe className="text-cyan-400" size={18} />
                </div>
                <div>
                  <div className="text-sm font-bold text-white font-mono">Domain Intel Lookup</div>
                  <div className="text-xs text-slate-400">WHOIS record, domain age, DNS audit</div>
                </div>
              </button>

              {/* OSINT Leak Scanner */}
              <button 
                onClick={() => setView("osint")}
                className="flex items-center space-x-3 p-3 bg-slate-950 border border-slate-800 hover:border-cyan-500 rounded-md transition text-left group md:col-span-2"
              >
                <div className="p-2 bg-cyan-950/40 rounded border border-cyan-900 group-hover:border-cyan-500">
                  <Key className="text-cyan-400" size={18} />
                </div>
                <div>
                  <div className="text-sm font-bold text-white font-mono">OSINT Leak Scanner</div>
                  <div className="text-xs text-slate-400">Search email credentials breaches database</div>
                </div>
              </button>
            </div>
          </div>

          <div className="border-t border-slate-800 pt-3 text-[10px] font-mono text-slate-500 flex justify-between">
            <span>OPERATOR: SECURE_ANALYST_ADMIN</span>
            <span>SYSTEM DB: SQLITE_ACTIVE</span>
          </div>
        </div>

      </div>

      {/* Recent Activity Logs */}
      <div className="cyber-card cyber-card-corners p-6">
        <div className="border-b border-slate-800 pb-2 mb-4 flex justify-between items-center">
          <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider block">Live Threat Logs Feed</span>
          <button onClick={() => setView("logs")} className="text-xs text-cyan-400 font-mono hover:underline">
            View All Logs →
          </button>
        </div>

        {recentLogs.length === 0 ? (
          <div className="text-center p-6 text-slate-500 font-mono text-xs">
            NO CURRENT OPERATIONS LOGGED. SYSTEM STANDBY.
          </div>
        ) : (
          <div className="space-y-2">
            {recentLogs.map((log) => {
              const statusVal = (log.result?.status || log.result?.risk_level || "Safe").toLowerCase();
              let badgeColor = "text-emerald-400 border-emerald-950 bg-emerald-950/20";
              if (statusVal.includes("malicious") || statusVal.includes("high")) {
                badgeColor = "text-red-400 border-red-950 bg-red-950/20";
              } else if (statusVal.includes("suspicious") || statusVal.includes("medium")) {
                badgeColor = "text-amber-400 border-amber-950 bg-amber-950/20";
              }

              return (
                <div key={log.id} className="flex flex-col md:flex-row md:items-center justify-between p-3 bg-slate-950/60 border border-slate-900 rounded font-mono text-xs hover:border-slate-800 transition">
                  <div className="flex items-center space-x-3 mb-2 md:mb-0">
                    <Terminal className="text-slate-500" size={14} />
                    <span className="text-slate-400 text-[10px]">{new Date(log.timestamp).toLocaleString()}</span>
                    <span className="px-2 py-0.5 border border-slate-800 bg-slate-900 rounded text-slate-300 font-bold text-[10px]">{log.scan_type}</span>
                    <span className="text-slate-200 truncate max-w-[300px] md:max-w-[400px]">{log.input_value}</span>
                  </div>
                  <div className="flex items-center space-x-4">
                    <span className={`px-2 py-0.5 border rounded text-[10px] font-bold uppercase ${badgeColor}`}>
                      {log.result?.status || log.result?.risk_level || "Safe"}
                    </span>
                    {log.analyst_notes && (
                      <span className="text-slate-500 text-[10px] italic max-w-[150px] truncate">
                        Notes: {log.analyst_notes}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
