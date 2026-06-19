import React, { useState, useEffect } from "react";
import Dashboard from "./views/Dashboard";
import UrlScanner from "./views/UrlScanner";
import EmailAnalyzer from "./views/EmailAnalyzer";
import IpChecker from "./views/IpChecker";
import DomainLookup from "./views/DomainLookup";
import ThreatLogs from "./views/ThreatLogs";
import OsintScanner from "./views/OsintScanner";

import { Shield, LayoutDashboard, Link2, Mail, Server, Globe, FileText, Terminal, Activity, Key } from "lucide-react";

export default function App() {
  const [view, setView] = useState("dashboard");
  const [time, setTime] = useState(new Date());

  // Keep timestamp clock active for police operations feel
  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const renderView = () => {
    switch (view) {
      case "dashboard":
        return <Dashboard setView={setView} />;
      case "url":
        return <UrlScanner />;
      case "email":
        return <EmailAnalyzer />;
      case "ip":
        return <IpChecker />;
      case "domain":
        return <DomainLookup />;
      case "logs":
        return <ThreatLogs />;
      case "osint":
        return <OsintScanner />;
      default:
        return <Dashboard setView={setView} />;
    }
  };

  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: <LayoutDashboard size={18} /> },
    { id: "url", label: "URL Threat Scanner", icon: <Link2 size={18} /> },
    { id: "email", label: "Email Spoof Analyzer", icon: <Mail size={18} /> },
    { id: "ip", label: "IP Reputation Checker", icon: <Server size={18} /> },
    { id: "domain", label: "Domain Intelligence", icon: <Globe size={18} /> },
    { id: "logs", label: "Threat Evidence Logs", icon: <FileText size={18} /> },
    { id: "osint", label: "OSINT Leak Scanner", icon: <Key size={18} /> }
  ];

  return (
    <div className="min-h-screen bg-slate-950 cyber-grid flex flex-col">
      
      {/* Top Banner Status Bar */}
      <header className="border-b border-slate-900 bg-slate-950 px-6 py-3.5 flex justify-between items-center z-10">
        <div className="flex items-center space-x-2.5">
          <div className="p-1.5 bg-cyan-950/80 border border-cyan-800 rounded">
            <Shield className="text-cyan-400 text-glow-cyber" size={20} />
          </div>
          <div>
            <span className="font-mono text-sm font-black text-slate-100 tracking-wider">CYBER THREAT ANALYZER v1.0</span>
            <span className="hidden md:inline font-mono text-[9px] text-cyan-600 ml-3 uppercase select-none tracking-widest border border-cyan-950/60 bg-cyan-950/15 px-1.5 py-0.5 rounded">
              Federal Investigator Console
            </span>
          </div>
        </div>

        {/* Live system logs and clock */}
        <div className="flex items-center space-x-6 font-mono text-[11px] text-slate-400">
          <div className="hidden lg:flex items-center space-x-2 bg-slate-900/60 border border-slate-900 px-2.5 py-1 rounded">
            <Activity className="text-emerald-500 led-blink-green rounded-full" size={12} />
            <span className="text-[10px] text-slate-300">CORE API ONLINE</span>
          </div>
          <div className="flex items-center space-x-1.5 text-slate-300">
            <Terminal size={12} className="text-cyan-500" />
            <span>{time.toLocaleTimeString()}</span>
          </div>
        </div>
      </header>

      {/* Main Body with Sidebar Layout */}
      <div className="flex flex-1 flex-col md:flex-row">
        
        {/* Left Sidebar Menu */}
        <aside className="w-full md:w-64 border-r border-slate-900 bg-slate-950/90 flex flex-col justify-between p-4 space-y-6">
          <div className="space-y-4">
            <span className="text-[10px] font-mono text-slate-500 font-bold uppercase tracking-widest block pl-2">Navigation Core</span>
            
            <nav className="space-y-1">
              {navItems.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setView(item.id)}
                  className={`w-full flex items-center space-x-3.5 px-3 py-2.5 rounded font-mono text-xs text-left transition ${
                    view === item.id 
                      ? "bg-cyan-950/60 border border-cyan-800 text-cyan-400 text-glow-cyber" 
                      : "border border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40"
                  }`}
                >
                  {item.icon}
                  <span className="font-semibold">{item.label}</span>
                </button>
              ))}
            </nav>
          </div>

          {/* User Profile Info Footer */}
          <div className="border-t border-slate-900 pt-4 font-mono text-xs space-y-2">
            <div className="flex items-center space-x-2 pl-1">
              <div className="w-2.5 h-2.5 rounded-full bg-emerald-500 led-blink-green"></div>
              <span className="text-slate-300 font-bold">Investigator Active</span>
            </div>
            <div className="p-2.5 bg-slate-950 border border-slate-900 rounded text-[10px] text-slate-500 space-y-0.5">
              <div>Badge: #CYBER-7801</div>
              <div>Duty: Digital Forensics</div>
              <div>IP: 10.142.12.89</div>
            </div>
          </div>
        </aside>

        {/* Main Content Area */}
        <main className="flex-1 p-6 md:p-8 bg-slate-950/60 overflow-y-auto max-h-[calc(100vh-60px)]">
          <div className="max-w-6xl mx-auto">
            {renderView()}
          </div>
        </main>

      </div>
    </div>
  );
}
