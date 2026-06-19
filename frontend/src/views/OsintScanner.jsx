import React, { useState } from "react";
import axios from "axios";
import { Shield, ShieldAlert, ShieldCheck, Activity, Key, Mail, Info, Database, AlertCircle } from "lucide-react";

const SAMPLES = [
  { label: "Target (admin@corporate.gov)", email: "admin@corporate.gov" },
  { label: "Internal Audit (agent-test@police.gov)", email: "agent-test@police.gov" },
  { label: "Standard (test@gmail.com)", email: "test@gmail.com" }
];

export default function OsintScanner() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [progressStep, setProgressStep] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [policeFields, setPoliceFields] = useState({
    fir_case_id: "",
    investigator_name: "",
    complaint_id: ""
  });

  const handleScan = async (scanEmail) => {
    const targetEmail = scanEmail || email;
    if (!targetEmail) return;

    setLoading(true);
    setError("");
    setResult(null);

    const steps = [
      "Parsing target email domain namespace...",
      "Querying Have I Been Pwned breach repositories...",
      "Auditing exposed credentials datasets...",
      "Resolving compromised data classes...",
      "Compiling digital identity leak threat indices..."
    ];

    for (let i = 0; i < steps.length; i++) {
      setProgressStep(steps[i]);
      await new Promise(resolve => setTimeout(resolve, 400));
    }

    try {
      const response = await axios.post("http://localhost:8000/api/check-osint", {
        email: targetEmail,
        police: policeFields
      });
      setResult(response.data);
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || "Connection to HIBP scanner backend failed.");
    } finally {
      setLoading(false);
    }
  };

  const getThreatColor = (score) => {
    if (score >= 70) return "text-red-500 border-red-900 bg-red-950/20";
    if (score >= 30) return "text-amber-500 border-amber-900 bg-amber-950/20";
    return "text-emerald-500 border-emerald-900 bg-emerald-950/20";
  };

  const getLedBlink = (score) => {
    if (score >= 70) return "led-blink-red";
    if (score >= 30) return "led-blink-yellow";
    return "led-blink-green";
  };

  // Helper to strip HTML tags from HIBP descriptions
  const cleanDescription = (html) => {
    if (!html) return "";
    return html.replace(/<[^>]*>?/gm, "").replace(/&quot;/g, '"');
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-wider text-white uppercase text-glow-cyber font-mono">
          HAVE I BEEN PWNED LOOKUP
        </h1>
        <p className="text-xs text-slate-400 font-mono">
          MODULE // OSINT_HIBP_AUDITOR // CREDENTIAL LEAK DETECTOR
        </p>
      </div>

      {/* Input */}
      <div className="cyber-card cyber-card-corners p-6 space-y-6">
        <label className="block text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
          Enter Target Email Address
        </label>
        <div className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-grow">
            <Mail className="absolute left-3 top-3.5 text-slate-500" size={18} />
            <input
              type="email"
              placeholder="e.g. suspect@domain.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={loading}
              className="w-full pl-10 pr-4 py-3 bg-slate-950 border border-slate-800 rounded font-mono text-sm text-slate-200 focus:outline-none focus:border-cyan-500 transition"
            />
          </div>
          <button
            onClick={() => handleScan()}
            disabled={loading || !email}
            className="px-6 py-3 bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 text-cyan-400 font-bold font-mono text-sm rounded transition disabled:opacity-40 disabled:cursor-not-allowed uppercase"
          >
            {loading ? "Checking..." : "Verify Leak"}
          </button>
        </div>
        
        {/* Police Case Information Section */}
        <div className="border-t border-slate-800 pt-4">
          <label className="block text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider mb-3">
            Case Information (For Police/Investigator Use)
          </label>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="block text-[10px] text-slate-500 uppercase font-mono mb-1">FIR Case ID</label>
              <input
                type="text"
                placeholder="FIR/2024/0123"
                value={policeFields.fir_case_id}
                onChange={(e) => setPoliceFields({...policeFields, fir_case_id: e.target.value})}
                disabled={loading}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded font-mono text-sm text-slate-200 focus:outline-none focus:border-cyan-500 transition"
              />
            </div>
            <div>
              <label className="block text-[10px] text-slate-500 uppercase font-mono mb-1">Investigator Name</label>
              <input
                type="text"
                placeholder="Officer Name"
                value={policeFields.investigator_name}
                onChange={(e) => setPoliceFields({...policeFields, investigator_name: e.target.value})}
                disabled={loading}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded font-mono text-sm text-slate-200 focus:outline-none focus:border-cyan-500 transition"
              />
            </div>
            <div>
              <label className="block text-[10px] text-slate-500 uppercase font-mono mb-1">Complaint ID</label>
              <input
                type="text"
                placeholder="COMP-045"
                value={policeFields.complaint_id}
                onChange={(e) => setPoliceFields({...policeFields, complaint_id: e.target.value})}
                disabled={loading}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded font-mono text-sm text-slate-200 focus:outline-none focus:border-cyan-500 transition"
              />
            </div>
          </div>
        </div>

        {/* Presets */}
        <div className="pt-2">
          <span className="text-[10px] text-slate-500 font-mono uppercase block mb-2">Test Presets:</span>
          <div className="flex flex-wrap gap-2">
            {SAMPLES.map((sample, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setEmail(sample.email);
                  handleScan(sample.email);
                }}
                disabled={loading}
                className="px-2.5 py-1 bg-slate-900/60 hover:bg-slate-900 border border-slate-800 rounded text-[11px] font-mono text-slate-400 hover:text-cyan-400 transition"
              >
                {sample.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="cyber-card cyber-card-corners p-8 flex flex-col items-center justify-center space-y-4">
          <Activity className="animate-spin text-cyan-500 text-glow-cyber" size={40} />
          <div className="w-full max-w-md bg-slate-950 border border-slate-800 rounded-full h-2.5 overflow-hidden">
            <div className="bg-cyan-500 h-full scan-line relative rounded-full" style={{ width: "80%", transition: "width 3s ease-in-out" }}></div>
          </div>
          <span className="text-xs text-cyan-400 font-mono text-center tracking-wider">{progressStep}</span>
        </div>
      )}

      {/* Error Info */}
      {error && (
        <div className="border border-red-950 bg-red-950/20 text-red-400 p-4 rounded font-mono text-xs flex items-center space-x-3">
          <AlertCircle size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs">
          
          {/* Risk Dial Card */}
          <div className="cyber-card cyber-card-corners p-6 flex flex-col items-center justify-between text-center space-y-6 lg:col-span-1">
            <div className="w-full border-b border-slate-800 pb-2 flex justify-between items-center text-xs">
              <span className="text-slate-400 uppercase">Leak Verdict</span>
              <span className="text-cyan-500 text-[10px]">{result.mode} Mode</span>
            </div>

            {/* Score Ring */}
            <div className="relative w-40 h-40 flex items-center justify-center">
              <div className="absolute w-full h-full border-[10px] border-slate-900 rounded-full"></div>
              <div className={`absolute w-36 h-36 border-2 border-dashed rounded-full opacity-35 ${getThreatColor(result.threat_score)}`}></div>
              <div className="flex flex-col items-center justify-center">
                <span className="text-4xl font-black text-slate-100">{result.threat_score}</span>
                <span className="text-[10px] text-slate-400 uppercase tracking-widest">PWNED INDEX</span>
              </div>
            </div>

            {/* Verdict Badge */}
            <div className={`w-full py-2 border rounded font-bold text-sm uppercase flex items-center justify-center space-x-2 ${getThreatColor(result.threat_score)}`}>
              <div className={`w-3.5 h-3.5 rounded-full ${getLedBlink(result.threat_score)}`}></div>
              <span>{result.status} Exposure Level</span>
            </div>

            {/* Core Stats */}
            <div className="w-full bg-slate-950 p-3 rounded border border-slate-900 text-left space-y-1.5 text-[11px]">
              <div><span className="text-slate-500">Exposed Data Breaches:</span> <b className="text-slate-300 font-bold">{result.found_leaks_count} platforms</b></div>
              <div><span className="text-slate-500">Registry Source:</span> {result.api_source}</div>
            </div>
          </div>

          {/* Breaches List & compromised fields */}
          <div className="lg:col-span-2 space-y-6">
            
            {/* Leaked fields list */}
            <div className="cyber-card cyber-card-corners p-6 space-y-4">
              <div className="border-b border-slate-800 pb-2 flex justify-between items-center">
                <span className="text-xs text-cyan-400 font-bold uppercase tracking-wider block">Compromised Data Fields</span>
                <Key className="text-cyan-400" size={16} />
              </div>

              {result.compromised_data_fields.length === 0 ? (
                <div className="p-3 bg-emerald-950/20 border border-emerald-950 text-emerald-400 rounded text-center">
                  Shield active: No credentials leak matches found in HIBP database.
                </div>
              ) : (
                <div className="flex flex-wrap gap-2.5">
                  {result.compromised_data_fields.map((field, idx) => {
                    const isCrit = field.toLowerCase().includes("password") || field.toLowerCase().includes("hash");
                    return (
                      <span 
                        key={idx} 
                        className={`px-3 py-1 border rounded text-[10px] font-bold uppercase tracking-wider ${
                          isCrit 
                            ? "text-red-400 border-red-950 bg-red-950/30 led-blink-red" 
                            : "text-amber-400 border-amber-950 bg-amber-950/20"
                        }`}
                      >
                        {field}
                      </span>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Database Leaks detail cards */}
            <div className="cyber-card cyber-card-corners p-6 space-y-4">
              <div className="border-b border-slate-800 pb-2">
                <span className="text-xs text-cyan-400 font-bold uppercase tracking-wider block">Leaked Database Source Records</span>
              </div>

              {result.breaches.length === 0 ? (
                <div className="text-center py-6 text-slate-500">
                  No public platform spills found under this account email.
                </div>
              ) : (
                <div className="space-y-4 max-h-72 overflow-y-auto pr-1 scrollbar">
                  {result.breaches.map((breach, idx) => (
                    <div key={idx} className="p-4 bg-slate-950 border border-slate-900 rounded hover:border-slate-800 transition space-y-2">
                      <div className="flex justify-between items-start">
                        <div className="flex items-center space-x-2">
                          <Database className="text-cyan-500" size={14} />
                          <span className="font-bold text-slate-200 text-sm">{breach.Title || breach.Name}</span>
                        </div>
                        <span className="px-2 py-0.5 border border-slate-800 bg-slate-900 rounded text-slate-400 text-[10px]">
                          {breach.BreachDate}
                        </span>
                      </div>
                      
                      <p className="text-[11px] text-slate-400 leading-relaxed">{cleanDescription(breach.Description)}</p>
                      
                      <div className="flex flex-wrap items-center pt-1 text-[10px]">
                        <span className="text-slate-500 mr-2 uppercase font-bold">Compromised:</span>
                        <div className="flex flex-wrap gap-1">
                          {breach.DataClasses.map((c, cidx) => (
                            <span key={cidx} className="px-1.5 py-0.5 bg-slate-900 rounded text-slate-300">
                              {c}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

          </div>

        </div>
      )}

    </div>
  );
}
