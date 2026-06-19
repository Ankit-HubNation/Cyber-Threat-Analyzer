import React, { useState } from "react";
import axios from "axios";
import { Globe, Activity, ShieldAlert, ShieldCheck, Calendar, Info, Shield, Key } from "lucide-react";

const SAMPLES = [
  { label: "Established (microsoft.com)", domain: "microsoft.com" },
  { label: "DNS Audit (github.com)", domain: "github.com" },
  { label: "Recent Domain (fresh-domain.xyz)", domain: "fresh-domain.xyz" }
];

export default function DomainLookup() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [progressStep, setProgressStep] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [policeFields, setPoliceFields] = useState({
    fir_case_id: "",
    investigator_name: "",
    complaint_id: ""
  });
  const [dnsTab, setDnsTab] = useState("A");

  const handleLookup = async (targetDomain) => {
    const queryDomain = targetDomain || domain;
    if (!queryDomain) return;

    setLoading(true);
    setError("");
    setResult(null);

    const steps = [
      "Cleaning domain syntax and filtering protocols...",
      "Connecting to WHOIS registries via Port 43...",
      "Retrieving registrar creation and expiration timelines...",
      "Calculating exact domain age vector...",
      "Resolving current DNS zone records (A, MX, TXT)..."
    ];

    for (let i = 0; i < steps.length; i++) {
      setProgressStep(steps[i]);
      await new Promise(resolve => setTimeout(resolve, 400));
    }

    try {
      const response = await axios.post("http://localhost:8000/api/domain-info", {
        domain: queryDomain,
        police: policeFields
      });
      setResult(response.data);
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || "Connection to API domain lookup failed. Check backend server.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-wider text-white uppercase text-glow-cyber font-mono">
          DOMAIN INTELLIGENCE LOOKUP
        </h1>
        <p className="text-xs text-slate-400 font-mono">
          MODULE // WHOIS_RESOLVER // REGISTRAR & Zone DNS AUDITOR
        </p>
      </div>

      {/* Input */}
      <div className="cyber-card cyber-card-corners p-6 space-y-6">
        <label className="block text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
          Enter Domain Name
        </label>
        <div className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-grow">
            <Globe className="absolute left-3 top-3.5 text-slate-500" size={18} />
            <input
              type="text"
              placeholder="e.g. domain-name.org"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              disabled={loading}
              className="w-full pl-10 pr-4 py-3 bg-slate-950 border border-slate-800 rounded font-mono text-sm text-slate-200 focus:outline-none focus:border-cyan-500 transition"
            />
          </div>
          <button
            onClick={() => handleLookup()}
            disabled={loading || !domain}
            className="px-6 py-3 bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 text-cyan-400 font-bold font-mono text-sm rounded transition disabled:opacity-40 disabled:cursor-not-allowed uppercase"
          >
            {loading ? "Resolving..." : "Query Domain"}
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
                  setDomain(sample.domain);
                  handleLookup(sample.domain);
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
          <ShieldAlert size={18} />
          <span>{error}</span>
        </div>
      )}

      {/* Result presentation */}
      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono">
          
          {/* Main Info Card */}
          <div className="cyber-card cyber-card-corners p-6 space-y-6 lg:col-span-1 flex flex-col justify-between">
            <div>
              <div className="border-b border-slate-800 pb-2 flex justify-between items-center text-xs">
                <span className="text-slate-400 uppercase">Domain Summary</span>
                <span className={`px-2 py-0.5 border rounded text-[9px] font-bold ${
                  result.status === "Safe" ? "text-emerald-400 border-emerald-950 bg-emerald-950/20" : "text-amber-400 border-amber-950 bg-amber-950/20"
                }`}>{result.status}</span>
              </div>

              {/* Age Display Badge */}
              <div className="my-6 p-4 bg-slate-950/80 border border-slate-900 rounded text-center">
                <Calendar className="mx-auto text-cyan-400 mb-2" size={28} />
                <span className="text-[10px] text-slate-500 uppercase block">Domain Age</span>
                <span className="text-sm font-bold text-white block mt-1">{result.whois.domain_age}</span>
              </div>

              {/* Assessment Text */}
              <div className="p-3 bg-slate-950 border border-slate-900 rounded text-[11px] flex items-start space-x-2">
                <Info size={14} className="text-cyan-400 flex-shrink-0 mt-0.5" />
                <div>
                  <span className="text-slate-400 block font-bold uppercase mb-1">Threat Assessment</span>
                  <span className="text-slate-300 leading-relaxed">{result.assessment}</span>
                </div>
              </div>
            </div>

            <div className="text-[10px] text-slate-500 uppercase pt-4 border-t border-slate-900">
              Target: {result.domain}
            </div>
          </div>

          {/* Details & DNS tab */}
          <div className="lg:col-span-2 space-y-6">
            
            {/* WHOIS records details */}
            <div className="cyber-card cyber-card-corners p-6 space-y-4">
              <div className="border-b border-slate-800 pb-2">
                <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider block">WHOIS Registration Details</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="flex flex-col p-2.5 bg-slate-950 border border-slate-900 rounded">
                  <span className="text-slate-500 mb-1">Registrar Organization:</span>
                  <span className="text-slate-200 font-bold truncate">{result.whois.registrar || "N/A"}</span>
                </div>

                <div className="flex flex-col p-2.5 bg-slate-950 border border-slate-900 rounded">
                  <span className="text-slate-500 mb-1">Registrant Country:</span>
                  <span className="text-slate-300 font-bold">{result.whois.country || "N/A"}</span>
                </div>

                <div className="flex flex-col p-2.5 bg-slate-950 border border-slate-900 rounded">
                  <span className="text-slate-500 mb-1">Creation Date:</span>
                  <span className="text-slate-300">
                    {result.whois.creation_date ? new Date(result.whois.creation_date).toLocaleDateString() : "Unknown"}
                  </span>
                </div>

                <div className="flex flex-col p-2.5 bg-slate-950 border border-slate-900 rounded">
                  <span className="text-slate-500 mb-1">Expiration Date:</span>
                  <span className="text-slate-300">
                    {result.whois.expiration_date ? new Date(result.whois.expiration_date).toLocaleDateString() : "Unknown"}
                  </span>
                </div>

                {/* Abuse contacts */}
                <div className="flex flex-col p-2.5 bg-slate-950 border border-slate-900 rounded col-span-1 md:col-span-2">
                  <span className="text-slate-500 mb-1">WHOIS Abuse Contact Emails:</span>
                  {result.whois.emails.length === 0 ? (
                    <span className="text-slate-500">None listed</span>
                  ) : (
                    <span className="text-cyan-400 font-semibold break-all">{result.whois.emails.join(", ")}</span>
                  )}
                </div>

                {/* Nameservers */}
                <div className="flex flex-col p-2.5 bg-slate-950 border border-slate-900 rounded col-span-1 md:col-span-2">
                  <span className="text-slate-500 mb-1">Authoritative Nameservers:</span>
                  {result.whois.nameservers.length === 0 ? (
                    <span className="text-slate-500">None listed</span>
                  ) : (
                    <span className="text-slate-300 font-mono break-all">{result.whois.nameservers.map(ns => ns.toLowerCase()).join(", ")}</span>
                  )}
                </div>
              </div>
            </div>

            {/* DNS Records Panel */}
            <div className="cyber-card cyber-card-corners p-6 space-y-4">
              <div className="border-b border-slate-800 pb-2">
                <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider block">Zone DNS Records Auditor</span>
              </div>

              {/* DNS tabs */}
              <div className="flex border-b border-slate-900 font-mono text-xs">
                {Object.keys(result.dns).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setDnsTab(tab)}
                    className={`px-4 py-2 border-b-2 font-bold transition ${
                      dnsTab === tab ? "border-cyan-500 text-cyan-400" : "border-transparent text-slate-500 hover:text-slate-300"
                    }`}
                  >
                    {tab} ({result.dns[tab].length})
                  </button>
                ))}
              </div>

              {/* Tab Content */}
              <div className="p-3 bg-slate-950 border border-slate-900 rounded max-h-48 overflow-y-auto text-[11px] font-mono scrollbar">
                {result.dns[dnsTab].length === 0 ? (
                  <span className="text-slate-600 block italic py-2">No {dnsTab} records registered in this zone.</span>
                ) : (
                  <ul className="space-y-1">
                    {result.dns[dnsTab].map((rec, index) => (
                      <li key={index} className="text-slate-300 select-all hover:bg-slate-900 p-1 rounded">
                        <span className="text-cyan-600 mr-2">[{index + 1}]</span> {rec}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>

          </div>

        </div>
      )}

    </div>
  );
}
