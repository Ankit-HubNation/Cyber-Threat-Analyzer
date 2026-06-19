import React, { useState } from "react";
import axios from "axios";
import { Link2, Shield, Activity, ShieldAlert, ShieldCheck, AlertTriangle, ExternalLink, HelpCircle, Lock, Unlock } from "lucide-react";

const SAMPLES = [
  { label: "Legitimate (google.com)", url: "https://google.com" },
  { label: "Suspicious Shortener (bit.ly + keyword)", url: "http://bit.ly/secure-banking-login-verify" },
  { label: "Malicious Phish (paypal-signin.xyz)", url: "http://paypal-signin-verify.secure-phish.xyz/login/verify.html" }
];

export default function UrlScanner() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [progressStep, setProgressStep] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [policeFields, setPoliceFields] = useState({
    fir_case_id: "",
    investigator_name: "",
    complaint_id: ""
  });

  const handleScan = async (scanUrl) => {
    const targetUrl = scanUrl || url;
    if (!targetUrl) return;

    setLoading(true);
    setError("");
    setResult(null);

    // Simulated progress steps for premium interactive experience
    const steps = [
      "Parsing URL structures and checking host formatting...",
      "Initiating remote SSL/TLS socket verification...",
      "Submitting payload identifiers to VirusTotal registries...",
      "Querying URLScan.io visual site indexing...",
      "Compiling complete risk vectors and security score..."
    ];

    for (let i = 0; i < steps.length; i++) {
      setProgressStep(steps[i]);
      await new Promise(resolve => setTimeout(resolve, 600));
    }

    try {
      const response = await axios.post("http://localhost:8000/api/scan-url", {
        url: targetUrl,
        police: policeFields
      });
      setResult(response.data);
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || "Connection to API scanner failed. Check backend server.");
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

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-wider text-white uppercase text-glow-cyber font-mono">
          URL THREAT SCANNER
        </h1>
        <p className="text-xs text-slate-400 font-mono">
          MODULE // URL_SCAN_INTELLIGENCE // REALTIME WEB RESOURCE AUDITOR
        </p>
      </div>

      {/* Input Form */}
      <div className="cyber-card cyber-card-corners p-6 space-y-6">
        <label className="block text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
          Enter URL for Cyber Analysis
        </label>
        <div className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-grow">
            <Link2 className="absolute left-3 top-3.5 text-slate-500" size={18} />
            <input
              type="text"
              placeholder="e.g. http://login-verify-account.com/secure"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={loading}
              className="w-full pl-10 pr-4 py-3 bg-slate-950 border border-slate-800 rounded font-mono text-sm text-slate-200 focus:outline-none focus:border-cyan-500 transition"
            />
          </div>
          <button
            onClick={() => handleScan()}
            disabled={loading || !url}
            className="px-6 py-3 bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 text-cyan-400 font-bold font-mono text-sm rounded transition disabled:opacity-40 disabled:cursor-not-allowed uppercase"
          >
            {loading ? "Scanning..." : "Execute Scan"}
          </button>
        </div>
        
        {/* Police Case Information Section */}
        <div className="border-t border-slate-800 pt-4">
          <label className="block text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider mb-3">
            Case Information (For Police/Investigator Use
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

        {/* Sample Links */}
        <div className="pt-2">
          <span className="text-[10px] text-slate-500 font-mono uppercase block mb-2">Test Presets for Investigators:</span>
          <div className="flex flex-wrap gap-2">
            {SAMPLES.map((sample, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setUrl(sample.url);
                  handleScan(sample.url);
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

      {/* Loading State */}
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

      {/* Result Presentation */}
      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* Main Risk Card */}
          <div className="cyber-card cyber-card-corners p-6 flex flex-col items-center justify-between text-center space-y-6 lg:col-span-1">
            <div className="w-full border-b border-slate-800 pb-2 flex justify-between items-center text-xs font-mono">
              <span className="text-slate-400 uppercase">Threat Verdict</span>
              <span className="text-cyan-500 text-[10px]">{result.mode} Mode</span>
            </div>

            {/* Score Radial Indicator */}
            <div className="relative w-40 h-40 flex items-center justify-center">
              {/* Outer gauge track */}
              <div className="absolute w-full h-full border-[10px] border-slate-900 rounded-full"></div>
              {/* Inner threat color border */}
              <div className={`absolute w-36 h-36 border-2 border-dashed rounded-full opacity-35 ${getThreatColor(result.threat_score)}`}></div>
              {/* Score output */}
              <div className="flex flex-col items-center justify-center font-mono">
                <span className="text-4xl font-black text-slate-100">{result.threat_score}</span>
                <span className="text-[10px] text-slate-400 uppercase tracking-widest">RISK INDEX</span>
              </div>
            </div>

            {/* Score Label Badge */}
            <div className={`w-full py-2 border rounded font-mono font-bold text-sm uppercase flex items-center justify-center space-x-2 ${getThreatColor(result.threat_score)}`}>
              <div className={`w-3.5 h-3.5 rounded-full ${getLedBlink(result.threat_score)}`}></div>
              <span>{result.status} Threat Level</span>
            </div>
            
            <span className="text-[10px] text-slate-500 font-mono uppercase tracking-wider block">
              TARGET URL: {result.url}
            </span>
          </div>

          {/* Details & API findings */}
          <div className="lg:col-span-2 space-y-6">
            
            {/* Heuristics breakdown */}
            <div className="cyber-card cyber-card-corners p-6 space-y-4">
              <div className="border-b border-slate-800 pb-2">
                <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider block">Local Threat Indicators Heuristics</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
                
                {/* Shortener check */}
                <div className="flex justify-between items-center p-2.5 bg-slate-950 rounded border border-slate-900">
                  <span className="text-slate-400">Shortened URL Redirection:</span>
                  <span className={result.heuristics.is_shortened ? "text-amber-400 font-bold" : "text-slate-500"}>
                    {result.heuristics.is_shortened ? "DETECTED (Flagged)" : "No Shortening Detected"}
                  </span>
                </div>

                {/* IP-based URL check */}
                <div className="flex justify-between items-center p-2.5 bg-slate-950 rounded border border-slate-900">
                  <span className="text-slate-400">IP Host Name Address:</span>
                  <span className={result.heuristics.is_ip ? "text-red-400 font-bold" : "text-slate-500"}>
                    {result.heuristics.is_ip ? "YES (Highly Suspicious)" : "No (Normal Hostname)"}
                  </span>
                </div>

                {/* SSL check */}
                <div className="flex justify-between items-center p-2.5 bg-slate-950 rounded border border-slate-900 col-span-1 md:col-span-2">
                  <div className="flex items-center space-x-2">
                    {result.heuristics.ssl_valid ? <Lock className="text-emerald-400" size={14} /> : <Unlock className="text-red-400" size={14} />}
                    <span className="text-slate-400">SSL Certificate Status:</span>
                  </div>
                  <span className={result.heuristics.ssl_valid ? "text-emerald-400 font-bold" : "text-red-400 font-bold"}>
                    {result.heuristics.ssl_details}
                  </span>
                </div>

                {/* Keyword alerts */}
                <div className="col-span-1 md:col-span-2 p-2.5 bg-slate-950 rounded border border-slate-900">
                  <span className="text-slate-400 block mb-2">Phishing Keyword Detections:</span>
                  {result.heuristics.keyword_hits.length === 0 ? (
                    <span className="text-slate-500">None detected</span>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      {result.heuristics.keyword_hits.map((kw, idx) => (
                        <span key={idx} className="px-2 py-0.5 bg-amber-950/40 border border-amber-900 text-amber-400 rounded text-[10px] uppercase font-bold">
                          {kw}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

              </div>
            </div>

            {/* Registry API results */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              
              {/* VirusTotal Report */}
              <div className="cyber-card cyber-card-corners p-5 space-y-3">
                <div className="border-b border-slate-800 pb-2">
                  <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider block">VirusTotal Registry</span>
                </div>
                
                {result.virustotal ? (
                  <div className="font-mono text-xs space-y-2">
                    <div className="flex justify-between border-b border-slate-900 pb-1.5">
                      <span className="text-slate-500">Source:</span>
                      <span className="text-slate-300 font-semibold">{result.virustotal.source}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-900 pb-1.5">
                      <span className="text-slate-500">Malicious Flag:</span>
                      <span className={result.virustotal.malicious > 0 ? "text-red-400 font-bold" : "text-emerald-400"}>
                        {result.virustotal.malicious} engines
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-900 pb-1.5">
                      <span className="text-slate-500">Suspicious Flag:</span>
                      <span className={result.virustotal.suspicious > 0 ? "text-amber-400 font-bold" : "text-slate-400"}>
                        {result.virustotal.suspicious} engines
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Clean / Undetected:</span>
                      <span className="text-slate-400">
                        {result.virustotal.harmless + result.virustotal.undetected} engines
                      </span>
                    </div>
                  </div>
                ) : (
                  <span className="text-xs text-slate-500 font-mono block">No VirusTotal records found.</span>
                )}
              </div>

              {/* URLScan Report */}
              <div className="cyber-card cyber-card-corners p-5 space-y-3">
                <div className="border-b border-slate-800 pb-2">
                  <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider block">URLScan.io Visual Snapshot</span>
                </div>
                
                {result.urlscan ? (
                  <div className="font-mono text-xs space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-slate-500">Snapshot Source:</span>
                      <span className="text-slate-300">{result.urlscan.source}</span>
                    </div>
                    {result.urlscan.screenshot && (
                      <div className="relative border border-slate-800 rounded overflow-hidden h-24">
                        <img 
                          src={result.urlscan.screenshot} 
                          alt="URLScan Screenshot preview"
                          className="w-full h-full object-cover" 
                          onError={(e) => {
                            e.target.src = "https://images.unsplash.com/photo-1563986768609-322da13575f3?w=300&auto=format&fit=crop&q=60";
                          }}
                        />
                        <div className="absolute inset-0 bg-gradient-to-t from-slate-950 via-transparent to-transparent flex items-end p-1">
                          <span className="text-[9px] text-slate-400">UUID: {result.urlscan.scan_id.substring(0, 12)}...</span>
                        </div>
                      </div>
                    )}
                    <a 
                      href={result.urlscan.result_url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-cyan-400 hover:text-cyan-300 font-bold text-[10px] flex items-center justify-end space-x-1"
                    >
                      <span>View Live Index Report</span>
                      <ExternalLink size={10} />
                    </a>
                  </div>
                ) : (
                  <span className="text-xs text-slate-500 font-mono block">No URLScan indices cataloged.</span>
                )}
              </div>

            </div>

          </div>

        </div>
      )}

    </div>
  );
}
