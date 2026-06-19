import React, { useState } from "react";
import axios from "axios";
import { Mail, Activity, AlertTriangle, ShieldCheck, ShieldAlert, FileText, ArrowRight, CornerDownRight, Server, Shield } from "lucide-react";

const SAMPLE_SPOOFED = `Delivered-To: investigator@police.gov
Received: from mail-relay.hackerdomain.net (unknown [198.51.100.42])
	by mx.google.com with ESMTPS id abc123xyz
	for <investigator@police.gov>
	(version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
	Fri, 19 Jun 2026 11:15:30 +0530
Authentication-Results: mx.google.com;
       dkim=fail header.i=@legit-bank.com;
       spf=fail (google.com: domain of billing@legit-bank.com does not designate 198.51.100.42 as permitted sender) smtp.mailfrom=billing@legit-bank.com;
       dmarc=fail (p=REJECT sp=REJECT) header.from=legit-bank.com
From: "Official Banking Support" <billing@legit-bank.com>
To: investigator@police.gov
Reply-To: refund-department@scam-center.ru
Subject: Critical Refund Notice - Update Immediately
Received-SPF: fail (google.com: domain of billing@legit-bank.com does not designate 198.51.100.42 as permitted sender)
`;

const SAMPLE_SAFE = `Delivered-To: agent@police.gov
Received: from mail-sor-f69.google.com (mail-sor-f69.google.com. [209.85.220.69])
        by mx.google.com with SMTPS id n14sor4242plk;
        Fri, 19 Jun 2026 10:42:00 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XyZ;
       spf=pass (google.com: domain of alerts@google.com designates 209.85.220.69 as permitted sender) smtp.mailfrom=alerts@google.com;
       dmarc=pass (p=REJECT sp=REJECT) header.from=google.com
From: "Google Security Alerts" <alerts@google.com>
To: agent@police.gov
Subject: Security Alert for your Connected Account
Received-SPF: pass (google.com: domain of alerts@google.com designates 209.85.220.69 as permitted sender)
`;

export default function EmailAnalyzer() {
  const [headers, setHeaders] = useState("");
  const [loading, setLoading] = useState(false);
  const [progressStep, setProgressStep] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [policeFields, setPoliceFields] = useState({
    fir_case_id: "",
    investigator_name: "",
    complaint_id: ""
  });

  const handleAnalyze = async (rawHeaders) => {
    const headersToScan = rawHeaders || headers;
    if (!headersToScan.trim()) return; // simple blank checks

    setLoading(true);
    setError("");
    setResult(null);

    // Simulated progress steps for premium interactive experience
    const steps = [
      "Parsing MIME headers block and mapping metadata attributes...",
      "Extracting SPF, DKIM, and DMARC authentication result tags...",
      "Resolving SMTP sender host IP address...",
      "Tracing network relay routing chain hops...",
      "Validating originating server reputation with AbuseIPDB...",
      "Calculating overall spoofing risk level..."
    ];

    for (let i = 0; i < steps.length; i++) {
      setProgressStep(steps[i]);
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    try {
      const response = await axios.post("http://localhost:8000/api/analyze-email", {
        headers: headersToScan,
        police: policeFields
      });
      setResult(response.data);
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || "Connection to API headers parser failed. Check backend server.");
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (risk) => {
    if (risk === "High") return "text-red-500 border-red-900 bg-red-950/20";
    if (risk === "Medium") return "text-amber-500 border-amber-900 bg-amber-950/20";
    return "text-emerald-500 border-emerald-900 bg-emerald-950/20";
  };

  const getLedBlink = (risk) => {
    if (risk === "High") return "led-blink-red";
    if (risk === "Medium") return "led-blink-yellow";
    return "led-blink-green";
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-wider text-white uppercase text-glow-cyber font-mono">
          EMAIL SPOOF ANALYZER
        </h1>
        <p className="text-xs text-slate-400 font-mono">
          MODULE // EMAIL_HEADER_INTERROGATOR // PHISHING & FRAUD DETECTOR
        </p>
      </div>

      {/* Input */}
      <div className="cyber-card cyber-card-corners p-6 space-y-6">
        <label className="block text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
          Paste Raw Email Header Block
        </label>
        
        <textarea
          placeholder="Paste raw email header logs here (e.g. from Gmail Show Original or Outlook View Headers)..."
          rows={8}
          value={headers}
          onChange={(e) => setHeaders(e.target.value)}
          disabled={loading}
          className="w-full p-4 bg-slate-950 border border-slate-800 rounded font-mono text-xs text-slate-300 focus:outline-none focus:border-cyan-500 transition resize-y"
        />

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

        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          {/* Test Presets */}
          <div className="flex flex-wrap gap-2">
            <span className="text-[10px] text-slate-500 font-mono uppercase block w-full md:w-auto self-center mr-1">Test Presets:</span>
            <button
              onClick={() => {
                setHeaders(SAMPLE_SPOOFED);
                handleAnalyze(SAMPLE_SPOOFED);
              }}
              disabled={loading}
              className="px-2.5 py-1 bg-red-950/20 hover:bg-red-950/30 border border-red-900/60 rounded text-[11px] font-mono text-red-400 transition"
            >
              Load Spoofed Header Case
            </button>
            <button
              onClick={() => {
                setHeaders(SAMPLE_SAFE);
                handleAnalyze(SAMPLE_SAFE);
              }}
              disabled={loading}
              className="px-2.5 py-1 bg-emerald-950/20 hover:bg-emerald-950/30 border border-emerald-900/60 rounded text-[11px] font-mono text-emerald-400 transition"
            >
              Load Legitimate Header Case
            </button>
          </div>

          <button
            onClick={() => handleAnalyze()}
            disabled={loading || !headers.trim()}
            className="w-full md:w-auto px-6 py-3 bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 text-cyan-400 font-bold font-mono text-sm rounded transition disabled:opacity-40 disabled:cursor-not-allowed uppercase"
          >
            {loading ? "Analyzing..." : "Analyze Headers"}
          </button>
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

      {/* Result Section */}
      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* Verdict Card */}
          <div className="cyber-card cyber-card-corners p-6 flex flex-col items-center justify-between text-center space-y-6 lg:col-span-1">
            <div className="w-full border-b border-slate-800 pb-2 flex justify-between items-center text-xs font-mono">
              <span className="text-slate-400 uppercase">Verification Summary</span>
              <span className="text-cyan-500 text-[10px]">{result.mode} Mode</span>
            </div>

            {/* Risk Gauge */}
            <div className="relative w-40 h-40 flex items-center justify-center">
              <div className="absolute w-full h-full border-[10px] border-slate-900 rounded-full"></div>
              <div className={`absolute w-36 h-36 border-2 border-dashed rounded-full opacity-35 ${getRiskColor(result.risk_level)}`}></div>
              <div className="flex flex-col items-center justify-center font-mono">
                <span className="text-4xl font-black text-slate-100">{result.spoof_score}</span>
                <span className="text-[10px] text-slate-400 uppercase tracking-widest">SPOOF INDEX</span>
              </div>
            </div>

            {/* Led Status Badge */}
            <div className={`w-full py-2 border rounded font-mono font-bold text-sm uppercase flex items-center justify-center space-x-2 ${getRiskColor(result.risk_level)}`}>
              <div className={`w-3.5 h-3.5 rounded-full ${getLedBlink(result.risk_level)}`}></div>
              <span>{result.risk_level} Spoof Risk</span>
            </div>

            {/* Email Metadata */}
            <div className="w-full bg-slate-950 p-3 rounded border border-slate-900 font-mono text-left text-[11px] space-y-1.5">
              <span className="text-slate-500 block uppercase border-b border-slate-900 pb-1 mb-1 font-bold">Header Metadata</span>
              <div className="truncate"><span className="text-slate-400">From:</span> {result.headers.from}</div>
              <div className="truncate"><span className="text-slate-400">To:</span> {result.headers.to}</div>
              <div className="truncate"><span className="text-slate-400">Subject:</span> {result.headers.subject}</div>
              <div className="truncate"><span className="text-slate-400">Reply-To:</span> {result.headers.reply_to || "Not Specified"}</div>
            </div>
          </div>

          {/* Breakdown reports */}
          <div className="lg:col-span-2 space-y-6">
            
            {/* Auth validation & IP Rep */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              
              {/* Authentications Table */}
              <div className="cyber-card cyber-card-corners p-5 space-y-3">
                <div className="border-b border-slate-800 pb-2">
                  <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider block">Authentication Results</span>
                </div>
                
                <div className="font-mono text-xs space-y-3">
                  {/* SPF */}
                  <div className="flex justify-between items-center border-b border-slate-900 pb-2">
                    <span className="text-slate-400">SPF Validation:</span>
                    <span className={`px-2 py-0.5 border rounded text-[10px] font-bold uppercase ${
                      result.auth_results.spf === "pass" ? "text-emerald-400 border-emerald-950 bg-emerald-950/20" : 
                      result.auth_results.spf === "fail" ? "text-red-400 border-red-950 bg-red-950/20" : "text-amber-400 border-amber-950 bg-amber-950/20"
                    }`}>
                      {result.auth_results.spf}
                    </span>
                  </div>

                  {/* DKIM */}
                  <div className="flex justify-between items-center border-b border-slate-900 pb-2">
                    <span className="text-slate-400">DKIM Signature:</span>
                    <span className={`px-2 py-0.5 border rounded text-[10px] font-bold uppercase ${
                      result.auth_results.dkim === "pass" ? "text-emerald-400 border-emerald-950 bg-emerald-950/20" : 
                      result.auth_results.dkim === "fail" ? "text-red-400 border-red-950 bg-red-950/20" : "text-amber-400 border-amber-950 bg-amber-950/20"
                    }`}>
                      {result.auth_results.dkim}
                    </span>
                  </div>

                  {/* DMARC */}
                  <div className="flex justify-between items-center pb-1">
                    <span className="text-slate-400">DMARC Alignment:</span>
                    <span className={`px-2 py-0.5 border rounded text-[10px] font-bold uppercase ${
                      result.auth_results.dmarc === "pass" ? "text-emerald-400 border-emerald-950 bg-emerald-950/20" : 
                      result.auth_results.dmarc === "fail" ? "text-red-400 border-red-950 bg-red-950/20" : "text-amber-400 border-amber-950 bg-amber-950/20"
                    }`}>
                      {result.auth_results.dmarc}
                    </span>
                  </div>
                </div>
              </div>

              {/* Reply-To mismatch & Sender IP */}
              <div className="cyber-card cyber-card-corners p-5 space-y-3">
                <div className="border-b border-slate-800 pb-2">
                  <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider block">Security Warnings</span>
                </div>
                
                <div className="font-mono text-xs space-y-3">
                  <div className="flex justify-between items-center border-b border-slate-900 pb-2">
                    <span className="text-slate-400">Reply-To Address Check:</span>
                    <span className={`font-bold ${result.mismatch.detected ? "text-red-400" : "text-emerald-400"}`}>
                      {result.mismatch.detected ? "MISMATCH" : "VERIFIED"}
                    </span>
                  </div>
                  {result.mismatch.detected && (
                    <div className="text-[10px] text-red-300 bg-red-950/20 border border-red-950 p-2 rounded">
                      {result.mismatch.details}
                    </div>
                  )}

                  <div className="flex justify-between items-center pt-1">
                    <span className="text-slate-400">Originating Sender IP:</span>
                    <span className="text-cyan-400 font-bold">{result.sender_ip}</span>
                  </div>
                </div>
              </div>

            </div>

            {/* Sender IP AbuseIPDB Reputation */}
            <div className="cyber-card cyber-card-corners p-5 space-y-4">
              <div className="border-b border-slate-800 pb-2 flex justify-between items-center">
                <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider">Originating Host Reputation (AbuseIPDB)</span>
                <span className="text-[10px] text-slate-500 font-mono">Source: {result.ip_reputation.source}</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
                <div className="flex justify-between p-2 bg-slate-950 border border-slate-900 rounded">
                  <span className="text-slate-400">Abuse Confidence Score:</span>
                  <span className={`font-bold ${result.ip_reputation.abuse_score > 30 ? "text-red-400" : "text-emerald-400"}`}>
                    {result.ip_reputation.abuse_score}%
                  </span>
                </div>

                <div className="flex justify-between p-2 bg-slate-950 border border-slate-900 rounded">
                  <span className="text-slate-400">Total Abuse Reports:</span>
                  <span className="text-slate-300 font-bold">{result.ip_reputation.total_reports}</span>
                </div>

                <div className="flex justify-between p-2 bg-slate-950 border border-slate-900 rounded">
                  <span className="text-slate-400">ISP / Provider:</span>
                  <span className="text-slate-300 truncate max-w-[150px]">{result.ip_reputation.isp}</span>
                </div>

                <div className="flex justify-between p-2 bg-slate-950 border border-slate-900 rounded">
                  <span className="text-slate-400">Country Code:</span>
                  <span className="text-slate-300 font-bold">{result.ip_reputation.country}</span>
                </div>
              </div>
            </div>

            {/* SMTP Relay Chain */}
            <div className="cyber-card cyber-card-corners p-5 space-y-4">
              <div className="border-b border-slate-800 pb-2">
                <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider block">Traced Relay Route Chain</span>
              </div>

              <div className="space-y-4">
                {result.relay_hops.map((hop, index) => (
                  <div key={index} className="flex font-mono text-xs items-start">
                    <div className="flex flex-col items-center mr-3 mt-1">
                      <div className="w-5 h-5 border border-cyan-800 bg-cyan-950/40 rounded-full flex items-center justify-center text-[10px] text-cyan-400 font-bold">
                        {hop.hop}
                      </div>
                      {index < result.relay_hops.length - 1 && (
                        <div className="w-[1px] bg-cyan-900 h-10 my-1"></div>
                      )}
                    </div>
                    
                    <div className="flex-grow p-3 bg-slate-950/60 border border-slate-900 rounded hover:border-slate-800 transition">
                      <div className="flex justify-between mb-1.5 font-bold">
                        <span className="text-cyan-400">Hop: {hop.from}</span>
                        <span className="text-slate-400 font-normal">By: {hop.by}</span>
                      </div>
                      <div className="text-[10px] text-slate-500 flex items-center space-x-1.5">
                        <Server size={10} />
                        <span>Transit Node Node IP: <b className="text-slate-400 font-semibold">{hop.ip}</b></span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

          </div>

        </div>
      )}

    </div>
  );
}
