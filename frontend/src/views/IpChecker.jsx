import React, { useState } from "react";
import axios from "axios";
import { Server, Activity, ShieldAlert, ShieldCheck, MapPin, Globe, Compass, AlertTriangle } from "lucide-react";

const SAMPLES = [
  { label: "Legitimate (8.8.8.8)", ip: "8.8.8.8" },
  { label: "Suspicious Node (198.51.100.42)", ip: "198.51.100.42" },
  { label: "Local Private (127.0.0.1)", ip: "127.0.0.1" }
];

export default function IpChecker() {
  const [ip, setIp] = useState("");
  const [loading, setLoading] = useState(false);
  const [progressStep, setProgressStep] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [policeFields, setPoliceFields] = useState({
    fir_case_id: "",
    investigator_name: "",
    complaint_id: ""
  });

  const handleCheck = async (targetIp) => {
    const queryIp = targetIp || ip;
    if (!queryIp) return;

    setLoading(true);
    setError("");
    setResult(null);

    const steps = [
      "Verifying IP address formatting validation...",
      "Connecting to global GeoIP databases...",
      "Resolving hosting autonomous system number (ASN)...",
      "Retrieving AbuseIPDB database logs registry...",
      "Parsing reported threat incidents counts..."
    ];

    for (let i = 0; i < steps.length; i++) {
      setProgressStep(steps[i]);
      await new Promise(resolve => setTimeout(resolve, 400));
    }

    try {
      const response = await axios.post("http://localhost:8000/api/check-ip", {
        ip: queryIp,
        police: policeFields
      });
      setResult(response.data);
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || "Connection to API IP checker failed. Check backend server.");
    } finally {
      setLoading(false);
    }
  };

  const getThreatColor = (score) => {
    if (score >= 50) return "text-red-500 border-red-900 bg-red-950/20";
    if (score >= 15) return "text-amber-500 border-amber-900 bg-amber-950/20";
    return "text-emerald-500 border-emerald-900 bg-emerald-950/20";
  };

  const getLedBlink = (score) => {
    if (score >= 50) return "led-blink-red";
    if (score >= 15) return "led-blink-yellow";
    return "led-blink-green";
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-wider text-white uppercase text-glow-cyber font-mono">
          IP REPUTATION CHECKER
        </h1>
        <p className="text-xs text-slate-400 font-mono">
          MODULE // IP_AUDITOR // GEOGRAPHIC & RISK EXAMINER
        </p>
      </div>

      {/* Input */}
      <div className="cyber-card cyber-card-corners p-6 space-y-6">
        <label className="block text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
          Enter IP Address (IPv4 or IPv6)
        </label>
        <div className="flex flex-col md:flex-row gap-3">
          <div className="relative flex-grow">
            <Server className="absolute left-3 top-3.5 text-slate-500" size={18} />
            <input
              type="text"
              placeholder="e.g. 185.220.101.4"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              disabled={loading}
              className="w-full pl-10 pr-4 py-3 bg-slate-950 border border-slate-800 rounded font-mono text-sm text-slate-200 focus:outline-none focus:border-cyan-500 transition"
            />
          </div>
          <button
            onClick={() => handleCheck()}
            disabled={loading || !ip}
            className="px-6 py-3 bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 text-cyan-400 font-bold font-mono text-sm rounded transition disabled:opacity-40 disabled:cursor-not-allowed uppercase"
          >
            {loading ? "Checking..." : "Verify IP"}
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
                  setIp(sample.ip);
                  handleCheck(sample.ip);
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
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* Risk Verdict */}
          <div className="cyber-card cyber-card-corners p-6 flex flex-col items-center justify-between text-center space-y-6 lg:col-span-1">
            <div className="w-full border-b border-slate-800 pb-2 flex justify-between items-center text-xs font-mono">
              <span className="text-slate-400 uppercase">IP Risk Rating</span>
              <span className="text-cyan-500 text-[10px]">{result.mode}</span>
            </div>

            {/* Confidence Score Dial */}
            <div className="relative w-40 h-40 flex items-center justify-center">
              <div className="absolute w-full h-full border-[10px] border-slate-900 rounded-full"></div>
              <div className={`absolute w-36 h-36 border-2 border-dashed rounded-full opacity-35 ${getThreatColor(result.threat_score)}`}></div>
              <div className="flex flex-col items-center justify-center font-mono">
                <span className="text-4xl font-black text-slate-100">{result.threat_score}%</span>
                <span className="text-[10px] text-slate-400 uppercase tracking-widest">ABUSE INDEX</span>
              </div>
            </div>

            {/* LED Verdict Badge */}
            <div className={`w-full py-2 border rounded font-mono font-bold text-sm uppercase flex items-center justify-center space-x-2 ${getThreatColor(result.threat_score)}`}>
              <div className={`w-3.5 h-3.5 rounded-full ${getLedBlink(result.threat_score)}`}></div>
              <span>{result.status} Status</span>
            </div>

            <span className="text-[10px] text-slate-500 font-mono uppercase tracking-wider block">
              TARGET IP: {result.ip}
            </span>
          </div>

          {/* Details breakdown */}
          <div className="lg:col-span-2 space-y-6">
            
            {/* Geo Info */}
            <div className="cyber-card cyber-card-corners p-6 space-y-4">
              <div className="border-b border-slate-800 pb-2 flex justify-between items-center">
                <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider block">Geographical Coordinates (GeoIP)</span>
                <MapPin className="text-cyan-400" size={16} />
              </div>

              {result.geo.error ? (
                <div className="text-xs text-amber-400 bg-amber-950/20 border border-amber-900/60 p-3 rounded font-mono">
                  {result.geo.error} // Private subnet / local address coordinates omitted.
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
                  <div className="flex justify-between p-2.5 bg-slate-950 border border-slate-900 rounded">
                    <span className="text-slate-400">Country:</span>
                    <span className="text-slate-300 font-bold">{result.geo.country} ({result.geo.country_code})</span>
                  </div>

                  <div className="flex justify-between p-2.5 bg-slate-950 border border-slate-900 rounded">
                    <span className="text-slate-400">Region / State:</span>
                    <span className="text-slate-300">{result.geo.region || "Unknown"}</span>
                  </div>

                  <div className="flex justify-between p-2.5 bg-slate-950 border border-slate-900 rounded">
                    <span className="text-slate-400">City / Postal:</span>
                    <span className="text-slate-300">{result.geo.city || "Unknown"} ({result.geo.zip || "-"})</span>
                  </div>

                  <div className="flex justify-between p-2.5 bg-slate-950 border border-slate-900 rounded">
                    <div className="flex items-center space-x-1">
                      <Compass size={12} className="text-cyan-500" />
                      <span className="text-slate-400">Coordinates:</span>
                    </div>
                    <span className="text-slate-300 font-bold">{result.geo.lat}, {result.geo.lon}</span>
                  </div>
                </div>
              )}
            </div>

            {/* ISP & Abuse details */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              
              {/* Network Credentials */}
              <div className="cyber-card cyber-card-corners p-5 space-y-3">
                <div className="border-b border-slate-800 pb-2">
                  <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider block">Network Provider Metadata</span>
                </div>

                <div className="font-mono text-xs space-y-3">
                  <div className="flex flex-col border-b border-slate-900 pb-2">
                    <span className="text-slate-500 mb-1">Internet Service Provider (ISP):</span>
                    <span className="text-slate-200 font-bold truncate">{result.geo.isp || "Unknown ISP"}</span>
                  </div>

                  <div className="flex flex-col border-b border-slate-900 pb-2">
                    <span className="text-slate-500 mb-1">Organization:</span>
                    <span className="text-slate-200 truncate">{result.geo.org || "Unknown Org"}</span>
                  </div>

                  <div className="flex flex-col">
                    <span className="text-slate-500 mb-1">AS Number (ASN):</span>
                    <span className="text-slate-300 font-bold truncate">{result.geo.asn || "N/A"}</span>
                  </div>
                </div>
              </div>

              {/* Abuse Logs */}
              <div className="cyber-card cyber-card-corners p-5 space-y-3">
                <div className="border-b border-slate-800 pb-2">
                  <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider block">Abuse Records Registry</span>
                </div>

                <div className="font-mono text-xs space-y-3">
                  <div className="flex justify-between border-b border-slate-900 pb-2">
                    <span className="text-slate-500">Registry Source:</span>
                    <span className="text-slate-300">{result.reputation.source}</span>
                  </div>

                  <div className="flex justify-between border-b border-slate-900 pb-2">
                    <span className="text-slate-500">Total Abuse Reports:</span>
                    <span className={`font-bold ${result.reputation.total_reports > 0 ? "text-red-400" : "text-slate-400"}`}>
                      {result.reputation.total_reports} reports
                    </span>
                  </div>

                  <div className="flex flex-col">
                    <span className="text-slate-500 mb-1">Last Reported:</span>
                    <span className="text-slate-300">
                      {result.reputation.last_reported_at ? new Date(result.reputation.last_reported_at).toLocaleString() : "No recent reports (Clean)"}
                    </span>
                  </div>
                </div>
              </div>

            </div>

          </div>

        </div>
      )}

    </div>
  );
}
