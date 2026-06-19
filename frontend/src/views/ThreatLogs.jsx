import React, { useEffect, useState } from "react";
import api from "../api";
import { Terminal, Search, Filter, Calendar, Save, Trash2, X, FileText, ChevronRight, Activity, Download } from "lucide-react";

export default function ThreatLogs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  
  // Search & Filter state
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState("ALL");
  const [filterSeverity, setFilterSeverity] = useState("ALL");

  // Selected Log Drawer state
  const [selectedLog, setSelectedLog] = useState(null);
  const [noteText, setNoteText] = useState("");
  const [savingNote, setSavingNote] = useState(false);
  
  // Police fields state for selected log
  const [policeFields, setPoliceFields] = useState({
    fir_case_id: "",
    investigator_name: "",
    complaint_id: ""
  });
  const [savingPoliceFields, setSavingPoliceFields] = useState(false);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const response = await api.get("/api/logs");
      setLogs(response.data);
    } catch (err) {
      console.error(err);
      setError("Failed to query threat logs from database.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const handleSelectLog = (log) => {
    setSelectedLog(log);
    setNoteText(log.analyst_notes || "");
    setPoliceFields({
      fir_case_id: log.fir_case_id || "",
      investigator_name: log.investigator_name || "",
      complaint_id: log.complaint_id || ""
    });
  };
  
  const handleSavePoliceFields = async () => {
    if (!selectedLog) return;
    setSavingPoliceFields(true);
    try {
      const response = await api.post(`/api/logs/${selectedLog.id}/police`, policeFields);
      // Update local state
      setLogs(logs.map(log => 
        log.id === selectedLog.id ? { ...log, ...policeFields } : log
      ));
      setSelectedLog({ ...selectedLog, ...policeFields });
    } catch (err) {
      console.error(err);
      alert("Failed to save police fields. Check backend server.");
    } finally {
      setSavingPoliceFields(false);
    }
  };
  
  const handleExportPDF = async () => {
    if (!selectedLog) return;
    try {
      const response = await api.get(`/api/logs/${selectedLog.id}/pdf`, {
        responseType: 'blob'
      });
      // Create a download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `threat-report-${selectedLog.id}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error(err);
      alert("Failed to export PDF. Check backend server.");
    }
  };

  const handleSaveNotes = async () => {
    if (!selectedLog) return;
    setSavingNote(true);
    try {
      await api.post(`/api/logs/${selectedLog.id}/notes`, {
        analyst_notes: noteText
      });
      // Update local logs list state
      setLogs(logs.map(log => 
        log.id === selectedLog.id ? { ...log, analyst_notes: noteText } : log
      ));
      setSelectedLog({ ...selectedLog, analyst_notes: noteText });
      alert("Analyst notes saved successfully.");
    } catch (err) {
      console.error(err);
      alert("Failed to save analyst notes. Check backend connection.");
    } finally {
      setSavingNote(false);
    }
  };

  const handleDeleteLog = async (logId) => {
    if (!window.confirm("Are you sure you want to delete this threat log entry from evidence files?")) {
      return;
    }
    try {
      await api.delete(`/api/logs/${logId}`);
      setLogs(logs.filter(log => log.id !== logId));
      if (selectedLog && selectedLog.id === logId) {
        setSelectedLog(null);
      }
    } catch (err) {
      console.error(err);
      alert("Failed to delete log entry.");
    }
  };

  const getSeverityBadge = (status) => {
    const s = (status || "Safe").toLowerCase();
    if (s.includes("malicious") || s.includes("high")) {
      return "text-red-400 border-red-950 bg-red-950/20";
    }
    if (s.includes("suspicious") || s.includes("medium")) {
      return "text-amber-400 border-amber-950 bg-amber-950/20";
    }
    return "text-emerald-400 border-emerald-950 bg-emerald-950/20";
  };

  // Filter logic
  const filteredLogs = logs.filter(log => {
    const inputMatches = log.input_value.toLowerCase().includes(search.toLowerCase());
    const typeMatches = filterType === "ALL" || log.scan_type === filterType;
    
    const severity = (log.result?.status || log.result?.risk_level || "Safe").toLowerCase();
    let severityMatches = true;
    if (filterSeverity !== "ALL") {
      if (filterSeverity === "MALICIOUS") {
        severityMatches = severity.includes("malicious") || severity.includes("high");
      } else if (filterSeverity === "SUSPICIOUS") {
        severityMatches = severity.includes("suspicious") || severity.includes("medium");
      } else if (filterSeverity === "SAFE") {
        severityMatches = !severity.includes("malicious") && !severity.includes("high") && !severity.includes("suspicious") && !severity.includes("medium");
      }
    }
    return inputMatches && typeMatches && severityMatches;
  });

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold tracking-wider text-white uppercase text-glow-cyber font-mono">
          THREAT LOGS & EVIDENCE DATABASE
        </h1>
        <p className="text-xs text-slate-400 font-mono">
          MODULE // EVIDENCE_STORE // AUDITED SECURITY INCIDENTS RECORDS
        </p>
      </div>

      {/* Filters & Search */}
      <div className="cyber-card cyber-card-corners p-4 grid grid-cols-1 md:grid-cols-4 gap-4 font-mono text-xs">
        {/* Search */}
        <div className="relative col-span-1 md:col-span-2">
          <Search className="absolute left-2.5 top-2 text-slate-500" size={14} />
          <input
            type="text"
            placeholder="Search by input telemetry..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-cyan-500 transition"
          />
        </div>

        {/* Scan Type Filter */}
        <div className="flex items-center space-x-2">
          <Filter className="text-slate-500" size={14} />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="w-full py-1.5 px-2 bg-slate-950 border border-slate-800 text-slate-300 rounded focus:outline-none focus:border-cyan-500 transition"
          >
            <option value="ALL">All Types</option>
            <option value="URL">URL Scans</option>
            <option value="EMAIL">Email Headers</option>
            <option value="IP">IP Addresses</option>
            <option value="DOMAIN">Domains WHOIS</option>
          </select>
        </div>

        {/* Severity Filter */}
        <div className="flex items-center space-x-2">
          <ChevronRight className="text-slate-500" size={14} />
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="w-full py-1.5 px-2 bg-slate-950 border border-slate-800 text-slate-300 rounded focus:outline-none focus:border-cyan-500 transition"
          >
            <option value="ALL">All Verdicts</option>
            <option value="SAFE">Clean (Safe)</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="MALICIOUS">Malicious / High</option>
          </select>
        </div>
      </div>

      {/* Main Table layout / Loading */}
      {loading ? (
        <div className="flex flex-col items-center justify-center h-48 text-cyan-500">
          <Activity className="animate-spin mb-4" size={32} />
          <span className="font-mono text-xs tracking-wider">RETRIEVING THREAT INTELLIGENCE logs...</span>
        </div>
      ) : error ? (
        <div className="border border-red-950 bg-red-950/20 text-red-400 p-4 rounded font-mono text-xs">
          {error}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* Logs Table */}
          <div className="cyber-card cyber-card-corners p-4 lg:col-span-2 overflow-x-auto scrollbar">
            {filteredLogs.length === 0 ? (
              <div className="text-center p-8 text-slate-500 font-mono text-xs">
                NO EVIDENCE LOGS FOUND FOR GIVEN FILTER PARAMETERS.
              </div>
            ) : (
              <table className="w-full font-mono text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-cyan-400 text-[10px] uppercase font-bold tracking-wider">
                    <th className="py-2 px-3">Date</th>
                    <th className="py-2 px-3">Type</th>
                    <th className="py-2 px-3">Telemetry Input</th>
                    <th className="py-2 px-3 text-right">Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-900/60">
                  {filteredLogs.map((log) => {
                    const severity = log.result?.status || log.result?.risk_level || "Safe";
                    return (
                      <tr 
                        key={log.id} 
                        onClick={() => handleSelectLog(log)}
                        className={`hover:bg-slate-900/40 cursor-pointer transition ${
                          selectedLog && selectedLog.id === log.id ? "bg-slate-900" : ""
                        }`}
                      >
                        <td className="py-3 px-3 text-[10px] text-slate-500 whitespace-nowrap">
                          {new Date(log.timestamp).toLocaleDateString()}
                        </td>
                        <td className="py-3 px-3">
                          <span className="px-1.5 py-0.5 border border-slate-800 bg-slate-900 rounded text-slate-400 font-bold text-[9px] uppercase">
                            {log.scan_type}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-slate-300 truncate max-w-[200px] select-all">
                          {log.input_value}
                        </td>
                        <td className="py-3 px-3 text-right">
                          <span className={`px-2 py-0.5 border rounded text-[9px] font-bold uppercase ${getSeverityBadge(severity)}`}>
                            {severity}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>

          {/* Details Drawer */}
          <div className="lg:col-span-1">
            {selectedLog ? (
              <div className="cyber-card cyber-card-corners p-5 space-y-5 flex flex-col justify-between h-full font-mono text-xs">
                <div>
                  <div className="border-b border-slate-800 pb-2 flex justify-between items-center mb-4">
                    <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">Evidence File Details</span>
                    <button onClick={() => setSelectedLog(null)} className="text-slate-500 hover:text-slate-300">
                      <X size={14} />
                    </button>
                  </div>

                  <div className="space-y-3">
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block mb-1">Incident Timestamp</span>
                      <span className="text-slate-300">{new Date(selectedLog.timestamp).toLocaleString()}</span>
                    </div>

                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block mb-1">Logged Input Details</span>
                      <span className="text-slate-200 bg-slate-950 p-2 rounded border border-slate-900 block break-all text-[11px] select-all">
                        {selectedLog.input_value}
                      </span>
                    </div>

                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block mb-1">Aggregated Core Metrics</span>
                      <div className="p-2 bg-slate-950 border border-slate-900 rounded space-y-1.5 text-[10px]">
                        <div><span className="text-slate-500">Scan Operation:</span> {selectedLog.scan_type}</div>
                        <div>
                          <span className="text-slate-500">Threat Verdict:</span> 
                          <span className={`ml-1 font-bold ${getSeverityBadge(selectedLog.result?.status || selectedLog.result?.risk_level)}`}>
                            {selectedLog.result?.status || selectedLog.result?.risk_level || "Safe"}
                          </span>
                        </div>
                        {selectedLog.result?.threat_score !== undefined && (
                          <div><span className="text-slate-500">Threat Index:</span> {selectedLog.result.threat_score}/100</div>
                        )}
                        {selectedLog.result?.spoof_score !== undefined && (
                          <div><span className="text-slate-500">Spoof Index:</span> {selectedLog.result.spoof_score}/100</div>
                        )}
                        <div><span className="text-slate-500">Analysis Engine:</span> {selectedLog.result?.mode || "Local Core"}</div>
                      </div>
                    </div>

                    {/* Analyst Notes Editor */}
                    <div className="space-y-2 pt-2">
                      <label className="text-[10px] text-slate-500 uppercase block font-bold">Investigator Notes</label>
                      <textarea
                        rows={4}
                        placeholder="Append cybercrime analyst comments, evidence logs index numbers, or investigation tracking IDs..."
                        value={noteText}
                        onChange={(e) => setNoteText(e.target.value)}
                        className="w-full p-2 bg-slate-950 border border-slate-900 rounded text-slate-300 focus:outline-none focus:border-cyan-500 text-[11px] resize-none"
                      />
                      <button
                        onClick={handleSaveNotes}
                        disabled={savingNote}
                        className="w-full py-2 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-400 font-bold rounded flex items-center justify-center space-x-1.5 transition text-[11px] uppercase"
                      >
                        <Save size={12} />
                        <span>{savingNote ? "Saving..." : "Save Analyst Notes"}</span>
                      </button>
                    </div>
                  </div>
                </div>

                <div className="border-t border-slate-900 pt-3 flex justify-between">
                  <button
                    onClick={() => handleDeleteLog(selectedLog.id)}
                    className="text-red-500 hover:text-red-400 font-bold flex items-center space-x-1 transition text-[10px] uppercase"
                  >
                    <Trash2 size={12} />
                    <span>Purge File</span>
                  </button>
                  <span className="text-slate-600 text-[9px] self-center">DB_ID: #{selectedLog.id}</span>
                </div>
              </div>
            ) : (
              <div className="cyber-card cyber-card-corners p-8 text-center text-slate-500 italic flex flex-col items-center justify-center h-48">
                <FileText className="mb-2 text-slate-600" size={24} />
                <span>Select a threat record row to inspect details and append investigator notes.</span>
              </div>
            )}
          </div>

        </div>
      )}

    </div>
  );
}
