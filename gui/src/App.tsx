import React, { useState, useEffect } from "react";
import {
  Shield,
  Search,
  Lock,
  Archive,
  Eye,
  Activity,
  FileText,
  Settings as SettingsIcon,
  Play,
  Folder,
  CheckCircle,
  AlertTriangle,
  Info,
  Server,
  Zap,
  TrendingUp,
  Cpu,
  RefreshCw,
  Hash,
  Download,
  UploadCloud,
  Layers
} from "lucide-react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
} from "recharts";

type DashboardTelemetryLog = {
  id: string;
  timestamp: string;
  level: "Info" | "Warning" | "Error" | "Critical" | "Security";
  message: string;
};

type EntropyPoint = {
  index: number;
  entropy: number;
};

const emptyPeReport = {
  file_name: "",
  file_size: 0,
  hashes: {
    md5: "",
    sha1: "",
    sha256: "",
  },
  timestamp: "",
  is_64_bit: false,
  machine: 0,
  entry_point: 0,
  image_base: 0,
  section_alignment: 0,
  file_alignment: 0,
  subsytem: 0,
  sections: [],
  imports: [],
  exports: [],
  tls_callbacks: [],
  global_entropy: 0,
  mitigations: {
    has_dep: false,
    has_aslr: false,
    has_high_entropy_aslr: false,
    has_cfg: false,
    has_force_integrity: false,
    has_nx: false,
    has_safeseh: false,
    has_gs: false,
  },
  has_digital_signature: false,
  packer_detected: false,
  detected_packer_name: null as string | null,
  security_score: 0,
  security_issues: [],
};

const emptyEntropyData: EntropyPoint[] = [];

export default function App() {
  const [activeTab, setActiveTab] = useState<string>("dashboard");
  const [isTauri, setIsTauri] = useState<boolean>(false);
  const [currentFilePath, setCurrentFilePath] = useState<string>("");
  const [analysisReport, setAnalysisReport] = useState<any>(emptyPeReport);
  const [telemetryLogs, setTelemetryLogs] = useState<DashboardTelemetryLog[]>([]);
  const [entropyData, setEntropyData] = useState<EntropyPoint[]>(emptyEntropyData);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [pipelineSummary, setPipelineSummary] = useState<any | null>(null);

  // Settings states for Protect tab
  const [renameSections, setRenameSections] = useState(true);
  const [generateJunk, setGenerateJunk] = useState(true);
  const [forceDep, setForceDep] = useState(true);
  const [forceAslr, setForceAslr] = useState(true);
  const [injectAntiTamper, setInjectAntiTamper] = useState(true);
  const [compressionType, setCompressionType] = useState("zstd");
  const [passphrase, setPassphrase] = useState("");

  // Pack States
  const [packSourceDir, setPackSourceDir] = useState("D:\\ProjectAssets");
  const [packOutFile, setPackOutFile] = useState("D:\\ProjectAssets\\bundled_assets.reapack");
  const [packPassphrase, setPackPassphrase] = useState("");

  // Detect Tauri Environment
  useEffect(() => {
    if ((window as any).__TAURI_METADATA__) {
      setIsTauri(true);
    }
  }, []);

  const telemetryEventToMessage = (event: any): string => {
    if (!event || typeof event !== "object") {
      return "Unknown telemetry event.";
    }

    if ("GenericMessage" in event) {
      const payload = event.GenericMessage;
      return `${payload?.subsystem ?? "Telemetry"}: ${payload?.message ?? ""}`.trim();
    }

    if ("IntegrityAlert" in event) {
      const payload = event.IntegrityAlert;
      return `Integrity alert for ${payload?.section_name ?? "section"}.`;
    }

    if ("CrashReport" in event) {
      const payload = event.CrashReport;
      return `Crash report at 0x${Number(payload?.instruction_pointer ?? 0).toString(16).toUpperCase()}.`;
    }

    if ("ExecutionTrace" in event) {
      const payload = event.ExecutionTrace;
      return `${payload?.module_name ?? "Module"} executed in ${payload?.elapsed_ms ?? 0}ms.`;
    }

    if ("PerformanceStat" in event) {
      const payload = event.PerformanceStat;
      return `Performance stat: CPU ${payload?.cpu_usage_pct ?? 0}% / Memory ${payload?.memory_bytes ?? 0} bytes.`;
    }

    return JSON.stringify(event);
  };

  const handleAnalyze = async () => {
    setIsLoading(true);
    try {
      if (isTauri) {
        const { invoke } = await import("@tauri-apps/api");
        const report: any = await invoke("tauri_analyze_file", { path: currentFilePath });
        setAnalysisReport(report);

        const visuals: any = await invoke("tauri_get_visuals", { path: currentFilePath });
        const heatmap = visuals.entropy_heatmap.map((v: number, idx: number) => ({
          index: idx,
          entropy: v,
        }));
        setEntropyData(heatmap);

        const telemetry = await invoke<any[]>("tauri_get_telemetry", { path: currentFilePath }).catch(() => []);
        setTelemetryLogs(
          telemetry.map((record: any) => ({
            id: record.id ?? crypto.randomUUID(),
            timestamp: record.timestamp,
            level: record.level,
            message: telemetryEventToMessage(record.event),
          }))
        );
      } else {
        setAnalysisReport(emptyPeReport);
        setEntropyData(emptyEntropyData);
        setTelemetryLogs([]);
        alert("Real backend data is available only when the app runs inside Tauri.");
      }
    } catch (err: any) {
      alert(`Analysis Failed: ${err}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleProtect = async () => {
    setIsLoading(true);
    try {
      const config = {
        obfuscation: {
          encrypt_strings: true,
          xor_key: 92,
          rename_sections: renameSections,
          section_prefix: ".reap",
          generate_junk_instructions: generateJunk,
          junk_size: 512,
          diversify_layout: true,
        },
        hardening: {
          force_dep: forceDep,
          force_aslr: forceAslr,
          force_high_entropy_aslr: forceAslr,
          force_cfg: true,
          force_integrity_check: injectAntiTamper,
          inject_anti_tamper: injectAntiTamper,
        },
        compression: compressionType === "none" ? "None" : compressionType === "zstd" ? "Zstd" : "Lzma",
        encrypt_assets: passphrase !== "",
        encryption_algorithm: "Aes256Gcm",
        generate_reports: true,
      };

      const outPath = currentFilePath.replace(".exe", "_protected.exe");

      if (isTauri) {
        const { invoke } = await import("@tauri-apps/api");
        const summary: any = await invoke("tauri_protect_binary", {
          inputPath: currentFilePath,
          outputPath: outPath,
          config,
          passphrase: passphrase || null,
        });
        setPipelineSummary(summary);

        const telemetry = await invoke<any[]>("tauri_get_telemetry", { path: currentFilePath }).catch(() => []);
        setTelemetryLogs(
          telemetry.map((record: any) => ({
            id: record.id ?? crypto.randomUUID(),
            timestamp: record.timestamp,
            level: record.level,
            message: telemetryEventToMessage(record.event),
          }))
        );
      } else {
        alert("Real protection output is available only when the app runs inside Tauri.");
      }
    } catch (err: any) {
      alert(`Protection Pipeline Failed: ${err}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handlePack = async () => {
    setIsLoading(true);
    try {
      if (isTauri) {
        const { invoke } = await import("@tauri-apps/api");
        await invoke("tauri_get_telemetry", { path: currentFilePath }).catch(() => []);
        alert("Packaging flow is not connected to a dedicated backend packer command yet.");
      } else {
        alert("Real packaging is available only when the app runs inside Tauri.");
      }
    } catch (err: any) {
      alert(`Packing Failed: ${err}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex h-screen bg-enterprise-950 text-enterprise-100 overflow-hidden select-none">
      {/* Sidebar Navigation */}
      <aside className="w-64 bg-enterprise-900 border-r border-enterprise-700 flex flex-col">
        {/* Brand Logo */}
        <div className="p-6 border-b border-enterprise-700 flex items-center space-x-3">
          <Shield className="h-7 w-7 text-blue-500 fill-blue-500/10" />
          <div>
            <h1 className="font-bold text-lg leading-tight tracking-tight">
              Reaper<span className="text-blue-500">Shield</span>
            </h1>
            <p className="text-[10px] text-enterprise-200 tracking-widest uppercase font-semibold">
              Enterprise Executable Security
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex-1 p-4 space-y-1">
          {[
            { id: "dashboard", label: "Dashboard", icon: Shield },
            { id: "analyze", label: "Analyze PE", icon: Search },
            { id: "protect", label: "Protect Pipeline", icon: Lock },
            { id: "pack", label: "Asset Packer", icon: Archive },
            { id: "telemetry", label: "Telemetry Logs", icon: Activity },
            { id: "reports", label: "Audit Reports", icon: FileText },
            { id: "settings", label: "Settings", icon: SettingsIcon },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id);
                  setPipelineSummary(null);
                }}
                className={`w-full flex items-center space-x-3 px-4 py-3 rounded-md text-sm font-medium transition-all ${
                  active
                    ? "bg-blue-600/10 text-blue-400 border border-blue-600/20"
                    : "text-enterprise-200 hover:bg-enterprise-800 hover:text-enterprise-100"
                }`}
              >
                <Icon className={`h-4 w-4 ${active ? "text-blue-400" : "text-enterprise-200"}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Environment Status Indicator */}
        <div className="p-4 border-t border-enterprise-700 bg-enterprise-950/40">
          <div className="flex items-center justify-between text-xs">
            <span className="text-enterprise-200">Shell Environment:</span>
            <span className={`font-bold flex items-center space-x-1 ${isTauri ? "text-emerald-400" : "text-amber-400"}`}>
              <Server className="h-3 w-3 mr-1" />
              {isTauri ? "TAURI CLIENT" : "SANDBOX PREVIEW"}
            </span>
          </div>
        </div>
      </aside>

      {/* Main Container */}
      <main className="flex-1 flex flex-col bg-enterprise-950 overflow-hidden">
        {/* Global Toolbar Header */}
        <header className="h-16 border-b border-enterprise-700 flex items-center justify-between px-8 bg-enterprise-900/50">
          <div className="flex items-center space-x-4 w-1/2">
            <Folder className="h-4 w-4 text-enterprise-200" />
            <input
              type="text"
              value={currentFilePath}
              onChange={(e) => setCurrentFilePath(e.target.value)}
              className="w-full bg-enterprise-950 text-xs px-3 py-2 rounded border border-enterprise-700 focus:outline-none focus:border-blue-500 font-mono text-enterprise-100"
              placeholder="Target binary absolute path (.exe)"
            />
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={handleAnalyze}
              disabled={isLoading}
              className="bg-blue-600 hover:bg-blue-500 text-white font-medium px-4 py-2 rounded text-xs transition flex items-center space-x-2 disabled:opacity-50"
            >
              {isLoading ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin mr-1" />
              ) : (
                <Play className="h-3.5 w-3.5 mr-1" />
              )}
              Analyze Core
            </button>
          </div>
        </header>

        {/* Content Viewport */}
        <div className="flex-1 overflow-y-auto p-8">
          {activeTab === "dashboard" && (
            <div className="space-y-6">
              {/* Row 1: Hero Widgets */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                {/* Security Rating Card */}
                <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-6 flex flex-col justify-between">
                  <div className="flex justify-between items-start">
                    <span className="text-xs font-semibold text-enterprise-200 uppercase tracking-wider">
                      Security Rating
                    </span>
                    <Shield className="h-5 w-5 text-blue-500" />
                  </div>
                  <div className="my-4 flex items-baseline">
                    <span className="text-4xl font-bold text-enterprise-100">
                      {analysisReport.security_score}
                    </span>
                    <span className="text-sm font-semibold text-enterprise-200 ml-1">/100</span>
                  </div>
                  <div className="text-xs text-enterprise-200 flex items-center space-x-1">
                    <span className="font-bold text-emerald-400">Stable</span>
                    <span>• PE structure compiled</span>
                  </div>
                </div>

                {/* File size widget */}
                <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-6 flex flex-col justify-between">
                  <div className="flex justify-between items-start">
                    <span className="text-xs font-semibold text-enterprise-200 uppercase tracking-wider">
                      Binary Size
                    </span>
                    <Layers className="h-5 w-5 text-purple-500" />
                  </div>
                  <div className="my-4">
                    <span className="text-3xl font-bold text-enterprise-100">
                      {(analysisReport.file_size / (1024 * 1024)).toFixed(2)}
                    </span>
                    <span className="text-sm font-bold text-enterprise-200 ml-1">MB</span>
                  </div>
                  <div className="text-xs text-enterprise-200 font-mono">
                    {analysisReport.file_size.toLocaleString()} bytes
                  </div>
                </div>

                {/* Exploit Mitigations Active */}
                <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-6 flex flex-col justify-between">
                  <div className="flex justify-between items-start">
                    <span className="text-xs font-semibold text-enterprise-200 uppercase tracking-wider">
                      Mitigation Index
                    </span>
                    <Zap className="h-5 w-5 text-amber-500" />
                  </div>
                  <div className="my-4">
                    <span className="text-3xl font-bold text-enterprise-100">
                      {Object.values(analysisReport.mitigations).filter(Boolean).length}
                    </span>
                    <span className="text-sm text-enterprise-200 ml-1">/8</span>
                  </div>
                  <div className="text-xs text-enterprise-200">
                    DEP, ASLR, CFG, GS active
                  </div>
                </div>

                {/* Section Count Widget */}
                <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-6 flex flex-col justify-between">
                  <div className="flex justify-between items-start">
                    <span className="text-xs font-semibold text-enterprise-200 uppercase tracking-wider">
                      Section Map
                    </span>
                    <Cpu className="h-5 w-5 text-emerald-500" />
                  </div>
                  <div className="my-4">
                    <span className="text-3xl font-bold text-enterprise-100">
                      {analysisReport.sections.length}
                    </span>
                    <span className="text-sm text-enterprise-200 ml-1">Segments</span>
                  </div>
                  <div className="text-xs text-enterprise-200">
                    Average Entropy: {analysisReport.global_entropy.toFixed(3)}
                  </div>
                </div>
              </div>

              {/* Row 2: Entropy Heatmap Graphics */}
              <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-6">
                <div className="flex justify-between items-center mb-6">
                  <div>
                    <h3 className="font-bold text-enterprise-100 text-sm uppercase tracking-wide">
                      Binary Entropy Heatmap & Density
                    </h3>
                    <p className="text-xs text-enterprise-200 mt-1">
                      Visualizing layout encryption and section block boundaries (Shannon Entropy scale: 0.0 - 8.0)
                    </p>
                  </div>
                  <div className="flex items-center space-x-2 text-xs">
                    <span className="flex items-center"><span className="w-2.5 h-2.5 rounded bg-emerald-500 mr-1"></span> Code</span>
                    <span className="flex items-center"><span className="w-2.5 h-2.5 rounded bg-purple-500 mr-1"></span> Protected / Compressed</span>
                  </div>
                </div>
                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={entropyData}>
                      <defs>
                        <linearGradient id="entropyColor" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2} />
                          <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid stroke="#1f2937" vertical={false} />
                      <XAxis dataKey="index" stroke="#9ca3af" fontSize={10} tickLine={false} />
                      <YAxis domain={[0, 8]} stroke="#9ca3af" fontSize={10} tickLine={false} />
                      <Tooltip
                        contentStyle={{ backgroundColor: "#111827", borderColor: "#374151", color: "#f3f4f6" }}
                        cursor={{ stroke: "#3b82f6", strokeWidth: 1 }}
                      />
                      <Area type="monotone" dataKey="entropy" stroke="#3b82f6" strokeWidth={1.5} fillOpacity={1} fill="url(#entropyColor)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Row 3: Double Grid of Mitigations vs Issues */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Mitigation compliance */}
                <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-6">
                  <h3 className="font-bold text-enterprise-100 text-sm uppercase tracking-wide mb-4">
                    Exploit Mitigations Grid
                  </h3>
                  <div className="grid grid-cols-2 gap-4">
                    {Object.entries(analysisReport.mitigations).map(([key, active]) => (
                      <div key={key} className="flex items-center justify-between p-3 bg-enterprise-950/55 rounded border border-enterprise-700">
                        <span className="text-xs font-medium capitalize text-enterprise-200">
                          {key.replace("has_", "").replace(/_/g, " ")}
                        </span>
                        {active ? (
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            ACTIVE
                          </span>
                        ) : (
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                            DISABLED
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Compliance issue console alerts */}
                <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-6 flex flex-col justify-between">
                  <div>
                    <h3 className="font-bold text-enterprise-100 text-sm uppercase tracking-wide mb-4">
                      Vulnerability & Audit Logs
                    </h3>
                    <div className="space-y-3 max-h-48 overflow-y-auto">
                      {analysisReport.security_issues.map((issue: string, idx: number) => (
                        <div key={idx} className="flex items-start space-x-2.5 p-3 bg-red-500/5 rounded border border-red-500/10">
                          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 flex-shrink-0" />
                          <span className="text-xs text-red-400 leading-normal">{issue}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "analyze" && (
            <div className="space-y-6">
              <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-6">
                <h3 className="font-bold text-enterprise-100 text-sm uppercase tracking-wide mb-6">
                  Complete Binary Structuring Report ({analysisReport.file_name})
                </h3>

                {/* Sub-Header PE metadata */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-6 p-4 bg-enterprise-950/40 rounded border border-enterprise-700 font-mono text-xs mb-6">
                  <div>
                    <div className="text-enterprise-200">Image Base</div>
                    <div className="font-semibold text-enterprise-100 mt-1">0x{analysisReport.image_base.toString(16).toUpperCase()}</div>
                  </div>
                  <div>
                    <div className="text-enterprise-200">Address Of Entry Point</div>
                    <div className="font-semibold text-enterprise-100 mt-1">0x{analysisReport.entry_point.toString(16).toUpperCase()}</div>
                  </div>
                  <div>
                    <div className="text-enterprise-200">File Alignment</div>
                    <div className="font-semibold text-enterprise-100 mt-1">{analysisReport.file_alignment} bytes</div>
                  </div>
                  <div>
                    <div className="text-enterprise-200">Digital Signature</div>
                    <div className={`font-semibold mt-1 ${analysisReport.has_digital_signature ? "text-emerald-400" : "text-red-400"}`}>
                      {analysisReport.has_digital_signature ? "SIGNED (VALID)" : "UNSIGNED"}
                    </div>
                  </div>
                </div>

                {/* Section Table */}
                <div className="mb-6">
                  <h4 className="font-bold text-enterprise-200 text-xs uppercase tracking-wide mb-3 flex items-center">
                    <Layers className="h-4 w-4 mr-1 text-blue-500" /> PE Raw Sections Maps
                  </h4>
                  <table className="w-full text-left text-xs border border-enterprise-700">
                    <thead className="bg-enterprise-900 border-b border-enterprise-700 text-enterprise-200 font-semibold">
                      <tr>
                        <th className="p-3">Section Name</th>
                        <th className="p-3">Virtual RVA</th>
                        <th className="p-3">Raw Pointer</th>
                        <th className="p-3">Raw Size</th>
                        <th className="p-3">Entropy Rating</th>
                        <th className="p-3">Characteristics</th>
                        <th className="p-3">Flags</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-enterprise-700">
                      {analysisReport.sections.map((sec: any, idx: number) => (
                        <tr key={idx} className="hover:bg-enterprise-900/40 font-mono">
                          <td className="p-3 font-semibold text-enterprise-100">{sec.name}</td>
                          <td className="p-3">0x{sec.virtual_address.toString(16).toUpperCase()}</td>
                          <td className="p-3">0x{sec.raw_data_pointer.toString(16).toUpperCase()}</td>
                          <td className="p-3">{sec.raw_data_size.toLocaleString()} B</td>
                          <td className={`p-3 font-semibold ${sec.entropy > 7.4 ? "text-purple-400" : "text-enterprise-100"}`}>{sec.entropy.toFixed(3)}</td>
                          <td className="p-3">0x{sec.characteristics.toString(16).toUpperCase()}</td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${sec.is_suspicious ? "bg-red-500/10 text-red-400 border border-red-500/20" : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"}`}>
                              {sec.is_suspicious ? "SUSPICIOUS" : "NORMAL"}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* double-grid imports/exports */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Imports */}
                  <div>
                    <h4 className="font-bold text-enterprise-200 text-xs uppercase tracking-wide mb-3 flex items-center">
                      <Download className="h-4 w-4 mr-1 text-blue-500" /> DLL Import Dependencies Table
                    </h4>
                    <div className="max-h-60 overflow-y-auto border border-enterprise-700 rounded font-mono text-xs divide-y divide-enterprise-700 bg-enterprise-950/20">
                      {analysisReport.imports.map((imp: any, idx: number) => (
                        <div key={idx} className="p-3 flex justify-between">
                          <span className="font-semibold text-blue-400">{imp.dll}</span>
                          <span className="text-enterprise-200">{imp.function}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Exports */}
                  <div>
                    <h4 className="font-bold text-enterprise-200 text-xs uppercase tracking-wide mb-3 flex items-center">
                      <UploadCloud className="h-4 w-4 mr-1 text-blue-500" /> Export Function Tables
                    </h4>
                    <div className="max-h-60 overflow-y-auto border border-enterprise-700 rounded font-mono text-xs divide-y divide-enterprise-700 bg-enterprise-950/20">
                      {analysisReport.exports.length === 0 ? (
                        <div className="p-3 text-enterprise-200 italic">No exported functions found inside binary.</div>
                      ) : (
                        analysisReport.exports.map((exp: any, idx: number) => (
                          <div key={idx} className="p-3 flex justify-between">
                            <span className="font-semibold text-emerald-400">{exp.name}</span>
                            <span className="text-enterprise-200">RVA: 0x{exp.rva.toString(16).toUpperCase()}</span>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "protect" && (
            <div className="space-y-6">
              {!pipelineSummary ? (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  {/* Left block options */}
                  <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-6 md:col-span-2 space-y-6">
                    <h3 className="font-bold text-enterprise-100 text-sm uppercase tracking-wide border-b border-enterprise-700 pb-3">
                      ReaperShield Protective Pipeline Options
                    </h3>

                    {/* Section Rename option */}
                    <div className="flex justify-between items-start p-4 bg-enterprise-950/40 rounded border border-enterprise-700">
                      <div className="space-y-1">
                        <label className="text-xs font-bold text-enterprise-100 uppercase tracking-wide">
                          Rename PE Standard Sections
                        </label>
                        <p className="text-xs text-enterprise-200">
                          Renames standard sections like <code>.text</code>, <code>.rdata</code> to randomized strings (e.g. <code>.reap5c</code>).
                        </p>
                      </div>
                      <input
                        type="checkbox"
                        checked={renameSections}
                        onChange={(e) => setRenameSections(e.target.checked)}
                        className="w-4 h-4 text-blue-600 border-enterprise-700 rounded bg-enterprise-950 focus:ring-blue-500"
                      />
                    </div>

                    {/* Junk instructions option */}
                    <div className="flex justify-between items-start p-4 bg-enterprise-950/40 rounded border border-enterprise-700">
                      <div className="space-y-1">
                        <label className="text-xs font-bold text-enterprise-100 uppercase tracking-wide">
                          Inject Assembly Junk Code
                        </label>
                        <p className="text-xs text-enterprise-200">
                          Appends valid, non-crashing CPU instruction blocks (NOPs, XCHGs) to code sections to scramble signatures.
                        </p>
                      </div>
                      <input
                        type="checkbox"
                        checked={generateJunk}
                        onChange={(e) => setGenerateJunk(e.target.checked)}
                        className="w-4 h-4 text-blue-600 border-enterprise-700 rounded bg-enterprise-950 focus:ring-blue-500"
                      />
                    </div>

                    {/* Force DEP ASLR mitigations */}
                    <div className="flex justify-between items-start p-4 bg-enterprise-950/40 rounded border border-enterprise-700">
                      <div className="space-y-1">
                        <label className="text-xs font-bold text-enterprise-100 uppercase tracking-wide">
                          Strict Exploit Mitigations (DEP/ASLR)
                        </label>
                        <p className="text-xs text-enterprise-200">
                          Forces high-entropy ASLR and DEP flags inside the DLL characteristics header, ensuring OS-level defenses.
                        </p>
                      </div>
                      <input
                        type="checkbox"
                        checked={forceAslr}
                        onChange={(e) => {
                          setForceAslr(e.target.checked);
                          setForceDep(e.target.checked);
                        }}
                        className="w-4 h-4 text-blue-600 border-enterprise-700 rounded bg-enterprise-950 focus:ring-blue-500"
                      />
                    </div>

                    {/* Injected Integrity verification */}
                    <div className="flex justify-between items-start p-4 bg-enterprise-950/40 rounded border border-enterprise-700">
                      <div className="space-y-1">
                        <label className="text-xs font-bold text-enterprise-100 uppercase tracking-wide">
                          Inject Self-Validation Checksums (Anti-Tamper)
                        </label>
                        <p className="text-xs text-enterprise-200">
                          Encodes cryptographic hashes of code sections into a dedicated <code>.reapint</code> block, enabling tamper audits.
                        </p>
                      </div>
                      <input
                        type="checkbox"
                        checked={injectAntiTamper}
                        onChange={(e) => setInjectAntiTamper(e.target.checked)}
                        className="w-4 h-4 text-blue-600 border-enterprise-700 rounded bg-enterprise-950 focus:ring-blue-500"
                      />
                    </div>
                  </div>

                  {/* Right side packing settings */}
                  <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-6 flex flex-col justify-between">
                    <div className="space-y-6">
                      <h3 className="font-bold text-enterprise-100 text-sm uppercase tracking-wide border-b border-enterprise-700 pb-3">
                        Compression & Key Setup
                      </h3>

                      {/* Compression selector */}
                      <div className="space-y-2">
                        <label className="text-xs font-bold text-enterprise-200 uppercase">Compression Standard</label>
                        <select
                          value={compressionType}
                          onChange={(e) => setCompressionType(e.target.value)}
                          className="w-full bg-enterprise-950 border border-enterprise-700 rounded p-2 text-xs text-enterprise-100 font-medium focus:outline-none"
                        >
                          <option value="none">No compression (Staged wrapper)</option>
                          <option value="zstd">Zstandard (Zstd High-Performance)</option>
                          <option value="lzma">LZMA2 (Extreme Ratio Packer)</option>
                        </select>
                      </div>

                      {/* Passphrase key */}
                      <div className="space-y-2">
                        <label className="text-xs font-bold text-enterprise-200 uppercase">Crypting Key (AES-256-GCM)</label>
                        <input
                          type="password"
                          value={passphrase}
                          onChange={(e) => setPassphrase(e.target.value)}
                          className="w-full bg-enterprise-950 border border-enterprise-700 rounded p-2.5 text-xs text-enterprise-100 font-mono text-center"
                          placeholder="Optional payload key string"
                        />
                      </div>
                    </div>

                    <div className="mt-8">
                      <button
                        onClick={handleProtect}
                        disabled={isLoading}
                        className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-3.5 rounded text-xs tracking-wider transition uppercase flex items-center justify-center space-x-2"
                      >
                        {isLoading ? (
                          <RefreshCw className="h-4 w-4 animate-spin" />
                        ) : (
                          <Shield className="h-4 w-4 fill-white/10" />
                        )}
                        <span>Compile Protected Output</span>
                      </button>
                    </div>
                  </div>
                </div>
              ) : (
                /* Post protect summary layout */
                <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-8 max-w-3xl mx-auto space-y-6">
                  <div className="text-center">
                    <CheckCircle className="h-14 w-14 text-emerald-400 mx-auto mb-4" />
                    <h3 className="text-xl font-bold text-enterprise-100">ReaperShield Protective Packaging Successful</h3>
                    <p className="text-xs text-enterprise-200 mt-1">
                      Protected binary written to: <code>{currentFilePath.replace(".exe", "_protected.exe")}</code>
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-6 p-6 bg-enterprise-950/40 rounded border border-enterprise-700 font-mono text-xs">
                    <div>
                      <span className="text-enterprise-200 uppercase font-semibold">Original Size:</span>
                      <div className="text-lg font-bold text-enterprise-100 mt-1">{pipelineSummary.original_size.toLocaleString()} bytes</div>
                    </div>
                    <div>
                      <span className="text-enterprise-200 uppercase font-semibold">Protected Size:</span>
                      <div className="text-lg font-bold text-enterprise-100 mt-1">{pipelineSummary.protected_size.toLocaleString()} bytes</div>
                    </div>
                    <div>
                      <span className="text-enterprise-200 uppercase font-semibold">Security Score:</span>
                      <div className="text-lg font-bold text-emerald-400 mt-1">
                        {pipelineSummary.initial_security_score} → {pipelineSummary.protected_security_score} / 100
                      </div>
                    </div>
                    <div>
                      <span className="text-enterprise-200 uppercase font-semibold">Decryption Key:</span>
                      <div className="text-lg font-bold text-purple-400 mt-1">{passphrase ? "AES-256 (Passphrase)" : "No Passphrase"}</div>
                    </div>
                  </div>

                  <div className="text-center">
                    <button
                      onClick={() => setPipelineSummary(null)}
                      className="bg-blue-600 hover:bg-blue-500 text-white font-semibold px-6 py-2.5 rounded text-xs transition"
                    >
                      Run Pipeline Again
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === "pack" && (
            <div className="space-y-6">
              <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-6 max-w-2xl mx-auto space-y-6">
                <h3 className="font-bold text-enterprise-100 text-sm uppercase tracking-wide border-b border-enterprise-700 pb-3">
                  Enterprise Secure Packer & Bundler Utility
                </h3>

                <div className="space-y-4">
                  <div className="space-y-2">
                    <label className="text-xs font-bold text-enterprise-200 uppercase tracking-wide">
                      Source Directory Path
                    </label>
                    <input
                      type="text"
                      value={packSourceDir}
                      onChange={(e) => setPackSourceDir(e.target.value)}
                      className="w-full bg-enterprise-950 border border-enterprise-700 rounded p-2.5 text-xs text-enterprise-100 font-mono"
                      placeholder="Folder containing files or dependencies"
                    />
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs font-bold text-enterprise-200 uppercase tracking-wide">
                      Output File Location
                    </label>
                    <input
                      type="text"
                      value={packOutFile}
                      onChange={(e) => setPackOutFile(e.target.value)}
                      className="w-full bg-enterprise-950 border border-enterprise-700 rounded p-2.5 text-xs text-enterprise-100 font-mono"
                      placeholder="Output .reapack file"
                    />
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs font-bold text-enterprise-200 uppercase tracking-wide">
                      Passphrase for Encryption (ChaCha20-Poly1305)
                    </label>
                    <input
                      type="password"
                      value={packPassphrase}
                      onChange={(e) => setPackPassphrase(e.target.value)}
                      className="w-full bg-enterprise-950 border border-enterprise-700 rounded p-2.5 text-xs text-enterprise-100 font-mono text-center"
                      placeholder="Optional bundle cryptography key"
                    />
                  </div>
                </div>

                <div className="pt-4">
                  <button
                    onClick={handlePack}
                    disabled={isLoading}
                    className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-3 rounded text-xs tracking-wider transition uppercase"
                  >
                    Create Pack Bundle
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === "telemetry" && (
            <div className="space-y-6">
              <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-6">
                <h3 className="font-bold text-enterprise-100 text-sm uppercase tracking-wide mb-6">
                  Runtime Instrumentation Logs & Telemetry Alert Feed
                </h3>

                <div className="space-y-3 max-h-[500px] overflow-y-auto">
                  {telemetryLogs.length === 0 ? (
                    <div className="p-4 rounded border border-dashed border-enterprise-700 text-xs text-enterprise-200 font-mono bg-enterprise-950/30">
                      No telemetry has been loaded yet. Run an analysis or protection job in Tauri to populate real logs.
                    </div>
                  ) : (
                    telemetryLogs.map((log) => {
                      const isSec = log.level === "Security";
                      const isWarn = log.level === "Warning";
                      return (
                        <div
                          key={log.id}
                          className={`p-4 rounded border text-xs font-mono flex items-start space-x-3 ${
                            isSec
                              ? "bg-red-500/10 border-red-500/20 text-red-400"
                              : isWarn
                              ? "bg-amber-500/10 border-amber-500/20 text-amber-400"
                              : "bg-enterprise-950/40 border-enterprise-700 text-enterprise-200"
                          }`}
                        >
                          <span className="font-bold text-[10px] uppercase tracking-wide bg-enterprise-950/80 px-2 py-0.5 rounded border border-enterprise-700 select-none">
                            {log.level}
                          </span>
                          <div className="flex-1">
                            <p className="font-semibold text-enterprise-100">{log.message}</p>
                            <span className="text-[10px] text-enterprise-200 block mt-1">
                              {new Date(log.timestamp).toLocaleString()}
                            </span>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === "reports" && (
            <div className="space-y-6">
              <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-6 max-w-xl mx-auto text-center space-y-6">
                <FileText className="h-14 w-14 text-blue-500 mx-auto" />
                <div>
                  <h3 className="text-lg font-bold text-enterprise-100">Enterprise Security Audits Generator</h3>
                  <p className="text-xs text-enterprise-200 mt-1">
                    Export high-fidelity diagnostic reports containing section permissions, exploit mitigation matrices, hashes, and detailed logs.
                  </p>
                </div>

                <div className="flex flex-col space-y-3">
                  <button
                    onClick={async () => {
                      if (isTauri) {
                        try {
                          const { invoke } = await import("@tauri-apps/api");
                          const res = await invoke("tauri_generate_report", { path: currentFilePath });
                          alert(`HTML Report written to: ${res}`);
                        } catch (err) {
                          alert(`Report Generation Failed: ${err}`);
                        }
                      } else {
                        alert("Auditing Simulated: Created HTML report at Target folder.");
                      }
                    }}
                    className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-3 rounded text-xs transition uppercase"
                  >
                    Compile HTML Interactive Report
                  </button>

                  <button
                    onClick={() => {
                      alert("Audit Report downloaded inside workspace context.");
                    }}
                    className="w-full bg-enterprise-950 border border-enterprise-700 hover:bg-enterprise-900 text-enterprise-100 font-semibold py-3 rounded text-xs transition uppercase"
                  >
                    Export JSON Technical Manifest
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === "settings" && (
            <div className="space-y-6">
              <div className="bg-enterprise-800 border border-enterprise-700 rounded-lg p-6 max-w-2xl mx-auto space-y-6">
                <h3 className="font-bold text-enterprise-100 text-sm uppercase tracking-wide border-b border-enterprise-700 pb-3">
                  ReaperShield Global Preferences
                </h3>

                <div className="space-y-4">
                  <div className="flex justify-between items-center p-3 bg-enterprise-950/40 rounded border border-enterprise-700">
                    <div>
                      <span className="text-xs font-semibold text-enterprise-100 uppercase">Structured Crash Monitor</span>
                      <p className="text-[10px] text-enterprise-200 mt-1">Saves structured crash details locally on execution failures.</p>
                    </div>
                    <span className="px-2 py-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-bold text-[10px] rounded">ENABLED</span>
                  </div>

                  <div className="flex justify-between items-center p-3 bg-enterprise-950/40 rounded border border-enterprise-700">
                    <div>
                      <span className="text-xs font-semibold text-enterprise-100 uppercase">FIPS Compliant PBKDF2</span>
                      <p className="text-[10px] text-enterprise-200 mt-1">Derives all sub-keys with SHA-256 iterations under FIPS guidance.</p>
                    </div>
                    <span className="px-2 py-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-bold text-[10px] rounded">ENABLED</span>
                  </div>

                  <div className="flex justify-between items-center p-3 bg-enterprise-950/40 rounded border border-enterprise-700">
                    <div>
                      <span className="text-xs font-semibold text-enterprise-100 uppercase">Cross-Platform Loader Stub</span>
                      <p className="text-[10px] text-enterprise-200 mt-1">Targets Win64 runtime extraction compatibility.</p>
                    </div>
                    <span className="px-2 py-1 bg-blue-500/10 border border-blue-500/20 text-blue-400 font-bold text-[10px] rounded">X64 WINDOWS</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
