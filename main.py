from contextlib import contextmanager
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import json

from application.dtos import AnalysisResultDTO, VulnerabilityDTO
from application.service.ingestion_service import IngestionService
from application.service.prioritization_service import PrioritizationService
from infrastructure.clients.osv_client import OSVVulnerabilityLookup
from infrastructure.clients.threat_intel import ThreatIntelClient
from infrastructure.graph.networkx_adapter import NetworkXGraphAnalyzer
from infrastructure.graph.repositories import SQLAlchemyRepository
from infrastructure.persistence.database import create_database_engine, create_session
from infrastructure.clients.registry_client import DepsDevClient

# Dependency Injection Setup
@contextmanager
def get_repository():
    """Context manager for repository with session"""
    engine = create_database_engine()
    session = create_session(engine)
    try:
        yield SQLAlchemyRepository(session)
    finally:
        session.close()


def create_app() -> FastAPI:
    """Factory function with dependency injection"""
    
    # Initialize database
    engine = create_database_engine()
    
    # Wire up adapters (OUTER HEXAGON)
    graph_analyzer = NetworkXGraphAnalyzer()
    threat_intel = ThreatIntelClient()
    vuln_lookup = OSVVulnerabilityLookup()
    metadata_provider = DepsDevClient()
    app = FastAPI(title="HDFM v4.0 SBOM Analyzer")
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    @app.get("/", response_class=HTMLResponse)
    async def root():
        """Serve web interface"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>HDFM v4.0 - SQLite + OSV.dev</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-white p-8">
    <div class="max-w-7xl mx-auto">
        <h1 class="text-3xl font-bold mb-2 bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
            HDFM v4.0 SBOM Analyzer
        </h1>
        <p class="text-slate-400 mb-8">SQLAlchemy + OSV.dev + Hexagonal Architecture</p>
        
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div class="bg-slate-800 rounded-lg p-6">
                <h2 class="text-xl font-bold mb-4">Upload New SBOM</h2>
                <input type="file" id="file" accept=".json" class="mb-4 text-sm">
                <div class="flex gap-2">
                    <button onclick="analyze()" class="bg-cyan-500 hover:bg-cyan-600 px-6 py-2 rounded">
                        Analyze
                    </button>
                    <button onclick="demo()" class="bg-blue-500 hover:bg-blue-600 px-6 py-2 rounded">
                        Try Demo
                    </button>
                </div>
            </div>
            
            <div class="bg-slate-800 rounded-lg p-6">
                <h2 class="text-xl font-bold mb-4">Stored SBOMs</h2>
                <button onclick="loadSBOMs()" class="bg-purple-500 hover:bg-purple-600 px-6 py-2 rounded">
                    View Stored SBOMs
                </button>
                <div id="sbom-list" class="mt-4 space-y-2"></div>
            </div>
        </div>
        
        <div id="results" class="hidden space-y-6">
            <div class="flex justify-between items-center">
                <h2 class="text-2xl font-bold">Analysis Results</h2>
                <button onclick="reanalyze()" class="bg-green-500 hover:bg-green-600 px-4 py-2 rounded text-sm">
                    Re-analyze (Update Priorities)
                </button>
            </div>
            
            <div class="grid grid-cols-5 gap-4">
                <div class="bg-slate-800 rounded p-4">
                    <div class="text-slate-400 text-sm">Components</div>
                    <div id="total-comp" class="text-2xl font-bold">0</div>
                </div>
                <div class="bg-slate-800 rounded p-4">
                    <div class="text-slate-400 text-sm">Vulnerabilities</div>
                    <div id="total-vuln" class="text-2xl font-bold">0</div>
                </div>
                <div class="bg-red-500/20 rounded p-4">
                    <div class="text-red-300 text-sm">Critical</div>
                    <div id="critical" class="text-2xl font-bold">0</div>
                </div>
                <div class="bg-slate-800 rounded p-4">
                    <div class="text-slate-400 text-sm">Hub Components</div>
                    <div id="hubs" class="text-2xl font-bold">0</div>
                </div>
                <div class="bg-slate-800 rounded p-4">
                    <div class="text-slate-400 text-sm">Max Depth</div>
                    <div id="depth" class="text-2xl font-bold">0</div>
                </div>
            </div>
            
            <div class="bg-slate-800 rounded-lg overflow-hidden">
                <div class="p-4 border-b border-slate-700">
                    <h3 class="text-xl font-bold">Prioritized Vulnerabilities</h3>
                    <p class="text-sm text-slate-400">Sorted by HDFM Score | Data from OSV.dev</p>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-slate-900">
                            <tr>
                                <th class="px-4 py-3 text-left text-xs font-semibold uppercase">CVE</th>
                                <th class="px-4 py-3 text-left text-xs font-semibold uppercase">Component</th>
                                <th class="px-4 py-3 text-left text-xs font-semibold uppercase">CVSS</th>
                                <th class="px-4 py-3 text-left text-xs font-semibold uppercase">HDFM Score</th>
                                <th class="px-4 py-3 text-left text-xs font-semibold uppercase">Priority</th>
                                <th class="px-4 py-3 text-left text-xs font-semibold uppercase">TCS</th>
                                <th class="px-4 py-3 text-left text-xs font-semibold uppercase">KEV</th>
                            </tr>
                        </thead>
                        <tbody id="vulns"></tbody>
                    </table>
                </div>
            </div>
            
            <div class="bg-slate-800 rounded-lg p-4">
                <h3 class="font-bold mb-2">Analysis History</h3>
                <button onclick="loadHistory()" class="bg-slate-700 hover:bg-slate-600 px-4 py-2 rounded text-sm">
                    View All Analyses
                </button>
                <div id="history" class="mt-4"></div>
            </div>
        </div>
    </div>
    
    <script>
        let currentSbomId = null;
        
        async function analyze() {
            const file = document.getElementById('file').files[0];
            if (!file) return alert('Select a file first');
            
            const formData = new FormData();
            formData.append('file', file);
            
            const res = await fetch('/api/analyze', { method: 'POST', body: formData });
            const data = await res.json();
            currentSbomId = data.sbom_id;
            displayResults(data);
        }
        
        async function demo() {
            const res = await fetch('/api/demo');
            const data = await res.json();
            currentSbomId = data.sbom_id;
            displayResults(data);
        }
        
        async function reanalyze() {
            if (!currentSbomId) return alert('No SBOM loaded');
            
            const res = await fetch(`/api/reanalyze/${currentSbomId}`, { method: 'POST' });
            const data = await res.json();
            displayResults(data);
            alert('Analysis updated with latest threat intelligence!');
        }
        
        async function loadSBOMs() {
            const res = await fetch('/api/sboms');
            const sboms = await res.json();
            
            const list = document.getElementById('sbom-list');
            list.innerHTML = sboms.map(s => `
                <div class="bg-slate-700 p-3 rounded cursor-pointer hover:bg-slate-600" onclick="loadSBOM('${s.id}')">
                    <div class="font-bold">${s.name} v${s.version}</div>
                    <div class="text-xs text-slate-400">${s.created_at}</div>
                </div>
            `).join('');
        }
        
        async function loadSBOM(sbomId) {
            const res = await fetch(`/api/sbom/${sbomId}/latest`);
            const data = await res.json();
            currentSbomId = sbomId;
            displayResults(data);
        }
        
        async function loadHistory() {
            if (!currentSbomId) return;
            
            const res = await fetch(`/api/sbom/${currentSbomId}/history`);
            const analyses = await res.json();
            
            const history = document.getElementById('history');
            history.innerHTML = analyses.map((a, i) => `
                <div class="bg-slate-700 p-3 rounded mb-2">
                    <div class="flex justify-between">
                        <span class="font-bold">Analysis #${analyses.length - i}</span>
                        <span class="text-sm text-slate-400">${a.timestamp}</span>
                    </div>
                    <div class="text-sm mt-1">
                        Critical: ${a.critical_findings} | Total: ${a.total_vulnerabilities}
                    </div>
                </div>
            `).join('');
        }
        
        function displayResults(data) {
            document.getElementById('results').classList.remove('hidden');
            document.getElementById('total-comp').textContent = data.total_components;
            document.getElementById('total-vuln').textContent = data.total_vulnerabilities;
            document.getElementById('critical').textContent = data.critical_findings;
            document.getElementById('hubs').textContent = data.hub_components;
            document.getElementById('depth').textContent = data.max_depth;
            
            const tbody = document.getElementById('vulns');
            tbody.innerHTML = data.vulnerabilities.map(v => `
                <tr class="hover:bg-slate-700/50 border-b border-slate-700">
                    <td class="px-4 py-3 font-mono text-cyan-400 text-sm">${v.id}</td>
                    <td class="px-4 py-3 text-sm">${v.component}</td>
                    <td class="px-4 py-3 text-sm">${v.cvss_score.toFixed(1)}</td>
                    <td class="px-4 py-3">
                        <div class="flex items-center gap-2">
                            <div class="w-20 h-2 bg-slate-700 rounded overflow-hidden">
                                <div class="h-full ${v.hdfm_score > 0.8 ? 'bg-red-500' : v.hdfm_score > 0.5 ? 'bg-orange-500' : 'bg-yellow-500'}" 
                                     style="width: ${v.hdfm_score * 100}%"></div>
                            </div>
                            <span class="text-sm font-bold">${v.hdfm_score.toFixed(3)}</span>
                        </div>
                    </td>
                    <td class="px-4 py-3">
                        <span class="px-2 py-1 text-xs font-semibold rounded ${
                            v.priority === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                            v.priority === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                            v.priority === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
                            'bg-green-500/20 text-green-400'
                        }">${v.priority}</span>
                    </td>
                    <td class="px-4 py-3 text-sm">${v.tcs.toFixed(3)}</td>
                    <td class="px-4 py-3">
                        ${v.kev ? '<span class="px-2 py-1 text-xs bg-red-500/20 text-red-400 rounded">YES</span>' : 
                                  '<span class="text-slate-500 text-xs">No</span>'}
                    </td>
                </tr>
            `).join('');
        }
    </script>
</body>
</html>
        """
    
    @app.post("/api/analyze")
    async def analyze_sbom(file: UploadFile = File(...)):
        """Analyze uploaded SBOM and store in database"""
        try:
            contents = await file.read()
            sbom_data = json.loads(contents)
            
            with get_repository() as repository:
                # Save SBOM first
                sbom_id = repository.save_sbom(sbom_data, source="upload")
                # Create services
                ingestion_service = IngestionService(vuln_lookup, metadata_provider)
                prioritization_service = PrioritizationService(graph_analyzer, threat_intel, repository)
                # Parse and analyze
                components, dependencies = ingestion_service.parse_sbom(sbom_data)
                result = prioritization_service.analyze(sbom_id, components, dependencies)
                
                return AnalysisResultDTO(
                    sbom_id=result.sbom_id,
                    timestamp=result.timestamp.isoformat(),
                    total_components=result.total_components,
                    total_vulnerabilities=result.total_vulnerabilities,
                    critical_findings=result.critical_findings,
                    hub_components=result.hub_components,
                    max_depth=result.max_depth,
                    vulnerabilities=[
                        VulnerabilityDTO(
                            id=v.id,
                            component=v.component_name,
                            cvss_score=v.cvss_score,
                            hdfm_score=v.hdfm_score,
                            priority=v.priority.value,
                            tcs=v.tcs,
                            epss=v.epss,
                            kev=v.kev,
                            description=v.description
                        ) for v in result.vulnerabilities
                    ],
                    entropy_weights=result.entropy_weights
                )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/reanalyze/{sbom_id}")
    async def reanalyze_sbom(sbom_id: str):
        """Re-analyze existing SBOM with updated threat intelligence"""
        try:
            with get_repository() as repository:
                sbom_dict = repository.get_sbom(sbom_id)
                
                if not sbom_dict:
                    raise HTTPException(status_code=404, detail="SBOM not found")
                
                ingestion_service = IngestionService(vuln_lookup, metadata_provider)
                prioritization_service = PrioritizationService(graph_analyzer, threat_intel, repository)
                
                components, dependencies = ingestion_service.parse_sbom(sbom_dict['data'])
                result = prioritization_service.analyze(sbom_id, components, dependencies)
                
                return AnalysisResultDTO(
                    sbom_id=result.sbom_id,
                    timestamp=result.timestamp.isoformat(),
                    total_components=result.total_components,
                    total_vulnerabilities=result.total_vulnerabilities,
                    critical_findings=result.critical_findings,
                    hub_components=result.hub_components,
                    max_depth=result.max_depth,
                    vulnerabilities=[
                        VulnerabilityDTO(
                            id=v.id,
                            component=v.component_name,
                            cvss_score=v.cvss_score,
                            hdfm_score=v.hdfm_score,
                            priority=v.priority.value,
                            tcs=v.tcs,
                            epss=v.epss,
                            kev=v.kev,
                            description=v.description
                        ) for v in result.vulnerabilities
                    ],
                    entropy_weights=result.entropy_weights
                )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/sboms")
    async def list_sboms():
        """List all stored SBOMs"""
        with get_repository() as repository:
            return repository.list_sboms()
    
    @app.get("/api/sbom/{sbom_id}/latest")
    async def get_latest_analysis(sbom_id: str):
        """Get latest analysis for SBOM"""
        with get_repository() as repository:
            result = repository.get_latest_analysis(sbom_id)
            
            if not result:
                raise HTTPException(status_code=404, detail="No analysis found")
            
            return AnalysisResultDTO(
                sbom_id=result.sbom_id,
                timestamp=result.timestamp.isoformat(),
                total_components=result.total_components,
                total_vulnerabilities=result.total_vulnerabilities,
                critical_findings=result.critical_findings,
                hub_components=result.hub_components,
                max_depth=result.max_depth,
                vulnerabilities=[
                    VulnerabilityDTO(
                        id=v.id,
                        component=v.component_name,
                        cvss_score=v.cvss_score,
                        hdfm_score=v.hdfm_score,
                        priority=v.priority.value,
                        tcs=v.tcs,
                        epss=v.epss,
                        kev=v.kev,
                        description=v.description
                    ) for v in result.vulnerabilities
                ],
                entropy_weights=result.entropy_weights
            )
    
    @app.get("/api/sbom/{sbom_id}/history")
    async def get_analysis_history(sbom_id: str):
        """Get all analyses for trend analysis"""
        with get_repository() as repository:
            results = repository.get_all_analyses(sbom_id)
            
            return [{
                'timestamp': r.timestamp.isoformat(),
                'total_vulnerabilities': r.total_vulnerabilities,
                'critical_findings': r.critical_findings,
                'hub_components': r.hub_components
            } for r in results]
    
    @app.get("/api/demo")
    async def demo():
        """Demo with sample data"""
        demo_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "metadata": {
                "component": {
                    "name": "demo-app",
                    "version": "1.0.0"
                }
            },
            "components": [
                {
                    "bom-ref": "log4j",
                    "name": "log4j-core",
                    "version": "2.14.1",
                    "vulnerabilities": [{
                        "id": "CVE-2021-44228",
                        "ratings": [{"score": 10.0, "vector": "CVSS:3.1/AV:N/AC:L"}],
                        "description": "Log4Shell RCE"
                    }]
                }
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["log4j"]}]
        }
        
        with get_repository() as repository:
            sbom_id = repository.save_sbom(demo_sbom, source="demo")
            
            ingestion_service = IngestionService(vuln_lookup)
            prioritization_service = PrioritizationService(graph_analyzer, threat_intel, repository)
            
            components, dependencies = ingestion_service.parse_sbom(demo_sbom)
            result = prioritization_service.analyze(sbom_id, components, dependencies)
            
            return AnalysisResultDTO(
                sbom_id=result.sbom_id,
                timestamp=result.timestamp.isoformat(),
                total_components=result.total_components,
                total_vulnerabilities=result.total_vulnerabilities,
                critical_findings=result.critical_findings,
                hub_components=result.hub_components,
                max_depth=result.max_depth,
                vulnerabilities=[
                    VulnerabilityDTO(
                        id=v.id,
                        component=v.component_name,
                        cvss_score=v.cvss_score,
                        hdfm_score=v.hdfm_score,
                        priority=v.priority.value,
                        tcs=v.tcs,
                        epss=v.epss,
                        kev=v.kev,
                        description=v.description
                    ) for v in result.vulnerabilities
                ],
                entropy_weights=result.entropy_weights
            )
    
    return app


if __name__ == "__main__":
    import uvicorn
    app = create_app()
    print("1. Starting HDFM v4.0 SBOM Analyzer...")
    print("2. SQLite database: hdfm_sbom.db")
    print("3. OSV.dev integration enabled")
    print("4. Open http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)