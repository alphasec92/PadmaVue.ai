"""
Data Repository - Async file-based storage with type safety
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, TypeVar, Generic
from dataclasses import dataclass, asdict, field
from enum import Enum

import aiofiles
import structlog

from app.config import settings

logger = structlog.get_logger()

# Storage paths
DATA_DIR = Path(settings.DATA_DIR)
PROJECTS_DIR = DATA_DIR / "projects"
ANALYSES_DIR = DATA_DIR / "analyses"
REPORTS_DIR = DATA_DIR / "reports"
EXPORTS_DIR = DATA_DIR / "exports"


# ===========================================
# Data Models
# ===========================================

class Status(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ProjectData:
    id: str
    name: str
    description: str = ""
    status: str = "created"
    files: List[Dict] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    # Optional fields added by architect form
    source: Optional[str] = None
    architecture_types: List[str] = field(default_factory=list)
    methodology: Optional[str] = None


@dataclass  
class AnalysisData:
    id: str
    project_id: str
    methodology: str
    status: str = Status.PENDING.value
    threats: List[Dict] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)
    compliance_summary: Dict = field(default_factory=dict)
    agent_logs: List[Dict] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    dfd_mermaid: Optional[str] = None
    devsecops_rules: Optional[Dict] = None
    pasta_stages: Optional[Dict] = None
    source_data: Optional[Dict] = None  # Original form/file data used to create analysis
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None


@dataclass
class ReportData:
    id: str
    project_id: str
    analysis_id: str
    report_type: str
    content: Dict
    format: str = "json"
    file_path: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


# ===========================================
# Base Repository
# ===========================================

T = TypeVar('T')

class Repository(Generic[T]):
    """Async JSON file repository"""
    
    def __init__(self, path: Path, model_class: type):
        self.path = path
        self.model = model_class
        self.path.mkdir(parents=True, exist_ok=True)
    
    def _file(self, id: str) -> Path:
        return self.path / f"{id}.json"
    
    async def save(self, id: str, data: Dict) -> bool:
        try:
            # Create a copy to avoid modifying the input dict
            save_data = {**data, '_ts': datetime.utcnow().isoformat()}
            async with aiofiles.open(self._file(id), 'w') as f:
                await f.write(json.dumps(save_data, indent=2, default=str))
            return True
        except Exception as e:
            logger.error("save_failed", id=id, error=str(e))
            return False
    
    async def load(self, id: str) -> Optional[Dict]:
        try:
            if not self._file(id).exists():
                return None
            async with aiofiles.open(self._file(id)) as f:
                data = json.loads(await f.read())
                data.pop('_ts', None)
                return data
        except Exception as e:
            logger.error("load_failed", id=id, error=str(e))
            return None
    
    async def delete(self, id: str) -> bool:
        try:
            f = self._file(id)
            if f.exists():
                f.unlink()
            return True
        except Exception:
            return False
    
    async def list_ids(self) -> List[str]:
        return [f.stem for f in self.path.glob("*.json")]
    
    async def get(self, id: str) -> Optional[T]:
        data = await self.load(id)
        return self.model(**data) if data else None
    
    async def find(self, **criteria) -> List[T]:
        results = []
        for id in await self.list_ids():
            item = await self.get(id)
            if item and all(getattr(item, k, None) == v for k, v in criteria.items()):
                results.append(item)
        return results


# ===========================================
# Specialized Repositories
# ===========================================

class ProjectRepository(Repository[ProjectData]):
    def __init__(self):
        super().__init__(PROJECTS_DIR, ProjectData)
    
    async def create(self, name: str, description: str = "", **kw) -> ProjectData:
        project = ProjectData(id=str(uuid.uuid4()), name=name, description=description, **kw)
        await self.save(project.id, asdict(project))
        logger.info("project_created", id=project.id, name=name)
        return project
    
    async def update(self, id: str, **updates) -> Optional[ProjectData]:
        project = await self.get(id)
        if not project:
            return None
        data = {**asdict(project), **updates, 'updated_at': datetime.utcnow().isoformat()}
        await self.save(id, data)
        # Filter out internal fields (starting with _) that may have been added by storage
        clean_data = {k: v for k, v in data.items() if not k.startswith('_')}
        return ProjectData(**clean_data)
    
    async def add_file(self, id: str, file_info: Dict) -> bool:
        project = await self.get(id)
        if not project:
            return False
        project.files.append({**file_info, 'added_at': datetime.utcnow().isoformat()})
        return await self.save(id, asdict(project))


class AnalysisRepository(Repository[AnalysisData]):
    def __init__(self):
        super().__init__(ANALYSES_DIR, AnalysisData)
    
    async def create(self, project_id: str, methodology: str) -> AnalysisData:
        analysis = AnalysisData(id=str(uuid.uuid4()), project_id=project_id, methodology=methodology)
        await self.save(analysis.id, asdict(analysis))
        logger.info("analysis_created", id=analysis.id, project_id=project_id)
        return analysis
    
    async def update(self, id: str, **updates) -> Optional[AnalysisData]:
        analysis = await self.get(id)
        if not analysis:
            return None
        data = {**asdict(analysis), **updates}
        await self.save(id, data)
        # Filter out internal fields (starting with _) that may have been added by storage
        clean_data = {k: v for k, v in data.items() if not k.startswith('_')}
        return AnalysisData(**clean_data)
    
    async def complete(self, id: str, results: Dict) -> Optional[AnalysisData]:
        return await self.update(id,
            status=Status.COMPLETED.value,
            completed_at=datetime.utcnow().isoformat(),
            **{k: results.get(k) for k in ['summary', 'threats', 'compliance_summary', 'dfd_mermaid', 'devsecops_rules', 'pasta_stages'] if k in results}
        )
    
    async def add_log(self, id: str, agent: str, action: str, data: Dict) -> bool:
        analysis = await self.get(id)
        if not analysis:
            return False
        analysis.agent_logs.append({'timestamp': datetime.utcnow().isoformat(), 'agent': agent, 'action': action, 'data': data})
        return await self.save(id, asdict(analysis))
    
    async def for_project(self, project_id: str) -> List[AnalysisData]:
        analyses = await self.find(project_id=project_id)
        return sorted(analyses, key=lambda a: a.created_at, reverse=True)
    
    async def list_all(self, limit: int = 20) -> List[Dict]:
        """List all analyses, most recent first."""
        ids = await self.list_ids()
        analyses = []
        for aid in ids[:limit * 2]:  # Get extra to filter
            data = await self.load(aid)
            if data:
                analyses.append({
                    "id": data.get("id", aid),
                    "project_id": data.get("project_id"),
                    "methodology": data.get("methodology"),
                    "status": data.get("status"),
                    "created_at": data.get("created_at"),
                    "completed_at": data.get("completed_at"),
                    "threats_count": len(data.get("threats", [])),
                })
        # Sort by created_at descending
        analyses.sort(key=lambda a: a.get("created_at", ""), reverse=True)
        return analyses[:limit]


class ReportRepository(Repository[ReportData]):
    def __init__(self):
        super().__init__(REPORTS_DIR, ReportData)
        EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    async def create(self, project_id: str, analysis_id: str, report_type: str, content: Dict, fmt: str = "json") -> ReportData:
        report_id = str(uuid.uuid4())
        file_path = None
        
        if fmt in ("json", "md"):
            export_file = EXPORTS_DIR / f"report_{report_id}.{fmt}"
            text = json.dumps(content, indent=2, default=str) if fmt == "json" else self._to_markdown(content)
            async with aiofiles.open(export_file, 'w') as f:
                await f.write(text)
            file_path = str(export_file)
        
        report = ReportData(id=report_id, project_id=project_id, analysis_id=analysis_id, report_type=report_type, content=content, format=fmt, file_path=file_path)
        await self.save(report_id, asdict(report))
        logger.info("report_created", id=report_id, type=report_type)
        return report
    
    async def for_project(self, project_id: str) -> List[ReportData]:
        return await self.find(project_id=project_id)
    
    def _to_markdown(self, content: Dict) -> str:
        lines = ["# Security Analysis Report", f"\n**Generated:** {datetime.utcnow().isoformat()}", "\n## Summary"]
        if s := content.get('summary'):
            lines.append(f"- **Total Threats:** {s.get('total_threats', 0)}")
            for sev, cnt in s.get('by_severity', {}).items():
                lines.append(f"- **{sev.title()}:** {cnt}")
        if threats := content.get('threats'):
            lines.append("\n## Threats")
            for t in threats:
                lines.extend([f"\n### {t.get('title', 'Unknown')}", f"**Severity:** {t.get('severity')}", f"**Category:** {t.get('category')}", f"\n{t.get('description', '')}"])
                if m := t.get('mitigations'):
                    lines.extend(["\n**Mitigations:**"] + [f"- {x}" for x in m])
        return "\n".join(lines)


class ThreatRepository(Repository[Dict]):
    def __init__(self):
        super().__init__(DATA_DIR / "threats", dict)
    
    async def save_batch(self, analysis_id: str, threats: List[Dict]) -> bool:
        for t in threats:
            t_id = t.get('id', str(uuid.uuid4()))
            await self.save(t_id, {**t, 'analysis_id': analysis_id, 'stored_at': datetime.utcnow().isoformat()})
        logger.info("threats_saved", analysis_id=analysis_id, count=len(threats))
        return True
    
    async def for_analysis(self, analysis_id: str) -> List[Dict]:
        return [t for t in [await self.load(id) for id in await self.list_ids()] if t and t.get('analysis_id') == analysis_id]


# ===========================================
# Global Instances
# ===========================================

project_repo = ProjectRepository()
analysis_repo = AnalysisRepository()
report_repo = ReportRepository()
threat_repo = ThreatRepository()

# Backward compatibility aliases
AnalysisStatus = Status
ProjectRepository.create_project = ProjectRepository.create
ProjectRepository.get_project = ProjectRepository.get
ProjectRepository.update_project = ProjectRepository.update
ProjectRepository.add_file_to_project = ProjectRepository.add_file
ProjectRepository.list_projects = lambda self: self.find()
AnalysisRepository.create_analysis = AnalysisRepository.create
AnalysisRepository.get_analysis = AnalysisRepository.get
AnalysisRepository.update_analysis = AnalysisRepository.update
AnalysisRepository.complete_analysis = AnalysisRepository.complete
AnalysisRepository.add_agent_log = AnalysisRepository.add_log
AnalysisRepository.get_project_analyses = AnalysisRepository.for_project
ReportRepository.create_report = ReportRepository.create
ReportRepository.get_report = ReportRepository.get
ReportRepository.get_project_reports = ReportRepository.for_project
ThreatRepository.save_threats = ThreatRepository.save_batch
ThreatRepository.get_threats_by_analysis = ThreatRepository.for_analysis
