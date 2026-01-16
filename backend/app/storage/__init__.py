"""
Data Storage Layer
Persistent storage for projects, analyses, and AI-generated content
"""

from app.storage.repository import (
    Repository,
    ProjectData,
    AnalysisData,
    ReportData,
    Status,
    ProjectRepository,
    AnalysisRepository,
    ReportRepository,
    ThreatRepository,
    project_repo,
    analysis_repo,
    report_repo,
    threat_repo,
    AnalysisStatus,  # Backward compatibility alias
)

__all__ = [
    'Repository',
    'ProjectData',
    'AnalysisData',
    'ReportData',
    'Status',
    'AnalysisStatus',
    'ProjectRepository',
    'AnalysisRepository',
    'ReportRepository',
    'ThreatRepository',
    'project_repo',
    'analysis_repo',
    'report_repo',
    'threat_repo',
]
