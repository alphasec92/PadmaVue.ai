"""
Document Ingestion API Endpoints
Handles file uploads with persistent storage
"""

import os
import uuid
import hashlib
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import structlog
import aiofiles

from app.config import settings
from app.storage.repository import project_repo, ProjectData
from app.utils.validation import (
    validate_filename,
    validate_file_extension,
    validate_file_size,
    validate_project_name,
    generate_safe_filename,
    FileValidationError,
)
from app.core.logging import audit_logger

logger = structlog.get_logger()
router = APIRouter()


# ===========================================
# Models
# ===========================================

class IngestResponse(BaseModel):
    """Response model for ingestion"""
    project_id: str
    project_name: str
    status: str
    files_processed: int
    document_count: int
    message: str
    created_at: str


class ProjectResponse(BaseModel):
    """Response model for project data"""
    id: str
    name: str
    description: str
    status: str
    files_count: int
    created_at: str
    updated_at: str


class FileInfo(BaseModel):
    """File information model"""
    original_name: str
    safe_name: str
    size: int
    hash: str
    mime_type: Optional[str]


# ===========================================
# Endpoints
# ===========================================

@router.post("", response_model=IngestResponse)
async def ingest_documents(
    project_name: str = Form(..., min_length=1, max_length=100),
    description: str = Form(default=""),
    files: List[UploadFile] = File(...)
):
    """
    Ingest documents for security analysis.
    
    - Validates and sanitizes file names
    - Stores files securely
    - Creates project record for tracking
    - All data persisted for later retrieval
    """
    if not files:
        raise HTTPException(status_code=400, detail="At least one file is required")
    
    try:
        # Validate project name
        safe_project_name = validate_project_name(project_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Create project
    project = await project_repo.create_project(
        name=safe_project_name,
        description=description[:500] if description else "",
        metadata={
            'source': 'api_upload',
            'upload_time': datetime.utcnow().isoformat()
        }
    )
    
    project_dir = os.path.join(settings.UPLOAD_DIR, project.id)
    os.makedirs(project_dir, mode=0o750, exist_ok=True)
    
    processed_files = []
    errors = []
    
    for file in files:
        try:
            # Validate filename
            original_name = validate_filename(file.filename or "unnamed")
            
            # Validate extension
            if not validate_file_extension(original_name):
                errors.append(f"File type not allowed: {original_name}")
                continue
            
            # Read file content
            content = await file.read()
            
            # Validate size
            if not validate_file_size(len(content)):
                errors.append(f"File too large: {original_name}")
                continue
            
            # Generate safe filename and compute hash
            safe_name = generate_safe_filename(original_name)
            file_hash = hashlib.sha256(content).hexdigest()
            
            # Save file
            file_path = os.path.join(project_dir, safe_name)
            async with aiofiles.open(file_path, 'wb') as f:
                await f.write(content)
            
            os.chmod(file_path, 0o640)
            
            # Record file info
            file_info = {
                'original_name': original_name,
                'safe_name': safe_name,
                'size': len(content),
                'hash': file_hash,
                'mime_type': file.content_type,
                'path': file_path
            }
            
            processed_files.append(file_info)
            
            # Add to project
            await project_repo.add_file_to_project(project.id, file_info)
            
            logger.info("File processed",
                       project_id=project.id,
                       file=original_name,
                       size=len(content))
            
        except FileValidationError as e:
            errors.append(f"Validation error for {file.filename}: {str(e)}")
        except Exception as e:
            errors.append(f"Error processing {file.filename}: {str(e)}")
            logger.error("File processing error", error=str(e))
    
    if not processed_files:
        # Clean up empty project
        await project_repo.delete(project.id)
        raise HTTPException(
            status_code=400, 
            detail=f"No files could be processed. Errors: {'; '.join(errors)}"
        )
    
    # Update project status
    await project_repo.update_project(
        project.id,
        status="ingested",
        metadata={
            **project.metadata,
            'files_count': len(processed_files),
            'errors': errors if errors else None
        }
    )
    
    # Audit log
    audit_logger.log_data_access(
        user_id="api",
        data_type="project",
        record_id=project.id,
        action="create",
        files_count=len(processed_files)
    )
    
    logger.info("Ingestion complete",
               project_id=project.id,
               files_processed=len(processed_files),
               errors=len(errors))
    
    return IngestResponse(
        project_id=project.id,
        project_name=safe_project_name,
        status="ingested",
        files_processed=len(processed_files),
        document_count=len(processed_files),
        message=f"Successfully processed {len(processed_files)} files" + 
                (f" with {len(errors)} errors" if errors else ""),
        created_at=project.created_at
    )


@router.get("", response_model=List[ProjectResponse])
async def list_projects():
    """List all projects"""
    projects = await project_repo.list_projects()
    
    return [
        ProjectResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            status=p.status,
            files_count=len(p.files),
            created_at=p.created_at,
            updated_at=p.updated_at
        )
        for p in projects
    ]


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: str):
    """Get project by ID"""
    project = await project_repo.get_project(project_id)
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        status=project.status,
        files_count=len(project.files),
        created_at=project.created_at,
        updated_at=project.updated_at
    )


@router.get("/{project_id}/files")
async def get_project_files(project_id: str):
    """Get files for a project"""
    project = await project_repo.get_project(project_id)
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return {
        "project_id": project_id,
        "files": [
            {
                "name": f.get('original_name'),
                "size": f.get('size'),
                "hash": f.get('hash'),
                "added_at": f.get('added_at')
            }
            for f in project.files
        ],
        "total": len(project.files)
    }


@router.delete("/{project_id}")
async def delete_project(project_id: str):
    """Delete a project and its files"""
    project = await project_repo.get_project(project_id)
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Delete files
    project_dir = os.path.join(settings.UPLOAD_DIR, project_id)
    if os.path.exists(project_dir):
        import shutil
        shutil.rmtree(project_dir)
    
    # Delete project record
    await project_repo.delete(project_id)
    
    # Audit log
    audit_logger.log_data_access(
        user_id="api",
        data_type="project",
        record_id=project_id,
        action="delete"
    )
    
    logger.info("Project deleted", project_id=project_id)
    
    return {"status": "deleted", "project_id": project_id}


# ===========================================
# Legacy Support (in-memory store reference)
# ===========================================

async def get_project_data(project_id: str) -> Optional[dict]:
    """Get project data for analysis (compatibility function)"""
    project = await project_repo.get_project(project_id)
    if not project:
        return None
    
    return {
        'project_id': project.id,
        'project_name': project.name,
        'description': project.description,
        'files': project.files,
        'metadata': project.metadata
    }


# Export for other modules
ingestion_store = {}  # Legacy compatibility - use project_repo instead
