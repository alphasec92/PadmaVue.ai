"""
Input Validation - Secure, concise validation utilities
"""

import os
import re
import html
import hashlib
from pathlib import Path
from typing import List, Set
from functools import lru_cache

from app.config import settings


class ValidationError(Exception):
    """Validation error with safe message"""
    pass


# ===========================================
# Constants (Immutable Sets for O(1) lookup)
# ===========================================

VALID_METHODOLOGIES: Set[str] = frozenset({'stride', 'pasta'})
VALID_SEVERITIES: Set[str] = frozenset({'low', 'medium', 'high', 'critical'})
VALID_ANALYSIS_TYPES: Set[str] = frozenset({'full', 'stride', 'pasta', 'compliance', 'devsecops'})
VALID_FRAMEWORKS: Set[str] = frozenset({'NIST_800_53', 'OWASP_ASVS', 'SOC2', 'GDPR', 'HIPAA', 'PCI_DSS'})
TEXT_EXTENSIONS: Set[str] = frozenset({'.txt', '.md', '.json', '.yaml', '.yml', '.xml', '.py', '.js', '.ts', '.tf'})
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
DANGEROUS_CHARS = re.compile(r'[<>"\'/\\;\x00]')


# ===========================================
# File Validation
# ===========================================

def validate_filename(filename: str) -> str:
    """Sanitize filename - remove path traversal and dangerous chars"""
    if not filename:
        raise ValidationError("Filename required")
    
    # Strip path, null bytes, traversal
    name = os.path.basename(filename).replace('\x00', '').replace('..', '')
    name = name.replace('/', '').replace('\\', '')
    
    if not name or name in ('.', '..'):
        raise ValidationError("Invalid filename")
    
    # Truncate if too long (preserve extension)
    if len(name) > 255:
        base, ext = os.path.splitext(name)
        name = base[:255-len(ext)] + ext
    
    return name


def validate_file(filename: str, size: int, content: bytes = None) -> bool:
    """Validate file extension, size, and optionally content"""
    ext = os.path.splitext(filename)[1].lower()
    
    if ext not in settings.allowed_extensions_list:
        raise ValidationError(f"File type {ext} not allowed")
    
    if not (0 < size <= settings.MAX_FILE_SIZE):
        raise ValidationError(f"File size must be 1B - {settings.MAX_FILE_SIZE}B")
    
    # Validate text files are valid UTF-8
    if content and ext in TEXT_EXTENSIONS:
        try:
            content.decode('utf-8')
        except UnicodeDecodeError:
            raise ValidationError("Invalid text encoding")
    
    return True


def safe_filename(original: str) -> str:
    """Generate hash-based safe filename"""
    name, ext = os.path.splitext(original)
    return f"{hashlib.sha256(name.encode()).hexdigest()[:16]}{ext.lower()}"


def safe_path(filename: str, base_dir: str) -> Path:
    """Get validated path within base directory"""
    name = validate_filename(filename)
    path = (Path(base_dir) / name).resolve()
    base = Path(base_dir).resolve()
    
    if not str(path).startswith(str(base)):
        raise ValidationError("Path traversal detected")
    
    return path


# ===========================================
# Text Validation
# ===========================================

def sanitize(text: str, max_len: int = 1000) -> str:
    """Sanitize text: escape HTML, remove nulls, truncate"""
    if not text:
        return ""
    return html.escape(text.replace('\x00', ''))[:max_len]


def validate_project_name(name: str) -> str:
    """Validate project name"""
    if not name:
        raise ValidationError("Project name required")
    
    clean = DANGEROUS_CHARS.sub('', name)[:100].strip()
    
    if not re.search(r'[a-zA-Z0-9]', clean):
        raise ValidationError("Name must contain alphanumeric characters")
    
    return clean


def is_valid_uuid(s: str) -> bool:
    """Check if string is valid UUID"""
    return bool(UUID_PATTERN.match(s))


# ===========================================
# API Input Validation
# ===========================================

def validate_enum(value: str, valid_set: Set[str], field_name: str) -> str:
    """Generic enum validator"""
    v = value.lower().strip()
    if v not in valid_set:
        raise ValidationError(f"Invalid {field_name}. Must be: {', '.join(sorted(valid_set))}")
    return v


# Convenience functions using validate_enum
validate_methodology = lambda v: validate_enum(v, VALID_METHODOLOGIES, "methodology")
validate_severity = lambda v: validate_enum(v, VALID_SEVERITIES, "severity")  
validate_analysis_type = lambda v: validate_enum(v, VALID_ANALYSIS_TYPES, "analysis_type")


def validate_compliance_frameworks(frameworks: List[str]) -> List[str]:
    """Validate and filter compliance frameworks"""
    valid = [f.upper().strip() for f in frameworks if f.upper().strip() in VALID_FRAMEWORKS]
    return valid or ['NIST_800_53', 'OWASP_ASVS']


# Re-export for backward compatibility
FileValidationError = ValidationError

# Backward compatibility aliases for ingest.py
def validate_file_extension(filename: str) -> bool:
    """Validate file extension is allowed"""
    ext = os.path.splitext(filename)[1].lower()
    return ext in settings.allowed_extensions_list

def validate_file_size(size: int) -> bool:
    """Validate file size is within limits"""
    return 0 < size <= settings.MAX_FILE_SIZE

def generate_safe_filename(filename: str) -> str:
    """Alias for safe_filename"""
    return safe_filename(filename)

def sanitize_html(text: str) -> str:
    """Alias for sanitize"""
    return sanitize(text)

def sanitize_string(text: str, max_length: int = 1000) -> str:
    """Alias for sanitize"""
    return sanitize(text, max_length)

def validate_uuid(s: str) -> bool:
    """Alias for is_valid_uuid"""
    return is_valid_uuid(s)

def validate_file_content(content: bytes, ext: str) -> bool:
    """Validate file content"""
    if ext in TEXT_EXTENSIONS:
        try:
            content.decode('utf-8')
        except UnicodeDecodeError:
            raise ValidationError("Invalid text encoding")
    return True

def validate_path_within_directory(path: Path, base_dir: Path) -> bool:
    """Check if path is within base directory"""
    try:
        path.resolve().relative_to(base_dir.resolve())
        return True
    except ValueError:
        return False

def get_safe_path(filename: str, base_dir: str) -> Path:
    """Alias for safe_path"""
    return safe_path(filename, base_dir)
