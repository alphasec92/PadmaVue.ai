"""
Document Parser Service
Parses various document formats for security analysis
"""

import os
from typing import List, Dict, Any, Optional
from pathlib import Path

import structlog

from app.config import settings

logger = structlog.get_logger()


class DocumentParser:
    """
    Document parser using Unstructured.io for multiple formats.
    
    Supports:
    - PDF documents
    - Markdown files
    - Word documents (DOCX)
    - Plain text
    - YAML/JSON configuration files
    """
    
    def __init__(self):
        self.chunk_size = 1000
        self.chunk_overlap = 200
    
    async def parse_document(
        self,
        file_path: str
    ) -> List[Dict[str, Any]]:
        """
        Parse a document and return chunks.
        
        Args:
            file_path: Path to the document
        
        Returns:
            List of document chunks with metadata
        """
        file_path = Path(file_path)
        extension = file_path.suffix.lower()
        
        logger.info("Parsing document", 
                   file=file_path.name, 
                   extension=extension)
        
        try:
            if extension == ".pdf":
                return await self._parse_pdf(file_path)
            elif extension == ".md":
                return await self._parse_markdown(file_path)
            elif extension == ".docx":
                return await self._parse_docx(file_path)
            elif extension in [".txt", ".text"]:
                return await self._parse_text(file_path)
            elif extension in [".yaml", ".yml"]:
                return await self._parse_yaml(file_path)
            elif extension == ".json":
                return await self._parse_json(file_path)
            else:
                logger.warning("Unknown file type, treating as text", extension=extension)
                return await self._parse_text(file_path)
                
        except Exception as e:
            logger.error("Failed to parse document", 
                        file=file_path.name, 
                        error=str(e))
            raise
    
    async def _parse_pdf(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse PDF document"""
        chunks = []
        
        try:
            from pypdf import PdfReader
            
            reader = PdfReader(str(file_path))
            
            for page_num, page in enumerate(reader.pages, 1):
                text = page.extract_text()
                
                if text.strip():
                    page_chunks = self._chunk_text(
                        text,
                        metadata={
                            "source_file": file_path.name,
                            "page_number": page_num,
                            "chunk_type": "pdf_page",
                            "total_pages": len(reader.pages)
                        }
                    )
                    chunks.extend(page_chunks)
            
            logger.info("Parsed PDF", 
                       file=file_path.name, 
                       pages=len(reader.pages),
                       chunks=len(chunks))
            
        except ImportError:
            logger.warning("pypdf not available, using basic parsing")
            chunks = await self._fallback_parse(file_path, "pdf")
        
        return chunks
    
    async def _parse_markdown(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse Markdown document"""
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Split by headers for better context preservation
        sections = self._split_markdown_sections(content)
        
        chunks = []
        for section in sections:
            section_chunks = self._chunk_text(
                section["content"],
                metadata={
                    "source_file": file_path.name,
                    "chunk_type": "markdown_section",
                    "section_title": section.get("title", ""),
                    "section_level": section.get("level", 0)
                }
            )
            chunks.extend(section_chunks)
        
        logger.info("Parsed Markdown", 
                   file=file_path.name, 
                   sections=len(sections),
                   chunks=len(chunks))
        
        return chunks
    
    async def _parse_docx(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse Word document"""
        chunks = []
        
        try:
            from docx import Document
            
            doc = Document(str(file_path))
            
            paragraphs = []
            for para in doc.paragraphs:
                if para.text.strip():
                    paragraphs.append(para.text)
            
            full_text = "\n\n".join(paragraphs)
            
            chunks = self._chunk_text(
                full_text,
                metadata={
                    "source_file": file_path.name,
                    "chunk_type": "docx",
                    "paragraph_count": len(paragraphs)
                }
            )
            
            logger.info("Parsed DOCX", 
                       file=file_path.name,
                       paragraphs=len(paragraphs),
                       chunks=len(chunks))
            
        except ImportError:
            logger.warning("python-docx not available, using basic parsing")
            chunks = await self._fallback_parse(file_path, "docx")
        
        return chunks
    
    async def _parse_text(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse plain text file"""
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        chunks = self._chunk_text(
            content,
            metadata={
                "source_file": file_path.name,
                "chunk_type": "text"
            }
        )
        
        logger.info("Parsed text file", 
                   file=file_path.name,
                   chunks=len(chunks))
        
        return chunks
    
    async def _parse_yaml(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse YAML configuration file"""
        import yaml
        
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            data = yaml.safe_load(content)
        
        # Convert YAML structure to searchable text
        text_content = self._yaml_to_text(data)
        
        chunks = self._chunk_text(
            text_content,
            metadata={
                "source_file": file_path.name,
                "chunk_type": "yaml_config",
                "raw_yaml": content[:500]  # Store first 500 chars of raw YAML
            }
        )
        
        # Also store the raw YAML as a single chunk for structure analysis
        chunks.append({
            "content": content,
            "metadata": {
                "source_file": file_path.name,
                "chunk_type": "yaml_raw"
            }
        })
        
        logger.info("Parsed YAML", file=file_path.name, chunks=len(chunks))
        
        return chunks
    
    async def _parse_json(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse JSON file"""
        import json
        
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            data = json.loads(content)
        
        # Convert JSON structure to searchable text
        text_content = self._json_to_text(data)
        
        chunks = self._chunk_text(
            text_content,
            metadata={
                "source_file": file_path.name,
                "chunk_type": "json_config"
            }
        )
        
        logger.info("Parsed JSON", file=file_path.name, chunks=len(chunks))
        
        return chunks
    
    def _chunk_text(
        self,
        text: str,
        metadata: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """Split text into overlapping chunks"""
        chunks = []
        
        if len(text) <= self.chunk_size:
            chunks.append({
                "content": text,
                "metadata": {**(metadata or {}), "chunk_index": 0}
            })
        else:
            start = 0
            chunk_index = 0
            
            while start < len(text):
                end = start + self.chunk_size
                
                # Try to break at sentence boundary
                if end < len(text):
                    # Look for sentence end within the chunk
                    for sep in [". ", ".\n", "\n\n", "\n"]:
                        last_sep = text.rfind(sep, start, end)
                        if last_sep > start + self.chunk_size // 2:
                            end = last_sep + len(sep)
                            break
                
                chunk_text = text[start:end].strip()
                
                if chunk_text:
                    chunks.append({
                        "content": chunk_text,
                        "metadata": {
                            **(metadata or {}),
                            "chunk_index": chunk_index,
                            "start_char": start,
                            "end_char": end
                        }
                    })
                    chunk_index += 1
                
                start = end - self.chunk_overlap
        
        return chunks
    
    def _split_markdown_sections(self, content: str) -> List[Dict[str, Any]]:
        """Split markdown by headers"""
        import re
        
        sections = []
        current_section = {"title": "", "level": 0, "content": ""}
        
        lines = content.split("\n")
        
        for line in lines:
            header_match = re.match(r'^(#{1,6})\s+(.+)$', line)
            
            if header_match:
                # Save previous section if it has content
                if current_section["content"].strip():
                    sections.append(current_section)
                
                # Start new section
                level = len(header_match.group(1))
                title = header_match.group(2)
                current_section = {
                    "title": title,
                    "level": level,
                    "content": f"{line}\n"
                }
            else:
                current_section["content"] += f"{line}\n"
        
        # Don't forget the last section
        if current_section["content"].strip():
            sections.append(current_section)
        
        return sections
    
    def _yaml_to_text(self, data: Any, prefix: str = "") -> str:
        """Convert YAML data to searchable text"""
        lines = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_prefix = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    lines.append(f"{new_prefix}:")
                    lines.append(self._yaml_to_text(value, new_prefix))
                else:
                    lines.append(f"{new_prefix}: {value}")
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_prefix = f"{prefix}[{i}]"
                if isinstance(item, (dict, list)):
                    lines.append(self._yaml_to_text(item, new_prefix))
                else:
                    lines.append(f"{new_prefix}: {item}")
        
        else:
            lines.append(str(data))
        
        return "\n".join(lines)
    
    def _json_to_text(self, data: Any, prefix: str = "") -> str:
        """Convert JSON data to searchable text"""
        return self._yaml_to_text(data, prefix)
    
    async def _fallback_parse(
        self,
        file_path: Path,
        file_type: str
    ) -> List[Dict[str, Any]]:
        """Fallback parsing when specific parsers aren't available"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except:
            with open(file_path, "rb") as f:
                content = f.read().decode("utf-8", errors="ignore")
        
        return self._chunk_text(
            content,
            metadata={
                "source_file": file_path.name,
                "chunk_type": f"{file_type}_fallback"
            }
        )


