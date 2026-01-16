"""
Custom Exceptions with User-Friendly Messages
Provides categorized errors for better UX while logging technical details
"""

from enum import Enum
from typing import Optional, Dict, Any


class ErrorCategory(str, Enum):
    """Error categories for user-friendly classification"""
    FILE_ERROR = "file_error"
    LLM_ERROR = "llm_error"
    VALIDATION_ERROR = "validation_error"
    NOT_FOUND = "not_found"
    RATE_LIMIT = "rate_limit"
    CONFIGURATION = "configuration"
    DATABASE = "database"
    INTERNAL = "internal"


# User-friendly messages for each category
ERROR_MESSAGES = {
    ErrorCategory.FILE_ERROR: {
        "title": "File Processing Error",
        "default": "There was a problem processing your file. Please ensure the file is in a supported format and not corrupted.",
        "unsupported_type": "The file type you uploaded is not supported. Supported formats: PDF, MD, TXT, JSON, YAML, XML, Python, JavaScript, TypeScript, Terraform.",
        "too_large": "The file is too large. Maximum file size is 10MB.",
        "empty": "The uploaded file appears to be empty.",
        "encoding": "The file has an unsupported encoding. Please ensure text files are UTF-8 encoded.",
    },
    ErrorCategory.LLM_ERROR: {
        "title": "AI Analysis Error",
        "default": "The AI service encountered an issue while analyzing your project. Please try again in a moment.",
        "timeout": "The analysis took longer than expected. Please try with a smaller document or simpler project.",
        "rate_limit": "We've reached the AI service rate limit. Please wait a moment and try again.",
        "api_key": "The AI service is not properly configured. Please contact the administrator.",
        "unavailable": "The AI service is temporarily unavailable. Please try again later.",
    },
    ErrorCategory.VALIDATION_ERROR: {
        "title": "Validation Error",
        "default": "The provided input is invalid. Please check your data and try again.",
        "methodology": "Invalid methodology selected. Please choose STRIDE or PASTA.",
        "project_name": "Invalid project name. Use alphanumeric characters only.",
    },
    ErrorCategory.NOT_FOUND: {
        "title": "Not Found",
        "default": "The requested resource was not found.",
        "project": "Project not found. Please upload your documents first before running analysis.",
        "analysis": "Analysis not found. It may have been deleted or the ID is incorrect.",
    },
    ErrorCategory.RATE_LIMIT: {
        "title": "Rate Limit Exceeded",
        "default": "Too many requests. Please wait a moment before trying again.",
    },
    ErrorCategory.CONFIGURATION: {
        "title": "Configuration Error",
        "default": "The server is not properly configured. Please contact the administrator.",
    },
    ErrorCategory.DATABASE: {
        "title": "Storage Error",
        "default": "There was an issue saving or retrieving your data. Please try again.",
    },
    ErrorCategory.INTERNAL: {
        "title": "Internal Error",
        "default": "An unexpected error occurred. Our team has been notified. Please try again later.",
    },
}


class AnalysisError(Exception):
    """
    Base exception for analysis errors with user-friendly messaging.
    
    Provides both a user-safe message for the frontend and
    technical details for backend logging.
    """
    
    def __init__(
        self,
        category: ErrorCategory,
        message_key: str = "default",
        technical_details: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
    ):
        self.category = category
        self.message_key = message_key
        self.technical_details = technical_details or str(original_error) if original_error else None
        self.context = context or {}
        self.original_error = original_error
        
        # Get user-friendly message
        category_messages = ERROR_MESSAGES.get(category, ERROR_MESSAGES[ErrorCategory.INTERNAL])
        self.user_message = category_messages.get(message_key, category_messages["default"])
        self.title = category_messages.get("title", "Error")
        
        super().__init__(self.user_message)
    
    def to_response(self) -> Dict[str, Any]:
        """Convert to API response format"""
        return {
            "error": True,
            "category": self.category.value,
            "title": self.title,
            "message": self.user_message,
            "help": self._get_help_text(),
        }
    
    def to_log_context(self) -> Dict[str, Any]:
        """Get context for logging (includes technical details)"""
        return {
            "category": self.category.value,
            "message_key": self.message_key,
            "technical_details": self.technical_details,
            "original_error_type": type(self.original_error).__name__ if self.original_error else None,
            **self.context,
        }
    
    def _get_help_text(self) -> str:
        """Get helpful suggestions based on error category"""
        help_texts = {
            ErrorCategory.FILE_ERROR: "Try uploading a different file format or checking if the file is corrupted.",
            ErrorCategory.LLM_ERROR: "Wait a few moments and try again. If the issue persists, try with a smaller document.",
            ErrorCategory.VALIDATION_ERROR: "Check your input and ensure all required fields are filled correctly.",
            ErrorCategory.NOT_FOUND: "Make sure you've uploaded documents before running analysis.",
            ErrorCategory.RATE_LIMIT: "Wait 60 seconds before making another request.",
            ErrorCategory.CONFIGURATION: "Contact the system administrator to resolve this issue.",
            ErrorCategory.DATABASE: "Try the operation again. If it persists, contact support.",
            ErrorCategory.INTERNAL: "Our team has been notified. Please try again later.",
        }
        return help_texts.get(self.category, "Please try again.")


# Convenience subclasses for common error types
class FileError(AnalysisError):
    def __init__(self, message_key: str = "default", **kwargs):
        super().__init__(ErrorCategory.FILE_ERROR, message_key, **kwargs)


class LLMError(AnalysisError):
    def __init__(self, message_key: str = "default", **kwargs):
        super().__init__(ErrorCategory.LLM_ERROR, message_key, **kwargs)


class ValidationError(AnalysisError):
    def __init__(self, message_key: str = "default", **kwargs):
        super().__init__(ErrorCategory.VALIDATION_ERROR, message_key, **kwargs)


class NotFoundError(AnalysisError):
    def __init__(self, message_key: str = "default", **kwargs):
        super().__init__(ErrorCategory.NOT_FOUND, message_key, **kwargs)


class DatabaseError(AnalysisError):
    def __init__(self, message_key: str = "default", **kwargs):
        super().__init__(ErrorCategory.DATABASE, message_key, **kwargs)


def classify_error(error: Exception, context: Optional[Dict[str, Any]] = None) -> AnalysisError:
    """
    Classify a raw exception into an appropriate AnalysisError.
    This is used to convert unexpected exceptions into user-friendly errors.
    """
    error_str = str(error).lower()
    context = context or {}
    
    # LLM-related errors
    if any(keyword in error_str for keyword in ['openai', 'anthropic', 'api key', 'rate limit', 'quota', 'timeout', 'model']):
        if 'rate limit' in error_str or 'quota' in error_str:
            return LLMError("rate_limit", original_error=error, context=context)
        if 'timeout' in error_str:
            return LLMError("timeout", original_error=error, context=context)
        if 'api key' in error_str or 'authentication' in error_str:
            return LLMError("api_key", original_error=error, context=context)
        return LLMError("default", original_error=error, context=context)
    
    # Database/storage errors
    if any(keyword in error_str for keyword in ['database', 'connection', 'neo4j', 'qdrant', 'storage', 'repository']):
        return DatabaseError("default", original_error=error, context=context)
    
    # File errors
    if any(keyword in error_str for keyword in ['file', 'upload', 'encoding', 'decode']):
        if 'encoding' in error_str or 'decode' in error_str:
            return FileError("encoding", original_error=error, context=context)
        return FileError("default", original_error=error, context=context)
    
    # Validation errors
    if any(keyword in error_str for keyword in ['validation', 'invalid', 'required', 'missing']):
        return ValidationError("default", original_error=error, context=context)
    
    # Default to internal error
    return AnalysisError(
        ErrorCategory.INTERNAL,
        technical_details=str(error),
        context=context,
        original_error=error,
    )
