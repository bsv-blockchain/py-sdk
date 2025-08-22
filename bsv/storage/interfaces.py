from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, List, Optional

@dataclass
class DownloadResult:
    """
    Result object for file download operations.
    """
    data: bytes
    mime_type: str

@dataclass
class UploadFileResult:
    """
    Result object for file upload operations.
    """
    uhrp_url: str
    published: bool
    # Optionally, add more fields if needed for future extensions

@dataclass
class FindFileData:
    """
    Metadata for a file found by UHRP URL.
    """
    name: str
    size: str
    mime_type: str
    expiry_time: int
    code: Optional[str] = None
    description: Optional[str] = None

@dataclass
class UploadMetadata:
    """
    Metadata for each upload returned by list_uploads.
    """
    uhrp_url: str
    expiry_time: int
    name: Optional[str] = None
    size: Optional[str] = None
    mime_type: Optional[str] = None
    code: Optional[str] = None
    description: Optional[str] = None

@dataclass
class RenewFileResult:
    """
    Result object for file renewal operations.
    """
    status: str
    prev_expiry_time: int
    new_expiry_time: int
    amount: int
    code: Optional[str] = None
    description: Optional[str] = None

class StorageDownloaderInterface(ABC):
    """
    Abstract base class for file downloaders.
    """
    @abstractmethod
    def resolve(self, uhrp_url: str) -> List[str]:
        """
        Resolve a UHRP URL to a list of HTTP URLs.
        """
        pass

    @abstractmethod
    def download(self, uhrp_url: str) -> DownloadResult:
        """
        Download a file by its UHRP URL.
        """
        pass

class StorageUploaderInterface(ABC):
    """
    Abstract base class for file uploaders.
    """
    @abstractmethod
    def publish_file(self, file_data: bytes, mime_type: str, retention_period: int) -> UploadFileResult:
        """
        Upload a file to the storage service.
        """
        pass

    @abstractmethod
    def find_file(self, uhrp_url: str) -> FindFileData:
        """
        Retrieve metadata for a file by its UHRP URL.
        """
        pass

    @abstractmethod
    def list_uploads(self) -> List[UploadMetadata]:
        """
        List all uploads for the authenticated user.
        """
        pass

    @abstractmethod
    def renew_file(self, uhrp_url: str, additional_minutes: int) -> RenewFileResult:
        """
        Extend the retention period for an uploaded file.
        """
        pass
