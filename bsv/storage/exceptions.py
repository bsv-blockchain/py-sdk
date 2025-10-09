class StorageError(Exception):
    """
    Base exception for the storage module.
    """
    pass

class UploadError(StorageError):
    """
    Raised when file upload fails.
    """
    pass

class DownloadError(StorageError):
    """
    Raised when file download fails.
    """
    pass

class AuthError(StorageError):
    """
    Raised when authentication or wallet integration fails.
    """
    pass

class NetworkError(StorageError):
    """
    Raised when network communication fails.
    """
    pass
