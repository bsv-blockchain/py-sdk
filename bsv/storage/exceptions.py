class StorageError(Exception):
    """
    Base exception for the storage module.
    """


class UploadError(StorageError):
    """
    Raised when file upload fails.
    """


class DownloadError(StorageError):
    """
    Raised when file download fails.
    """


class AuthError(StorageError):
    """
    Raised when authentication or wallet integration fails.
    """


class NetworkError(StorageError):
    """
    Raised when network communication fails.
    """
