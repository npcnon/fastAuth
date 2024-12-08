class BlockedRefreshTokenException(Exception):
    """Exception raised when refresh token is blocked."""
    def __init__(self, message="Refresh token blocked: refresh token is blocked, please log in again"):
        self.message = message
        super().__init__(self.message)
