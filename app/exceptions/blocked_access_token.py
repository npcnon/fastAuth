class BlockedAccessTokenException(Exception):
    """Exception raised when access token is blocked."""
    def __init__(self, message="Access token blocked: access token is blocked"):
        self.message = message
        super().__init__(self.message)
