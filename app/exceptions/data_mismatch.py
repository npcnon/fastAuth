class DataMismatchException(Exception):
    """Exception raised when user data does not match."""
    def __init__(self, message="User data mismatch: the access token employee does not match the employee data"):
        self.message = message
        super().__init__(self.message)
