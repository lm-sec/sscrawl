class AuthenticationMethodNotSupportedException(Exception):
    """The selected vault does not support the provided authentication mehod."""

    def __init__(self, text: str = None):
        final_text = 'The selected vault does not support the provided authentication method.'
        if text is not None:
            final_text = text

        super().__init__(final_text)
