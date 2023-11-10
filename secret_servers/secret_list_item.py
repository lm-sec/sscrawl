class SecretListItem():
    """A secret item with all the necessary information to be retrieved.
    SecretListItems are obtained when listing the secrets of a secret server.
    They are told appart by their unique id.
    """

    unique_id: str

    def __init__(self, unique_id: str = None):
        self.unique_id = unique_id
