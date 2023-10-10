class SSNode:
    def __init__(self, id: str, isRoot = False):
        self.is_root = isRoot
        self.id = self.plantuml_encode(id)
        self.readable_id = id
        self.username = ''
        self.password = ''
        self.domain = ''
        self.is_file = False
        self.file_name = ''
        self.got_denied = False
        self.already_found = False
        self.children: 'list[SSNode]' = []
        super()

    def plantuml_encode(self, string: str) -> str:
        if not isinstance(string, str):
            string = str(string)
            
        return string.replace("/", "_slash_")