import re
from uuid import UUID


class Utils:
    def is_valid_uuid(uuid: str) -> bool:
        try:
            UUID(uuid)
            return True
        except ValueError:
            return False

    def is_username_like(field_name: str) -> bool:
        """Matches different patterns of 'username', 'role-id', 'user-id', 'client-id'"""
        # https://regex101.com/r/mR00PO/1
        return re.match(
            r"^\s*((user[ \_\-]?((name)|(id))?)|(((role)|(client))[ \_\-]?id))\s*$",
            field_name, re.IGNORECASE) is not None

    def is_password_like(field_name: str) -> bool:
        """Matches different patterns of 'username' and 'secret-id'"""
        # https://regex101.com/r/7OFm05/1
        return re.match(
            r"^\s*((pass[ \_\-]?(word)?)|(secret[ \_\-]?(id)?))\s*$",
            field_name, re.IGNORECASE) is not None

    def is_file_like(file_content: str) -> bool:
        """Tells if the file_content looks like it is a file, as if it is multi-line, for instance"""
        file_markers = ["\n", "\r", "\x00"]
        return len(file_content) > 200 or any(ele in file_content for ele in file_markers)
