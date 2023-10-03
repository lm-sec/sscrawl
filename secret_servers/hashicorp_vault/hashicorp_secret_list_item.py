from secret_servers.hashicorp_vault.hashicorp_vault_constants import SECRET_ENGINE_CUBBYHOLE, SECRET_ENGINE_KVV1, SECRET_ENGINE_KVV2
from secret_servers.secret_list_item import SecretListItem

class HashicorpSecretListItem(SecretListItem):
  secret_engine_type: str
  secret_engine_path: str
  secret_local_path: str

  def __init__(self, secret_engine_type: str, secret_engine_path: str, secret_local_path : str):
    self.secret_engine_type = secret_engine_type
    self.secret_engine_path = secret_engine_path
    self.secret_local_path = secret_local_path
    super().__init__(self.get_secret_data_path())

  def get_secret_data_path(self):
    if self.secret_engine_type == SECRET_ENGINE_KVV1 or self.secret_engine_type == SECRET_ENGINE_CUBBYHOLE:
      return f"/{self.secret_engine_path}{self.secret_local_path}"
    elif self.secret_engine_type == SECRET_ENGINE_KVV2:
      return f"/{self.secret_engine_path}data/{self.secret_local_path}"
    return ""
