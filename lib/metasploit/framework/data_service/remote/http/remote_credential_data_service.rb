require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteCredentialDataService
  include ResponseDataHelper

  CREDENTIAL_PATH = '/api/1/msf/credential'

  def creds(opts = {})
    json_to_open_struct_object(self.get_data(CREDENTIAL_PATH, opts), [])
  end

  def create_credential(opts)
    self.post_data_async(CREDENTIAL_PATH, opts)
  end
end