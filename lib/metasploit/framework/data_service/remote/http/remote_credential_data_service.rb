require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteCredentialDataService
  include ResponseDataHelper

  CREDENTIAL_API_PATH = '/api/1/msf/credential'
  # "MDM_CLASS" is a little misleading since it is not in that repo but trying to keep naming consistent across DataServices
  CREDENTIAL_MDM_CLASS = 'Metasploit::Credential::Core'

  def creds(opts = {})
    json_to_mdm_object(self.get_data(CREDENTIAL_API_PATH, opts), CREDENTIAL_MDM_CLASS, [])
  end

  def create_credential(opts)
    self.post_data_async(CREDENTIAL_API_PATH, opts)
  end
end