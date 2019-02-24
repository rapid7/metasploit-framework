require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteCredentialDataService
  include ResponseDataHelper

  CREDENTIAL_API_PATH = '/api/v1/credentials'
  # "MDM_CLASS" is a little misleading since it is not in that repo but trying to keep naming consistent across DataServices
  CREDENTIAL_MDM_CLASS = 'Metasploit::Credential::Core'

  def creds(opts = {})
    data = self.get_data(CREDENTIAL_API_PATH, opts)
    rv = json_to_mdm_object(data, CREDENTIAL_MDM_CLASS, [])
    parsed_body = JSON.parse(data.response.body)
    parsed_body.each do |cred|
      private_object = to_ar(cred['private_class'].constantize, cred['private'])
      rv[parsed_body.index(cred)].private = private_object
    end
    rv
  end

  def create_credential(opts)
    self.post_data_async(CREDENTIAL_API_PATH, opts)
  end
end