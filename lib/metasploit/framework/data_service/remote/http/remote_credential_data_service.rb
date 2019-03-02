require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteCredentialDataService
  include ResponseDataHelper

  CREDENTIAL_API_PATH = '/api/v1/credentials'
  # "MDM_CLASS" is a little misleading since it is not in that repo but trying to keep naming consistent across DataServices
  CREDENTIAL_MDM_CLASS = 'Metasploit::Credential::Core'

  def creds(opts = {})
    path = get_path_select(opts, CREDENTIAL_API_PATH)
    data = self.get_data(path, nil, opts)
    rv = json_to_mdm_object(data, CREDENTIAL_MDM_CLASS, [])
    parsed_body = JSON.parse(data.response.body, symbolize_names: true)
    data = parsed_body[:data]
    data.each do |cred|
      if cred[:public]
        public_object = to_ar(cred[:public][:type].constantize, cred[:public])
        rv[data.index(cred)].public = public_object
      end
      if cred[:private]
        private_object = to_ar(cred[:private][:type].constantize, cred[:private])
        rv[data.index(cred)].private = private_object
      end
      if cred[:origin]
        origin_object = to_ar(cred[:origin][:type].constantize, cred[:origin])
        rv[data.index(cred)].origin = origin_object
      end
    end
    rv
  end

  def create_credential(opts)
    json_to_mdm_object(self.post_data(CREDENTIAL_API_PATH, opts), CREDENTIAL_MDM_CLASS, []).first
  end

  def update_credential(opts)
    json_to_mdm_object(self.put_data(CREDENTIAL_API_PATH, opts), CREDENTIAL_MDM_CLASS, []).first
  end

  def delete_credentials(opts)
    json_to_mdm_object(self.delete_data(CREDENTIAL_API_PATH, opts), CREDENTIAL_MDM_CLASS, [])
  end
end
