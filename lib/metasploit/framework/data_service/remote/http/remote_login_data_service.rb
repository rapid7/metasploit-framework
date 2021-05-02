require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteLoginDataService
  include ResponseDataHelper

  LOGIN_API_PATH = '/api/v1/logins'
  # "MDM_CLASS" is a little misleading since it is not in that repo but trying to keep naming consistent across DataServices
  LOGIN_MDM_CLASS = 'Metasploit::Credential::Login'

  def logins(opts)
    path = get_path_select(opts, LOGIN_API_PATH)
    json_to_mdm_object(self.get_data(path, nil, opts), LOGIN_MDM_CLASS)
  end

  def create_credential_login(opts)
    json_to_mdm_object(self.post_data(LOGIN_API_PATH, opts), LOGIN_MDM_CLASS).first
  end

  def update_login(opts)
    path = LOGIN_API_PATH
    if opts && opts[:id]
      id = opts.delete(:id)
      path = "#{LOGIN_API_PATH}/#{id}"
    end
    json_to_mdm_object(self.put_data(path, opts), LOGIN_MDM_CLASS).first
  end
end