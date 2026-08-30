require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteMsfDataService
  include ResponseDataHelper

  MSF_API_PATH = '/api/v1/msf'
  MSF_VERSION_API_PATH = "#{MSF_API_PATH}/version"

  def get_msf_version
    json_to_hash(self.get_data(MSF_VERSION_API_PATH, nil, nil))
  end
end