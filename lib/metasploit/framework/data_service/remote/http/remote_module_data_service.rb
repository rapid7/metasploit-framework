require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteModuleDataService
  include ResponseDataHelper

  MODULE_API_PATH = '/api/v1/modules'

  def modules(opts)
    json_to_hash(self.get_data(MODULE_API_PATH, nil, opts))
  end

end