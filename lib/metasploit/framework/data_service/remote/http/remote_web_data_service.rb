require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteWebDataService
  include ResponseDataHelper

  WEB_API_PATH = '/api/v1/webs'

  def report_web_site(opts)
    self.post_data_async(WEB_API_PATH, opts)
  end
end