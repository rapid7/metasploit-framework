require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteLootDataService
  include ResponseDataHelper

  NMAP_PATH = '/api/1/msf/nmap'

  def import_nmap_xml_file(args)
    self.post_data_async(NMAP_PATH, args)
  end
end