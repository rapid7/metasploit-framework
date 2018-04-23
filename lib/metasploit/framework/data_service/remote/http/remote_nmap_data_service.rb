require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteNmapDataService
  include ResponseDataHelper

  NMAP_PATH = '/api/v1/nmaps'

  def import_nmap_xml_file(opts)
    filename = opts[:filename]
    data = ""
    File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end

    opts[:data] = Base64.urlsafe_encode64(data)

    self.post_data(NMAP_PATH, opts)
  end
end