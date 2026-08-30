require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteDbImportDataService
  include ResponseDataHelper

  DB_IMPORT_API_PATH = '/api/v1/db-import'

  def import_file(opts)
    filename = opts[:filename]
    data = ""
    File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end

    opts[:data] = Base64.urlsafe_encode64(data)

    self.post_data_async(DB_IMPORT_API_PATH, opts)
  end
end
