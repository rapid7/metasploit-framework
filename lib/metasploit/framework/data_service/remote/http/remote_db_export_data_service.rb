require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteDbExportDataService
  include ResponseDataHelper

  DB_EXPORT_API_PATH = '/api/v1/db-export'

  def run_db_export(opts)
    response = json_to_hash(self.get_data(DB_EXPORT_API_PATH, nil, opts))

    process_file(response[:db_export_file], opts[:path])
  end
end
