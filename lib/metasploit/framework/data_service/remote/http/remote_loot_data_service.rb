require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteLootDataService
  include ResponseDataHelper

  LOOT_API_PATH = '/api/v1/loots'
  LOOT_MDM_CLASS = 'Mdm::Loot'

  def loot(opts = {})
    path = get_path_select(opts, LOOT_API_PATH)
    data = self.get_data(path, nil, opts)
    rv = json_to_mdm_object(data, LOOT_MDM_CLASS)
    parsed_body = JSON.parse(data.response.body, symbolize_names: true)
    data = parsed_body[:data]
    data.each do |loot|
      # TODO: Add an option to toggle whether the file data is returned or not
      if loot[:data] && !loot[:data].empty?
        local_path = File.join(Msf::Config.loot_directory, File.basename(loot[:path]))
        rv[data.index(loot)].path = process_file(loot[:data], local_path)
      end
      if loot[:host]
        host_object = to_ar(RemoteHostDataService::HOST_MDM_CLASS.constantize, loot[:host])
        rv[data.index(loot)].host = host_object
      end
    end
    rv
  end

  def report_loot(opts)
    self.post_data_async(LOOT_API_PATH, opts)
  end

  def update_loot(opts)
    path = LOOT_API_PATH
    if opts && opts[:id]
      id = opts.delete(:id)
      path = "#{LOOT_API_PATH}/#{id}"
    end
    json_to_mdm_object(self.put_data(path, opts), LOOT_MDM_CLASS)
  end

  def delete_loot(opts)
    json_to_mdm_object(self.delete_data(LOOT_API_PATH, opts), LOOT_MDM_CLASS)
  end
end