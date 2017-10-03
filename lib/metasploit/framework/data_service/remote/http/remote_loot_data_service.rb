require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteLootDataService
  include ResponseDataHelper

  LOOT_PATH = '/api/1/msf/loot'

  def loot(opts = {})
    json_to_open_struct_object(self.get_data(LOOT_PATH, opts), [])
  end

  def report_loot(opts)
    self.post_data_async(LOOT_PATH, opts)
  end

  def find_or_create_loot(opts)
    json_to_open_struct_object(self.post_data(LOOT_PATH, opts))
  end

  def report_loots(loot)
    self.post_data(LOOT_PATH, loot)
  end
end