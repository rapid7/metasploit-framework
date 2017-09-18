require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteLootDataService
  include ResponseDataHelper

  LOOT_PATH = '/api/1/msf/loot'
  LOOT_SEARCH_PATH = LOOT_PATH + "/search"

  def loot(opts)
    json_to_open_struct_object(self.get_data(LOOT_PATH, opts), [])
  end

  def report_loot(opts)
    self.post_data_async(LOOT_PATH, opts)
  end

  def find_or_create_loot(opts)
    json_to_open_struct_object(self.post_data(LOOT_PATH, loot))
  end

  def report_loot(loot)
    self.post_data(LOOT_PATH, loot)
  end

  def do_host_search(search)
    response = self.post_data(LOOT_SEARCH_PATH, search)
    return response.body
  end
end