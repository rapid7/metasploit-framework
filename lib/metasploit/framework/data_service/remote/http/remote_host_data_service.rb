require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteHostDataService
  include ResponseDataHelper

  HOST_PATH = '/api/1/msf/host'
  HOST_SEARCH_PATH = HOST_PATH + "/search"

  def hosts(opts)
    json_to_open_struct_object(self.get_data(opts, HOST_PATH), [])
  end

  def report_host(opts)
    self.post_data_async(opts, HOST_PATH)
  end

  def find_or_create_host(opts)
    json_to_open_struct_object(self.post_data(host, HOST_PATH))
  end

  def report_hosts(hosts)
    self.post_data(hosts, HOST_PATH)
  end

  def do_host_search(search)
    response = self.post_data(search, HOST_SEARCH_PATH)
    return response.body
  end
end