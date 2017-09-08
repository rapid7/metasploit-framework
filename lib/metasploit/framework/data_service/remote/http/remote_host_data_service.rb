require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteHostDataService
  include ResponseDataHelper

  HOST_PATH = '/api/1/msf/host'
  HOST_SEARCH_PATH = HOST_PATH + "/search"

  def hosts(opts)
    json_to_open_struct_object(self.get_data(HOST_PATH, opts), [])
  end

  def report_host(opts)
    self.post_data_async(HOST_PATH, opts)
  end

  def find_or_create_host(opts)
    json_to_open_struct_object(self.post_data(HOST_PATH, host))
  end

  def report_hosts(hosts)
    self.post_data(HOST_PATH, hosts)
  end

  def do_host_search(search)
    response = self.post_data(HOST_SEARCH_PATH, search)
    return response.body
  end
end