require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteHostDataService
  include ResponseDataHelper

  HOST_API_PATH = '/api/v1/hosts'
  HOST_SEARCH_PATH = HOST_API_PATH + "/search"
  HOST_MDM_CLASS = 'Mdm::Host'

  def hosts(opts)
    json_to_mdm_object(self.get_data(HOST_API_PATH, nil, opts), HOST_MDM_CLASS, [])
  end

  def report_host(opts)
    json_to_mdm_object(self.post_data(HOST_API_PATH, opts), HOST_MDM_CLASS, []).first
  end

  def find_or_create_host(opts)
    json_to_mdm_object(self.post_data(HOST_API_PATH, opts), HOST_MDM_CLASS, []).first
  end

  def report_hosts(hosts)
    self.post_data(HOST_API_PATH, hosts)
  end

  def update_host(opts)
    path = HOST_API_PATH
    if opts && opts[:id]
      id = opts.delete(:id)
      path = "#{HOST_API_PATH}/#{id}"
    end
    json_to_mdm_object(self.put_data(path, opts), HOST_MDM_CLASS, [])
  end

  def delete_host(opts)
    json_to_mdm_object(self.delete_data(HOST_API_PATH, opts), HOST_MDM_CLASS, [])
  end

  # TODO: Remove? What is the purpose of this method?
  def do_host_search(search)
    response = self.post_data(HOST_SEARCH_PATH, search)
    return response.body
  end
end