require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteVulnDataService
  include ResponseDataHelper

  VULN_API_PATH = '/api/v1/vulns'
  VULN_MDM_CLASS = 'Mdm::Vuln'

  def vulns(opts)
    path = get_path_select(opts, VULN_API_PATH)
    json_to_mdm_object(self.get_data(path, nil, opts), VULN_MDM_CLASS)
  end

  def report_vuln(opts)
    json_to_mdm_object(self.post_data(VULN_API_PATH, opts), VULN_MDM_CLASS).first
  end

  def update_vuln(opts)
    path = VULN_API_PATH
    if opts && opts[:id]
      id = opts.delete(:id)
      path = "#{VULN_API_PATH}/#{id}"
    end
    json_to_mdm_object(self.put_data(path, opts), VULN_MDM_CLASS)
  end

  def delete_vuln(opts)
    json_to_mdm_object(self.delete_data(VULN_API_PATH, opts), VULN_MDM_CLASS)
  end
end