require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteVulnAttemptDataService
  include ResponseDataHelper

  VULN_ATTEMPT_API_PATH = '/api/v1/vuln-attempts'
  VULN_ATTEMPT_MDM_CLASS = 'Mdm::VulnAttempt'

  def vuln_attempts(opts)
    path = get_path_select(opts, VULN_ATTEMPT_API_PATH)
    json_to_mdm_object(self.get_data(path, nil, opts), VULN_ATTEMPT_MDM_CLASS)
  end

  def report_vuln_attempt(vuln, opts)
    opts[:vuln_id] = vuln.id
    json_to_mdm_object(self.post_data(VULN_ATTEMPT_API_PATH, opts), VULN_ATTEMPT_MDM_CLASS).first
  end
end