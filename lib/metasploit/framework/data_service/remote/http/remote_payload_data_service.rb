require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemotePayloadDataService
  include ResponseDataHelper

  PAYLOAD_API_PATH = '/api/v1/payloads'
  PAYLOAD_MDM_CLASS = 'Mdm::Payload'

  def payloads(opts)
    path = get_path_select(opts, PAYLOAD_API_PATH)
    json_to_mdm_object(self.get_data(path, nil, opts), PAYLOAD_MDM_CLASS)
  end

  def create_payload(opts)
    json_to_mdm_object(self.post_data(PAYLOAD_API_PATH, opts), PAYLOAD_MDM_CLASS).first
  end

  def update_payload(opts)
    path = PAYLOAD_API_PATH
    if opts && opts[:id]
      id = opts.delete(:id)
      path = "#{PAYLOAD_API_PATH}/#{id}"
    end
    json_to_mdm_object(self.put_data(path, opts), PAYLOAD_MDM_CLASS)
  end

  def delete_payload(opts)
    json_to_mdm_object(self.delete_data(PAYLOAD_API_PATH, opts), PAYLOAD_MDM_CLASS)
  end
end
