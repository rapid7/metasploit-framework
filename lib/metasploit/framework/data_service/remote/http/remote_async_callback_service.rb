require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteAsyncCallbackDataService
  include ResponseDataHelper

  ASYNC_CALLBACK_API_PATH = '/api/v1/async-callbacks'
  ASYNC_CALLBACK_MDM_CLASS = 'Mdm::AsyncCallback'

  def async_callbacks(opts)
    path = get_path_select(opts, ASYNC_CALLBACK_API_PATH)
    json_to_mdm_object(self.get_data(path, nil, opts), ASYNC_CALLBACK_MDM_CLASS, [])
  end

  def create_async_callback(opts)
    json_to_mdm_object(self.post_data(ASYNC_CALLBACK_API_PATH, opts), ASYNC_CALLBACK_MDM_CLASS, []).first
  end

  def update_async_callback(opts)
    path = ASYNC_CALLBACK_API_PATH
    if opts && opts[:id]
      id = opts.delete(:id)
      path = "#{ASYNC_CALLBACK_API_PATH}/#{id}"
    end
    json_to_mdm_object(self.put_data(path, opts), ASYNC_CALLBACK_MDM_CLASS, [])
  end

  def delete_async_callback(opts)
    json_to_mdm_object(self.delete_data(ASYNC_CALLBACK_API_PATH, opts), ASYNC_CALLBACK_MDM_CLASS, [])
  end
end
