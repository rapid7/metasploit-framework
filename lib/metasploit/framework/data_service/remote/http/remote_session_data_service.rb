require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteSessionDataService
  include ResponseDataHelper

  SESSION_API_PATH = '/api/v1/sessions'
  SESSION_MDM_CLASS = 'Mdm::Session'

  def sessions(opts)
    path = get_path_select(opts, SESSION_API_PATH)
    json_to_mdm_object(self.get_data(path, nil, opts), SESSION_MDM_CLASS, [])
  end

  def report_session(opts)
    $stderr.puts("RemoteSessionDataService.report_session(): opts=#{opts}")  # TODO: remove
    session = opts[:session]
    if (session.kind_of? Msf::Session)
      opts = SessionDataProxy.convert_msf_session_to_hash(session)
    elsif (opts[:host])
      $stderr.puts("*** RemoteSessionDataService.report_session(): executing path where session is not a kind_of Msf::Session...")  # TODO: remove
      opts[:host] = opts[:host].address
    end

    opts[:time_stamp] = Time.now.utc
    $stderr.puts("RemoteSessionDataService.report_session(): opts=#{opts}")  # TODO: remove
    sess_db = json_to_mdm_object(self.post_data(SESSION_API_PATH, opts), SESSION_MDM_CLASS, []).first
    if !sess_db.nil?
      $stderr.puts("RemoteSessionDataService.report_session(): sess_db=#{sess_db}, sess_db.id=#{sess_db.id}")  # TODO: remove
    else
      $stderr.puts("RemoteSessionDataService.report_session(): sess_db is nil")  # TODO: remove
    end
    session.db_record = sess_db
  end

  def update_session(opts)
    path = SESSION_API_PATH
    if opts && opts[:id]
      id = opts.delete(:id)
      path = "#{SESSION_API_PATH}/#{id}"
    end

    $stderr.puts("RemoteSessionDataService.update_session(): path=#{path}, opts=#{opts}")  # TODO: remove

    sess_db = json_to_mdm_object(self.put_data(path, opts), SESSION_MDM_CLASS, []).first
    $stderr.puts("RemoteSessionDataService.update_session(): returning... sess_db=#{sess_db}")  # TODO: remove

    sess_db
  end

end
