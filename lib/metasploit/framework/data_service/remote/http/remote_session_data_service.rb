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
    session = opts[:session]
    if (session.kind_of? Msf::Session)
      opts = convert_msf_session_to_hash(session)
      opts[:session_dto] = true
    elsif (opts[:host])
      opts[:host] = opts[:host].address
    end

    opts[:time_stamp] = Time.now.utc
    sess_db = json_to_mdm_object(self.post_data(SESSION_API_PATH, opts), SESSION_MDM_CLASS, []).first
    session.db_record = sess_db
  end

  #######
  private
  #######

  # TODO: handle task info
  def convert_msf_session_to_hash(msf_session)
    hash = Hash.new()
    hash[:host_data] = parse_host_opts(msf_session)
    hash[:session_data] = parse_session_data(msf_session)

    if (msf_session.via_exploit)
      hash[:vuln_info] = parse_vuln_info(msf_session)
    end

    return hash
  end

  def parse_session_data(msf_session)
    hash = Hash.new()
    # TODO: what to do with this shiz
    hash[:datastore] = msf_session.exploit_datastore.to_h
    hash[:desc] = msf_session.info
    hash[:local_id] = msf_session.sid
    hash[:platform] = msf_session.session_type
    hash[:port] = msf_session.session_port
    hash[:stype] = msf_session.type
    hash[:via_exploit] = msf_session.via_exploit
    hash[:via_payload] = msf_session.via_payload
    return hash
  end

  def parse_host_opts(msf_session)
    hash = Hash.new()
    hash[:host] = msf_session.session_host
    hash[:arch] = msf_session.arch if msf_session.respond_to?(:arch) and msf_session.arch
    hash[:workspace] = msf_session.workspace || msf_session[:workspace]
    return hash
  end

  def parse_vuln_info(msf_session)
    hash = Hash.new()
    if msf_session.via_exploit == "exploit/multi/handler" and msf_session.exploit_datastore['ParentModule']
      hash[:mod_fullname] = msf_session.exploit_datastore['ParentModule']
    else
      hash[:mod_fullname] = msf_session.via_exploit
    end

    hash[:remote_port] = msf_session.exploit_datastore["RPORT"]
    hash[:username] = msf_session.username
    hash[:run_id] = msf_session.exploit.user_data.try(:[], :run_id)

    hash[:mod_name] = msf_session.exploit.name
    hash[:mod_references] = msf_session.exploit.references
    return hash
  end
end

