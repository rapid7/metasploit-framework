module SessionDataProxy
  def sessions(opts={})
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.sessions(opts)
      end
    rescue => e
      self.log_error(e, "Problem retrieving sessions")
    end
  end

  def report_session(opts)
    begin
      self.data_service_operation do |data_service|
        add_opts_workspace(opts)
        data_service.report_session(opts)
      end
    rescue => e
      self.log_error(e, "Problem reporting session")
    end
  end

  # TODO: handle task info
  def self.convert_msf_session_to_hash(msf_session)
    hash = Hash.new()
    hash[:host_data] = parse_host_opts(msf_session)
    hash[:session_data] = parse_session_data(msf_session)

    if (msf_session.via_exploit)
      hash[:vuln_info] = parse_vuln_info(msf_session)
    end

    return hash
  end

  #######
  private
  #######

  def self.parse_session_data(msf_session)
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

  def self.parse_host_opts(msf_session)
    hash = Hash.new()
    hash[:host] = msf_session.session_host
    hash[:arch] = msf_session.arch if msf_session.respond_to?(:arch) and msf_session.arch
    hash[:workspace] = msf_session.workspace || msf_session[:workspace]
    return hash
  end

  def self.parse_vuln_info(msf_session)
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




