module Msf::DBManager::Session

  #
  # Returns a list of all sessions in the database that are selected
  # via the key-value pairs in the specified options.
  #
  def sessions(opts)
    return if not active

    ::ActiveRecord::Base.connection_pool.with_connection {
      # If we have the ID, there is no point in creating a complex query.
      if opts[:id] && !opts[:id].to_s.empty?
        return Array.wrap(Mdm::Session.find(opts[:id]))
      end

      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)

      search_term = opts.delete(:search_term)
      if search_term && !search_term.empty?
        column_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Mdm::Session, search_term)
        wspace.sessions.includes(:host).where(opts).where(column_search_conditions)
      else
        wspace.sessions.includes(:host).where(opts)
      end
    }
  end

  # Returns a session based on opened_time, host address, and workspace
  # (or returns nil)
  def get_session(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
    addr   = opts[:addr] || opts[:address] || opts[:host] || return
    host = get_host(:workspace => wspace, :host => addr)
    time = opts[:opened_at] || opts[:created_at] || opts[:time] || return
    ::Mdm::Session.find_by_host_id_and_opened_at(host.id, time)
  }
  end

  # @note The Mdm::Session#desc will be truncated to 255 characters.
  # @todo https://www.pivotaltracker.com/story/show/48249739
  #
  # @overload report_session(opts)
  #   Creates an Mdm::Session from Msf::Session. If +via_exploit+ is set on the
  #   +session+, then an Mdm::Vuln and Mdm::ExploitAttempt is created for the
  #   session's host.  The Mdm::Host for the +session_host+ is created using
  #   The session.session_host, +session.arch+ (if +session+ responds to arch),
  #   and the workspace derived from opts or the +session+.  The Mdm::Session is
  #   assumed to be +last_seen+ and +opened_at+ at the time report_session is
  #   called.  +session.exploit_datastore['ParentModule']+ is used for the
  #   Mdm::Session#via_exploit if +session.via_exploit+ is
  #   'exploit/multi/handler'.
  #
  #   @param opts [Hash{Symbol => Object}] options
  #   @option opt [Msf::Session, #datastore, #platform, #type, #via_exploit, #via_payload] :session
  #     The in-memory session to persist to the database.
  #   @option opts [Mdm::Workspace] :workspace The workspace for in which the
  #     :session host is contained.  Also used as the workspace for the
  #     Mdm::ExploitAttempt and Mdm::Vuln.  Defaults to Mdm::Worksapce with
  #     Mdm::Workspace#name equal to +session.workspace+.
  #   @return [nil] if Msf::DBManager#active is +false+.
  #   @return [Mdm::Session] if session is saved
  #   @raise [ArgumentError] if :session is not an {Msf::Session}.
  #   @raise [ActiveRecord::RecordInvalid] if session is invalid and cannot be
  #     saved, in which case, the Mdm::ExploitAttempt and Mdm::Vuln will not be
  #     created, but the Mdm::Host will have been.   (There is no transaction
  #       to rollback the Mdm::Host creation.)
  #   @see #find_or_create_host
  #   @see #Msf::Util::Host.normalize_host
  #   @see #report_exploit_success
  #   @see #report_vuln
  #
  # @overload report_session(opts)
  #   Creates an Mdm::Session from Mdm::Host.
  #
  #   @param opts [Hash{Symbol => Object}] options
  #   @option opts [DateTime, Time] :closed_at The date and time the session was
  #     closed.
  #   @option opts [String] :close_reason Reason the session was closed.
  #   @option opts [Hash] :datastore {Msf::DataStore#to_h}.
  #   @option opts [String] :desc Session description.  Will be truncated to 255
  #     characters.
  #   @option opts [Mdm::Host] :host The host on which the session was opened.
  #   @option opts [DateTime, Time] :last_seen The last date and time the
  #     session was seen to be open.  Defaults to :closed_at's value.
  #   @option opts [DateTime, Time] :opened_at The date and time that the
  #     session was opened.
  #   @option opts [String] :platform The platform of the host.
  #   @option opts [Array] :routes ([]) The routes through the session for
  #     pivoting.
  #   @option opts [String] :stype Session type.
  #   @option opts [String] :via_exploit The {Msf::Module#fullname} of the
  #     exploit that was used to open the session.
  #   @option option [String] :via_payload the {MSf::Module#fullname} of the
  #     payload sent to the host when the exploit was successful.
  #   @return [nil] if Msf::DBManager#active is +false+.
  #   @return [Mdm::Session] if session is saved.
  #   @raise [ArgumentError] if :host is not an Mdm::Host.
  #   @raise [ActiveRecord::RecordInvalid] if session is invalid and cannot be
  #     saved.
  #
  # @raise ArgumentError if :host and :session are both +nil+
  def report_session(opts)
    return if not active

  ::ActiveRecord::Base.connection_pool.with_connection {
    if opts[:session]
      session = opts[:session]
      s = create_mdm_session_from_session(opts)
      session.db_record = s
    elsif opts[:host]
      s = create_mdm_session_from_host(opts)
    else
      raise ArgumentError.new("Missing option :session or :host")
    end

    wspace = s.workspace


    if session and session.via_exploit
      # This is a live session, we know the host is vulnerable to something.
      infer_vuln_from_session(session, wspace)
    end

    s
  }
  end

  def report_session_host_dto(host_dto)
    host_dto[:host] = get_host(host_dto)
    create_mdm_session_from_host(host_dto)
  end

  def report_session_dto(session_dto)
    return if not active

    ::ActiveRecord::Base.connection_pool.with_connection {
      host_data = session_dto[:host_data]
      workspace = workspaces({ name: host_data[:workspace] }).first
      h_opts = {
        host: host_data[:host],
        workspace: workspace
      }
      h_opts[:arch] = host_data[:arch] if !host_data[:arch].nil? && !host_data[:arch].empty?
      host = find_or_create_host(h_opts)

      session_data = session_dto[:session_data]
      sess_data = {
          datastore: session_data[:datastore],
          desc: session_data[:desc],
          host_id: host.id,
          last_seen: session_dto[:time_stamp],
          local_id: session_data[:local_id],
          opened_at: session_dto[:time_stamp],
          platform: session_data[:platform],
          port: session_data[:port],
          routes: [],
          stype: session_data[:stype],
          via_exploit: session_data[:via_exploit],
          via_payload: session_data[:via_payload],
      }

      if sess_data[:via_exploit] == 'exploit/multi/handler' and sess_data[:datastore] and sess_data[:datastore]['ParentModule']
        sess_data[:via_exploit] = sess_data[:datastore]['ParentModule']
      end

      session_db_record = ::Mdm::Session.create!(sess_data)

      # TODO: Figure out task stuff


      if sess_data[:via_exploit]
        # This is a live session, we know the host is vulnerable to something.
        infer_vuln_from_session_dto(session_dto, session_db_record, workspace)
      end
      session_db_record
    }
  end

  # Clean out any stale sessions that have been orphaned by a dead framework instance.
  # @param last_seen_interval [Integer] interval, in seconds, open sessions are marked as alive
  def remove_stale_sessions(last_seen_interval)
    return unless active

    ::ActiveRecord::Base.connection_pool.with_connection {
      ::Mdm::Session.where(closed_at: nil).each do |db_session|
        next unless db_session.last_seen.nil? or ((Time.now.utc - db_session.last_seen) > (2 * last_seen_interval))
        db_session.closed_at    = db_session.last_seen || Time.now.utc
        db_session.close_reason = "Orphaned"
        db_session.save
      end
    }
  end

  #########
  protected
  #########

  # @param session [Msf::Session] A session with a db_record Msf::Session#db_record
  # @param wspace [Mdm::Workspace]
  # @return [void]
  def infer_vuln_from_session(session, wspace)
    ::ActiveRecord::Base.connection_pool.with_connection {
      s = session.db_record
      host = s.host

      if session.via_exploit == "exploit/multi/handler" and session.exploit_datastore['ParentModule']
        mod_fullname = session.exploit_datastore['ParentModule']
      else
        mod_fullname = session.via_exploit
      end
      mod_detail = ::Mdm::Module::Detail.find_by_fullname(mod_fullname)

      if mod_detail.nil?
        # Then the cache isn't built yet, take the hit for instantiating the
        # module
        mod_detail = framework.modules.create(mod_fullname)
        refs = mod_detail.references
      else
        refs = mod_detail.refs
      end
      mod_name = mod_detail.name

      vuln_info = {
        exploited_at: Time.now.utc,
        host: host,
        info: "Exploited by #{mod_fullname} to create Session #{s.id}",
        name: mod_name,
        refs: refs,
        workspace: wspace,
      }

      port    = session.exploit_datastore["RPORT"]
      service = (port ? host.services.find_by_port(port.to_i) : nil)

      vuln_info[:service] = service if service

      vuln = report_vuln(vuln_info)

      attempt_info = {
        host: host,
        module: mod_fullname,
        refs: refs,
        service: service,
        session_id: s.id,
        timestamp: Time.now.utc,
        username: session.username,
        vuln: vuln,
        workspace: wspace,
        run_id: session.exploit.user_data.try(:[], :run_id)
      }

      report_exploit_success(attempt_info)

      vuln
    }
  end

  def create_mdm_session_from_session(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      session = opts[:session]
      raise ArgumentError.new("Invalid :session, expected Msf::Session") unless session.kind_of? Msf::Session

      wspace = opts[:workspace] || find_workspace(session.workspace)
      h_opts = {
        host: Msf::Util::Host.normalize_host(session),
        workspace: wspace
      }
      h_opts[:arch] = session.arch if session.respond_to?(:arch) && !session.arch.nil? && !session.arch.empty?

      host = find_or_create_host(h_opts)
      sess_data = {
        datastore: session.exploit_datastore.to_h,
        desc: session.info,
        host_id: host.id,
        last_seen: Time.now.utc,
        local_id: session.sid,
        opened_at: Time.now.utc,
        platform: session.session_type,
        port: session.session_port,
        routes: [],
        stype: session.type,
        via_exploit: session.via_exploit,
        via_payload: session.via_payload,
      }

      # In the case of exploit/multi/handler we cannot yet determine the true
      # exploit responsible. But we can at least show the parent versus
      # just the generic handler:
      if session.via_exploit == "exploit/multi/handler" and sess_data[:datastore]['ParentModule']
        sess_data[:via_exploit] = sess_data[:datastore]['ParentModule']
      end

      s = ::Mdm::Session.create!(sess_data)

      if session.exploit_task and session.exploit_task.record
        session_task = session.exploit_task.record
        if session_task.class == Mdm::Task
          Mdm::TaskSession.create(task: session_task, session: s )
        end
      end

      s
    }
  end

  def create_mdm_session_from_host(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      host = opts[:host]
      raise ArgumentError.new("Invalid :host, expected Host object") unless host.kind_of? ::Mdm::Host
      sess_data = {
        host_id: host.id,
        stype: opts[:stype],
        desc: opts[:desc],
        platform: opts[:platform],
        via_payload: opts[:via_payload],
        via_exploit: opts[:via_exploit],
        routes: opts[:routes] || [],
        datastore: opts[:datastore],
        opened_at: opts[:opened_at],
        closed_at: opts[:closed_at],
        last_seen: opts[:last_seen] || opts[:closed_at],
        close_reason: opts[:close_reason],
      }


      s = ::Mdm::Session.create!(sess_data)
      s
    }
  end

  def infer_vuln_from_session_dto(session_dto, session_db_record, workspace)
    ::ActiveRecord::Base.connection_pool.with_connection {

      vuln_info_dto = session_dto[:vuln_info]
      host = session_db_record.host
      mod_name = vuln_info_dto[:mod_name] || 'unknown'
      refs = vuln_info_dto[:mod_references] || []

      vuln_info = {
          exploited_at: session_dto[:time_stamp],
          host: host,
          info: "Exploited by #{vuln_info_dto[:mod_fullname]} to create Session #{session_db_record.id}",
          name: mod_name,
          refs: refs,
          workspace: workspace,
      }

      port    = vuln_info_dto[:remote_port]
      service = (port ? host.services.find_by_port(port.to_i) : nil)

      vuln_info[:service] = service if service

      vuln = report_vuln(vuln_info)

      attempt_info = {
          host: host,
          module: vuln_info_dto[:mod_fullname],
          refs: refs,
          service: service,
          session_id: session_db_record.id,
          timestamp: session_dto[:time_stamp],
          username: vuln_info_dto[:username],
          vuln: vuln,
          workspace: workspace,
          run_id: vuln_info_dto[:run_id]
      }

      report_exploit_success(attempt_info)

      vuln
    }
  end
end
