module Msf::DBManager::Session
  require 'msf/core/db_manager/session/event'
  include Msf::DBManager::Session::Event

  require 'msf/core/db_manager/session/route'
  include Msf::DBManager::Session::Route

  # Returns a session based on opened_time, host address, and workspace
  # (or returns nil)
  def get_session(opts)
    with_connection {
      wspace = opts[:workspace] || opts[:wspace] || workspace
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
  #     Mdm::ExploitAttempt and Mdm::Vuln.  Defaults to Mdm::Workspace with
  #     Mdm::Workspace#name equal to `session.workspace`.
  #   @return [nil] if {Msf::DBManager::Connection#connected?} is `false`.
  #   @return [Mdm::Session] if session is saved
  #   @raise [ArgumentError] if :session is not an {Msf::Session}.
  #   @raise [ActiveRecord::RecordInvalid] if session is invalid and cannot be
  #     saved, in which case, the Mdm::ExploitAttempt and Mdm::Vuln will not be
  #     created, but the Mdm::Host will have been.   (There is no transaction
  #       to rollback the Mdm::Host creation.)
  #   @see #find_or_create_host
  #   @see #normalize_host
  #   @see #report_exploit_success
  #   @see #report_vuln
  #
  # @overload report_session(opts)
  #   Creates an Mdm::Session from Mdm::Host.
  #
  #   @param opts [Hash{Symbol => Object}] options
  #   @option opts [DateTime, Time] :closed_at The date and time the sesion was
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
  #   @return [nil] if {Msf::DBManager::Connection#connected?} is `false`.
  #   @return [Mdm::Session] if session is saved.
  #   @raise [ArgumentError] if :host is not an Mdm::Host.
  #   @raise [ActiveRecord::RecordInvalid] if session is invalid and cannot be
  #     saved.
  #
  # @raise ArgumentError if :host and :session is +nil+
  def report_session(opts)
    with_connection {
      if opts[:session]
        raise ArgumentError.new("Invalid :session, expected Msf::Session") unless opts[:session].kind_of? Msf::Session
        session = opts[:session]
        wspace = opts[:workspace] || find_workspace(session.workspace)
        h_opts = { }
        h_opts[:host]      = normalize_host(session)
        h_opts[:arch]      = session.arch if session.respond_to?(:arch) and session.arch
        h_opts[:workspace] = wspace
        host = find_or_create_host(h_opts)
        sess_data = {
            :host_id     => host.id,
            :stype       => session.type,
            :desc        => session.info,
            :platform    => session.platform,
            :via_payload => session.via_payload,
            :via_exploit => session.via_exploit,
            :routes      => [],
            :datastore   => session.exploit_datastore.to_h,
            :port        => session.session_port,
            :opened_at   => Time.now.utc,
            :last_seen   => Time.now.utc,
            :local_id    => session.sid
        }
      elsif opts[:host]
        raise ArgumentError.new("Invalid :host, expected Host object") unless opts[:host].kind_of? ::Mdm::Host
        host = opts[:host]
        sess_data = {
            :host_id => host.id,
            :stype => opts[:stype],
            :desc => opts[:desc],
            :platform => opts[:platform],
            :via_payload => opts[:via_payload],
            :via_exploit => opts[:via_exploit],
            :routes => opts[:routes] || [],
            :datastore => opts[:datastore],
            :opened_at => opts[:opened_at],
            :closed_at => opts[:closed_at],
            :last_seen => opts[:last_seen] || opts[:closed_at],
            :close_reason => opts[:close_reason],
        }
      else
        raise ArgumentError.new("Missing option :session or :host")
      end
      ret = {}

      # Truncate the session data if necessary
      if sess_data[:desc]
        sess_data[:desc] = sess_data[:desc][0,255]
      end

      # In the case of multi handler we cannot yet determine the true
      # exploit responsible. But we can at least show the parent versus
      # just the generic handler:
      if session and session.via_exploit == "exploit/multi/handler" and sess_data[:datastore]['ParentModule']
        sess_data[:via_exploit] = sess_data[:datastore]['ParentModule']
      end

      s = ::Mdm::Session.new(sess_data)
      s.save!

      if session and session.exploit_task and session.exploit_task.record
        session_task =  session.exploit_task.record
        if session_task.class == Mdm::Task
          Mdm::TaskSession.create(:task => session_task, :session => s )
        end
      end


      if opts[:session]
        session.db_record = s
      end

      # If this is a live session, we know the host is vulnerable to something.
      if opts[:session] and session.via_exploit
        mod = framework.modules.create(session.via_exploit)

        if session.via_exploit == "exploit/multi/handler" and sess_data[:datastore]['ParentModule']
          mod_fullname = sess_data[:datastore]['ParentModule']
          mod_name = ::Mdm::Module::Detail.find_by_fullname(mod_fullname).name
        else
          mod_name = mod.name
          mod_fullname = mod.fullname
        end

        vuln_info = {
            :host => host.address,
            :name => mod_name,
            :refs => mod.references,
            :workspace => wspace,
            :exploited_at => Time.now.utc,
            :info => "Exploited by #{mod_fullname} to create Session #{s.id}"
        }

        port    = session.exploit_datastore["RPORT"]
        service = (port ? host.services.find_by_port(port.to_i) : nil)

        vuln_info[:service] = service if service

        vuln = framework.db.report_vuln(vuln_info)

        if session.via_exploit == "exploit/multi/handler" and sess_data[:datastore]['ParentModule']
          via_exploit = sess_data[:datastore]['ParentModule']
        else
          via_exploit = session.via_exploit
        end
        attempt_info = {
            :timestamp   => Time.now.utc,
            :workspace   => wspace,
            :module      => via_exploit,
            :username    => session.username,
            :refs        => mod.references,
            :session_id  => s.id,
            :host        => host,
            :service     => service,
            :vuln        => vuln
        }

        framework.db.report_exploit_success(attempt_info)

      end

      s
    }
  end
end