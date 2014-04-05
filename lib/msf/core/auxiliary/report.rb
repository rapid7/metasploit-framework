# -*- coding: binary -*-
module Msf

###
#
# This module provides methods for reporting data to the DB
#
###

module Auxiliary::Report


  def initialize(info = {})
    super
  end

  # Shortcut method for detecting when the DB is active
  def db
    framework.db.active
  end

  def myworkspace
    @myworkspace = framework.db.find_workspace(self.workspace)
  end

  def mytask
    if self[:task]
      return self[:task].record
    elsif @task && @task.class == Mdm::Task
      return @task
    else
      return nil
    end
  end

  def inside_workspace_boundary?(ip)
    return true if not framework.db.active
    allowed = myworkspace.allow_actions_on?(ip)
    return allowed
  end



  #
  # Report a host's liveness and attributes such as operating system and service pack
  #
  # opts must contain :host, which is an IP address identifying the host
  # you're reporting about
  #
  # See data/sql/*.sql and lib/msf/core/db.rb for more info
  #
  def report_host(opts)
    return if not db
    opts = {
      :workspace => myworkspace,
      :task => mytask
    }.merge(opts)
    framework.db.report_host(opts)
  end

  def get_host(opts)
    return if not db
    opts = {:workspace => myworkspace}.merge(opts)
    framework.db.get_host(opts)
  end

  #
  # Report a client connection
  #
  # opts must contain
  #	:host      the address of the client connecting
  #	:ua_string a string that uniquely identifies this client
  # opts can contain
  #	:ua_name a brief identifier for the client, e.g. "Firefox"
  #	:ua_ver  the version number of the client, e.g. "3.0.11"
  #
  def report_client(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_client(opts)
  end

  def get_client(opts={})
    return if not db
    opts = {:workspace => myworkspace}.merge(opts)
    framework.db.get_client(opts)
  end

  #
  # Report detection of a service
  #
  def report_service(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_service(opts)
  end

  def report_note(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_note(opts)
  end

  def report_auth_info(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_auth_info(opts)
  end

  def report_vuln(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_vuln(opts)
  end

  # This will simply log a deprecation warning, since report_exploit()
  # is no longer implemented.
  def report_exploit(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_exploit(opts)
  end

  def report_loot(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_loot(opts)
  end

  def report_web_site(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_web_site(opts)
  end

  def report_web_page(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_web_page(opts)
  end

  def report_web_form(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_web_form(opts)
  end

  def report_web_vuln(opts={})
    return if not db
    opts = {
        :workspace => myworkspace,
        :task => mytask
    }.merge(opts)
    framework.db.report_web_vuln(opts)
  end

  #
  # Store some data stolen from a session as a file
  #
  # Also stores metadata about the file in the database when available
  # +ltype+ is an OID-style loot type, e.g. "cisco.ios.config".  Ignored when
  # no database is connected.
  #
  # +ctype+ is the Content-Type, e.g. "text/plain".  Affects the extension
  # the file will be saved with.
  #
  # +host+ can be an String address or a Session object
  #
  # +data+ is the actual contents of the file
  #
  # +filename+ and +info+ are only stored as metadata, and therefore both are
  # ignored if there is no database
  #
  def store_loot(ltype, ctype, host, data, filename=nil, info=nil, service=nil)
    if ! ::File.directory?(Msf::Config.loot_directory)
      FileUtils.mkdir_p(Msf::Config.loot_directory)
    end

    ext = 'bin'
    if filename
      parts = filename.to_s.split('.')
      if parts.length > 1 and parts[-1].length < 4
        ext = parts[-1]
      end
    end

    case ctype
    when "text/plain"
      ext = "txt"
    end
    # This method is available even if there is no database, don't bother checking
    host = framework.db.normalize_host(host)

    ws = (db ? myworkspace.name[0,16] : 'default')
    name =
      Time.now.strftime("%Y%m%d%H%M%S") + "_" + ws + "_" +
      (host || 'unknown') + '_' + ltype[0,16] + '_' +
      Rex::Text.rand_text_numeric(6) + '.' + ext

    name.gsub!(/[^a-z0-9\.\_]+/i, '')

    path = File.join(Msf::Config.loot_directory, name)
    full_path = ::File.expand_path(path)
    File.open(full_path, "wb") do |fd|
      fd.write(data)
    end

    if (db)
      # If we have a database we need to store it with all the available
      # metadata.
      conf = {}
      conf[:host] = host if host
      conf[:type] = ltype
      conf[:content_type] = ctype
      conf[:path] = full_path
      conf[:workspace] = myworkspace
      conf[:name] = filename if filename
      conf[:info] = info if info

      if service and service.kind_of?(::Mdm::Service)
        conf[:service] = service if service
      end

      framework.db.report_loot(conf)
    end

    return full_path.dup
  end

  #
  # Store some locally-generated data as a file, similiar to store_loot.
  # Sometimes useful for keeping artifacts of an exploit or auxiliary
  # module, such as files from fileformat exploits. (TODO: actually
  # implement this on file format modules.)
  #
  # +filenmae+ is the local file name.
  #
  # +data+ is the actual contents of the file
  #
  # Also stores metadata about the file in the database when available.
  # +ltype+ is an OID-style loot type, e.g. "cisco.ios.config".  Ignored when
  # no database is connected.
  #
  # +ctype+ is the Content-Type, e.g. "text/plain". Ignored when no database
  # is connected.
  #
  def store_local(ltype=nil, ctype=nil, data=nil, filename=nil)
    if ! ::File.directory?(Msf::Config.local_directory)
      FileUtils.mkdir_p(Msf::Config.local_directory)
    end

    # Split by fname an extension
    if filename and not filename.empty?
      if filename =~ /(.*)\.(.*)/
        ext = $2
        fname = $1
      else
        fname = filename
      end
    else
      fname = ctype || "local_#{Time.now.utc.to_i}"
    end

    # Split by path seperator
    fname = ::File.split(fname).last

    case ctype # Probably could use more cases
    when "text/plain"
      ext ||= "txt"
    when "text/xml"
      ext ||= "xml"
    when "text/html"
      ext ||= "html"
    when "application/pdf"
      ext ||= "pdf"
    else
      ext ||= "bin"
    end

    fname.gsub!(/[^a-z0-9\.\_\-]+/i, '')
    fname << ".#{ext}"

    ltype.gsub!(/[^a-z0-9\.\_\-]+/i, '')

    path = File.join(Msf::Config.local_directory, fname)
    full_path = ::File.expand_path(path)
    File.open(full_path, "wb") { |fd| fd.write(data) }

    # This will probably evolve into a new database table
    report_note(
      :data => full_path.dup,
      :type => "#{ltype}.localpath"
    )

    return full_path.dup
  end

  # Takes a credential from a script (shell or meterpreter), and
  # sources it correctly to the originating user account or
  # session. Note that the passed-in session ID should be the
  # Session.local_id, which will be correlated with the Session.id
  def store_cred(opts={})
    if [opts[:port],opts[:sname]].compact.empty?
      raise ArgumentError, "Missing option: :sname or :port"
    end
    cred_opts = opts
    cred_opts = opts.merge(:workspace => myworkspace)
    cred_host = myworkspace.hosts.find_by_address(cred_opts[:host])
    unless opts[:port]
      possible_services = myworkspace.services.find_all_by_host_id_and_name(cred_host[:id],cred_opts[:sname])
      case possible_services.size
      when 0
        case cred_opts[:sname].downcase
        when "smb"
          cred_opts[:port] = 445
        when "ssh"
          cred_opts[:port] = 22
        when "telnet"
          cred_opts[:port] = 23
        when "snmp"
          cred_opts[:port] = 161
          cred_opts[:proto] = "udp"
        else
          raise ArgumentError, "No matching :sname found to store this cred."
        end
      when 1
        cred_opts[:port] = possible_services.first[:port]
      else # SMB should prefer 445. Everyone else, just take the first hit.
        if (cred_opts[:sname].downcase == "smb") && possible_services.map {|x| x[:port]}.include?(445)
          cred_opts[:port] = 445
        elsif (cred_opts[:sname].downcase == "ssh") && possible_services.map {|x| x[:port]}.include?(22)
          cred_opts[:port] = 22
        else
          cred_opts[:port] = possible_services.first[:port]
        end
      end
    end
    if opts[:collect_user]
      cred_service = cred_host.services.find_by_host_id(cred_host[:id])
      myworkspace.creds.sort {|a,b| a.created_at.to_f}.each do |cred|
        if(cred.user.downcase == opts[:collect_user].downcase &&
           cred.pass == opts[:collect_pass]
          )
          cred_opts[:source_id] ||= cred.id
          cred_opts[:source_type] ||= cred_opts[:collect_type]
          break
        end
      end
    end
    if opts[:collect_session]
      session = myworkspace.sessions.find_all_by_local_id(opts[:collect_session]).last
      if !session.nil?
        cred_opts[:source_id] = session.id
        cred_opts[:source_type] = "exploit"
      end
    end
    print_status "Collecting #{cred_opts[:user]}:#{cred_opts[:pass]}"
    framework.db.report_auth_info(cred_opts)
  end
end
end

