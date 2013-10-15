# -*- coding: binary -*-

#
# Standard Library
#

require 'csv'
require 'tmpdir'
require 'uri'
require 'zip'

#
#
# Gems
#
#

#
# PacketFu
#

require 'packetfu'

#
# Rex
#


require 'rex/socket'

# Check Rex::Parser.nokogiri_loaded for status of the Nokogiri parsers
require 'rex/parser/acunetix_nokogiri'
require 'rex/parser/appscan_nokogiri'
require 'rex/parser/burp_session_nokogiri'
require 'rex/parser/ci_nokogiri'
require 'rex/parser/foundstone_nokogiri'
require 'rex/parser/fusionvm_nokogiri'
require 'rex/parser/mbsa_nokogiri'
require 'rex/parser/nexpose_raw_nokogiri'
require 'rex/parser/nexpose_simple_nokogiri'
require 'rex/parser/nmap_nokogiri'
require 'rex/parser/openvas_nokogiri'
require 'rex/parser/wapiti_nokogiri'

# Legacy XML parsers -- these will be converted some day
require 'rex/parser/ip360_aspl_xml'
require 'rex/parser/ip360_xml'
require 'rex/parser/nessus_xml'
require 'rex/parser/netsparker_xml'
require 'rex/parser/nexpose_xml'
require 'rex/parser/nmap_xml'
require 'rex/parser/retina_xml'

#
# Project
#

require 'msf/core/db_manager/import_msf_xml'

module Msf

###
#
# The states that a host can be in.
#
###
module HostState
  #
  # The host is alive.
  #
  Alive   = "alive"
  #
  # The host is dead.
  #
  Dead    = "down"
  #
  # The host state is unknown.
  #
  Unknown = "unknown"
end

###
#
# The states that a service can be in.
#
###
module ServiceState
  Open      = "open"
  Closed    = "closed"
  Filtered  = "filtered"
  Unknown   = "unknown"
end

###
#
# Events that can occur in the host/service database.
#
###
module DatabaseEvent

  #
  # Called when an existing host's state changes
  #
  def on_db_host_state(host, ostate)
  end

  #
  # Called when an existing service's state changes
  #
  def on_db_service_state(host, port, ostate)
  end

  #
  # Called when a new host is added to the database.  The host parameter is
  # of type Host.
  #
  def on_db_host(host)
  end

  #
  # Called when a new client is added to the database.  The client
  # parameter is of type Client.
  #
  def on_db_client(client)
  end

  #
  # Called when a new service is added to the database.  The service
  # parameter is of type Service.
  #
  def on_db_service(service)
  end

  #
  # Called when an applicable vulnerability is found for a service.  The vuln
  # parameter is of type Vuln.
  #
  def on_db_vuln(vuln)
  end

  #
  # Called when a new reference is created.
  #
  def on_db_ref(ref)
  end

end

class DBImportError < RuntimeError
end

###
#
# The DB module ActiveRecord definitions for the DBManager
#
###
class DBManager
  include Msf::DBManager::ImportMsfXml

  def rfc3330_reserved(ip)
    case ip.class.to_s
    when "PacketFu::Octets"
      ip_x = ip.to_x
      ip_i = ip.to_i
    when "String"
      if ipv46_validator(ip)
        ip_x = ip
        ip_i = Rex::Socket.addr_atoi(ip)
      else
        raise ArgumentError, "Invalid IP address: #{ip.inspect}"
      end
    when "Fixnum"
      if (0..2**32-1).include? ip
        ip_x = Rex::Socket.addr_itoa(ip)
        ip_i = ip
      else
        raise ArgumentError, "Invalid IP address: #{ip.inspect}"
      end
    else
      raise ArgumentError, "Invalid IP address: #{ip.inspect}"
    end
    return true if Rex::Socket::RangeWalker.new("0.0.0.0-0.255.255.255").include? ip_x
    return true if Rex::Socket::RangeWalker.new("127.0.0.0-127.255.255.255").include? ip_x
    return true if Rex::Socket::RangeWalker.new("169.254.0.0-169.254.255.255").include? ip_x
    return true if Rex::Socket::RangeWalker.new("224.0.0.0-239.255.255.255").include? ip_x
    return true if Rex::Socket::RangeWalker.new("255.255.255.255-255.255.255.255").include? ip_x
    return false
  end

  def ipv46_validator(addr)
    ipv4_validator(addr) or ipv6_validator(addr)
  end

  def ipv4_validator(addr)
    return false unless addr.kind_of? String
    Rex::Socket.is_ipv4?(addr)
  end

  def ipv6_validator(addr)
    Rex::Socket.is_ipv6?(addr)
  end

  # Takes a space-delimited set of ips and ranges, and subjects
  # them to RangeWalker for validation. Returns true or false.
  def validate_ips(ips)
    ret = true
    begin
      ips.split(/\s+/).each {|ip|
        unless Rex::Socket::RangeWalker.new(ip).ranges
          ret = false
          break
        end
        }
    rescue
      ret = false
    end
    return ret
  end


  #
  # Determines if the database is functional
  #
  def check
  ::ActiveRecord::Base.connection_pool.with_connection {
    res = ::Mdm::Host.find(:first)
  }
  end


  def default_workspace
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::Workspace.default
  }
  end

  def find_workspace(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::Workspace.find_by_name(name)
  }
  end

  #
  # Creates a new workspace in the database
  #
  def add_workspace(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::Workspace.find_or_create_by_name(name)
  }
  end

  def workspaces
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::Workspace.find(:all)
  }
  end

  #
  # Wait for all pending write to finish
  #
  def sync
    # There is no more queue.
  end

  #
  # Find a host.  Performs no database writes.
  #
  def get_host(opts)
    if opts.kind_of? ::Mdm::Host
      return opts
    elsif opts.kind_of? String
      raise RuntimeError, "This invokation of get_host is no longer supported: #{caller}"
    else
      address = opts[:addr] || opts[:address] || opts[:host] || return
      return address if address.kind_of? ::Mdm::Host
    end
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    if wspace.kind_of? String
      wspace = find_workspace(wspace)
    end

    address = normalize_host(address)
    return wspace.hosts.find_by_address(address)
  }
  end

  #
  # Exactly like report_host but waits for the database to create a host and returns it.
  #
  def find_or_create_host(opts)
    report_host(opts)
  end

  #
  # Report a host's attributes such as operating system and service pack
  #
  # The opts parameter MUST contain
  # +:host+::         -- the host's ip address
  #
  # The opts parameter can contain:
  # +:state+::        -- one of the Msf::HostState constants
  # +:os_name+::      -- one of the Msf::OperatingSystems constants
  # +:os_flavor+::    -- something like "XP" or "Gentoo"
  # +:os_sp+::        -- something like "SP2"
  # +:os_lang+::      -- something like "English", "French", or "en-US"
  # +:arch+::         -- one of the ARCH_* constants
  # +:mac+::          -- the host's MAC address
  # +:scope+::        -- interface identifier for link-local IPv6
  # +:virtual_host+:: -- the name of the VM host software, eg "VMWare", "QEMU", "Xen", etc.
  #
  def report_host(opts)

    return if not active
    addr = opts.delete(:host) || return

    # Sometimes a host setup through a pivot will see the address as "Remote Pipe"
    if addr.eql? "Remote Pipe"
      return
    end

  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    if wspace.kind_of? String
      wspace = find_workspace(wspace)
    end

    ret = { }

    if not addr.kind_of? ::Mdm::Host
      addr = normalize_host(addr)
      addr, scope = addr.split('%', 2)
      opts[:scope] = scope if scope

      unless ipv46_validator(addr)
        raise ::ArgumentError, "Invalid IP address in report_host(): #{addr}"
      end

      if opts[:comm] and opts[:comm].length > 0
        host = wspace.hosts.find_or_initialize_by_address_and_comm(addr, opts[:comm])
      else
        host = wspace.hosts.find_or_initialize_by_address(addr)
      end
    else
      host = addr
    end

    # Truncate the info field at the maximum field length
    if opts[:info]
      opts[:info] = opts[:info][0,65535]
    end

    # Truncate the name field at the maximum field length
    if opts[:name]
      opts[:name] = opts[:name][0,255]
    end

    opts.each { |k,v|
      if (host.attribute_names.include?(k.to_s))
        unless host.attribute_locked?(k.to_s)
          host[k] = v.to_s.gsub(/[\x00-\x1f]/n, '')
        end
      else
        dlog("Unknown attribute for ::Mdm::Host: #{k}")
      end
    }
    host.info = host.info[0,::Mdm::Host.columns_hash["info"].limit] if host.info

    # Set default fields if needed
    host.state       = HostState::Alive if not host.state
    host.comm        = ''        if not host.comm
    host.workspace   = wspace    if not host.workspace

    if host.changed?
      msf_import_timestamps(opts,host)
      host.save!
    end

    if opts[:task]
      Mdm::TaskHost.create(
          :task => opts[:task],
          :host => host
      )
    end

    host
  }
  end


  #
  # Update a host's attributes via semi-standardized sysinfo hash (Meterpreter)
  #
  # The opts parameter MUST contain the following entries
  # +:host+::           -- the host's ip address
  # +:info+::           -- the information hash
  # * 'Computer'        -- the host name
  # * 'OS'              -- the operating system string
  # * 'Architecture'    -- the hardware architecture
  # * 'System Language' -- the system language
  #
  # The opts parameter can contain:
  # +:workspace+::      -- the workspace for this host
  #
  def update_host_via_sysinfo(opts)

    return if not active
    addr = opts.delete(:host) || return
    info = opts.delete(:info) || return

    # Sometimes a host setup through a pivot will see the address as "Remote Pipe"
    if addr.eql? "Remote Pipe"
      return
    end

  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    if wspace.kind_of? String
      wspace = find_workspace(wspace)
    end

    if not addr.kind_of? ::Mdm::Host
      addr = normalize_host(addr)
      addr, scope = addr.split('%', 2)
      opts[:scope] = scope if scope

      unless ipv46_validator(addr)
        raise ::ArgumentError, "Invalid IP address in report_host(): #{addr}"
      end

      if opts[:comm] and opts[:comm].length > 0
        host = wspace.hosts.find_or_initialize_by_address_and_comm(addr, opts[:comm])
      else
        host = wspace.hosts.find_or_initialize_by_address(addr)
      end
    else
      host = addr
    end

    res = {}

    if info['Computer']
      res[:name] = info['Computer']
    end

    if info['Architecture']
      res[:arch] = info['Architecture'].split(/\s+/).first
    end

    if info['OS'] =~ /^Windows\s*([^\(]+)\(([^\)]+)\)/i
      res[:os_name]   = "Microsoft Windows"
      res[:os_flavor] = $1.strip
      build = $2.strip

      if build =~ /Service Pack (\d+)/
        res[:os_sp] = "SP" + $1
      else
        res[:os_sp] = "SP0"
      end
    end

    if info["System Language"]
      case info["System Language"]
        when /^en_/
          res[:os_lang] = "English"
      end
    end


    # Truncate the info field at the maximum field length
    if res[:info]
      res[:info] = res[:info][0,65535]
    end

    # Truncate the name field at the maximum field length
    if res[:name]
      res[:name] = res[:name][0,255]
    end

    res.each { |k,v|

      if (host.attribute_names.include?(k.to_s))
        unless host.attribute_locked?(k.to_s)
          host[k] = v.to_s.gsub(/[\x00-\x1f]/n, '')
        end
      else
        dlog("Unknown attribute for Host: #{k}")
      end
    }

    # Set default fields if needed
    host.state       = HostState::Alive if not host.state
    host.comm        = ''        if not host.comm
    host.workspace   = wspace    if not host.workspace

    if host.changed?
      host.save!
    end

    host
  }
  end
  #
  # Iterates over the hosts table calling the supplied block with the host
  # instance of each entry.
  #
  def each_host(wspace=workspace, &block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.hosts.each do |host|
      block.call(host)
    end
  }
  end

  #
  # Returns a list of all hosts in the database
  #
  def hosts(wspace = workspace, only_up = false, addresses = nil)
  ::ActiveRecord::Base.connection_pool.with_connection {
    conditions = {}
    conditions[:state] = [Msf::HostState::Alive, Msf::HostState::Unknown] if only_up
    conditions[:address] = addresses if addresses
    wspace.hosts.where(conditions).order(:address)
  }
  end



  def find_or_create_service(opts)
    report_service(opts)
  end

  #
  # Record a service in the database.
  #
  # opts MUST contain
  # +:host+::  the host where this service is running
  # +:port+::  the port where this service listens
  # +:proto+:: the transport layer protocol (e.g. tcp, udp)
  #
  # opts may contain
  # +:name+::  the application layer protocol (e.g. ssh, mssql, smb)
  # +:sname+:: an alias for the above
  #
  def report_service(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection { |conn|
    addr  = opts.delete(:host) || return
    hname = opts.delete(:host_name)
    hmac  = opts.delete(:mac)
    host  = nil
    wspace = opts.delete(:workspace) || workspace
    hopts = {:workspace => wspace, :host => addr}
    hopts[:name] = hname if hname
    hopts[:mac]  = hmac  if hmac

    # Other report_* methods take :sname to mean the service name, so we
    # map it here to ensure it ends up in the right place despite not being
    # a real column.
    if opts[:sname]
      opts[:name] = opts.delete(:sname)
    end

    if addr.kind_of? ::Mdm::Host
      host = addr
      addr = host.address
    else
      host = report_host(hopts)
    end

    if opts[:port].to_i.zero?
      dlog("Skipping port zero for service '%s' on host '%s'" % [opts[:name],host.address])
      return nil
    end

    ret  = {}
=begin
    host = get_host(:workspace => wspace, :address => addr)
    if host
      host.updated_at = host.created_at
      host.state      = HostState::Alive
      host.save!
    end
=end

    proto = opts[:proto] || 'tcp'

    service = host.services.find_or_initialize_by_port_and_proto(opts[:port].to_i, proto)
    opts.each { |k,v|
      if (service.attribute_names.include?(k.to_s))
        service[k] = ((v and k == :name) ? v.to_s.downcase : v)
      else
        dlog("Unknown attribute for Service: #{k}")
      end
    }
    service.state ||= ServiceState::Open
    service.info  ||= ""

    if (service and service.changed?)
      msf_import_timestamps(opts,service)
      service.save!
    end

    if opts[:task]
      Mdm::TaskService.create(
          :task => opts[:task],
          :service => service
      )
    end

    ret[:service] = service
  }
  end

  def get_service(wspace, host, proto, port)
  ::ActiveRecord::Base.connection_pool.with_connection {
    host = get_host(:workspace => wspace, :address => host)
    return if not host
    return host.services.find_by_proto_and_port(proto, port)
  }
  end

  #
  # Iterates over the services table calling the supplied block with the
  # service instance of each entry.
  #
  def each_service(wspace=workspace, &block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    services(wspace).each do |service|
      block.call(service)
    end
  }
  end

  #
  # Returns a list of all services in the database
  #
  def services(wspace = workspace, only_up = false, proto = nil, addresses = nil, ports = nil, names = nil)
  ::ActiveRecord::Base.connection_pool.with_connection {
    conditions = {}
    conditions[:state] = [ServiceState::Open] if only_up
    conditions[:proto] = proto if proto
    conditions["hosts.address"] = addresses if addresses
    conditions[:port] = ports if ports
    conditions[:name] = names if names
    wspace.services.includes(:host).where(conditions).order("hosts.address, port")
  }
  end

  # Returns a session based on opened_time, host address, and workspace
  # (or returns nil)
  def get_session(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
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
  #     Mdm::ExploitAttempt and Mdm::Vuln.  Defaults to Mdm::Worksapce with
  #     Mdm::Workspace#name equal to +session.workspace+.
  #   @return [nil] if {Msf::DBManager#active} is +false+.
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
  #   @return [nil] if {Msf::DBManager#active} is +false+.
  #   @return [Mdm::Session] if session is saved.
  #   @raise [ArgumentError] if :host is not an Mdm::Host.
  #   @raise [ActiveRecord::RecordInvalid] if session is invalid and cannot be
  #     saved.
  #
  # @raise ArgumentError if :host and :session is +nil+
  def report_session(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
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

  #
  # Record a session event in the database
  #
  # opts MUST contain one of:
  # +:session+:: the Msf::Session OR the ::Mdm::Session we are reporting
  # +:etype+::   event type, enum: command, output, upload, download, filedelete
  #
  # opts may contain
  # +:output+::      the data for an output event
  # +:command+::     the data for an command event
  # +:remote_path+:: path to the associated file for upload, download, and filedelete events
  # +:local_path+::  path to the associated file for upload, and download
  #
  def report_session_event(opts)
    return if not active
    raise ArgumentError.new("Missing required option :session") if opts[:session].nil?
    raise ArgumentError.new("Expected an :etype") unless opts[:etype]
    session = nil

  ::ActiveRecord::Base.connection_pool.with_connection {
    if opts[:session].respond_to? :db_record
      session = opts[:session].db_record
      if session.nil?
        # The session doesn't have a db_record which means
        #  a) the database wasn't connected at session registration time
        # or
        #  b) something awful happened and the report_session call failed
        #
        # Either way, we can't do anything with this session as is, so
        # log a warning and punt.
        wlog("Warning: trying to report a session_event for a session with no db_record (#{opts[:session].sid})")
        return
      end
      event_data = { :created_at => Time.now }
    else
      session = opts[:session]
      event_data = { :created_at => opts[:created_at] }
    end

    event_data[:session_id] = session.id
    [:remote_path, :local_path, :output, :command, :etype].each do |attr|
      event_data[attr] = opts[attr] if opts[attr]
    end

    s = ::Mdm::SessionEvent.create(event_data)
  }
  end

  def report_session_route(session, route)
    return if not active
    if session.respond_to? :db_record
      s = session.db_record
    else
      s = session
    end
    unless s.respond_to?(:routes)
      raise ArgumentError.new("Invalid :session, expected Session object got #{session.class}")
    end

  ::ActiveRecord::Base.connection_pool.with_connection {

    subnet, netmask = route.split("/")
    s.routes.create(:subnet => subnet, :netmask => netmask)
  }
  end

  def report_session_route_remove(session, route)
    return if not active
    if session.respond_to? :db_record
      s = session.db_record
    else
      s = session
    end
    unless s.respond_to?(:routes)
      raise ArgumentError.new("Invalid :session, expected Session object got #{session.class}")
    end

  ::ActiveRecord::Base.connection_pool.with_connection {
    subnet, netmask = route.split("/")
    r = s.routes.find_by_subnet_and_netmask(subnet, netmask)
    r.destroy if r
  }
  end


  def report_exploit_success(opts)
  ::ActiveRecord::Base.connection_pool.with_connection {

    wspace = opts.delete(:workspace) || workspace
    mrefs  = opts.delete(:refs) || return
    host   = opts.delete(:host)
    port   = opts.delete(:port)
    prot   = opts.delete(:proto)
    svc    = opts.delete(:service)
    vuln   = opts.delete(:vuln)

    timestamp = opts.delete(:timestamp)
    username  = opts.delete(:username)
    mname     = opts.delete(:module)

    # Look up or generate the host as appropriate
    if not (host and host.kind_of? ::Mdm::Host)
      if svc.kind_of? ::Mdm::Service
        host = svc.host
      else
        host = report_host(:workspace => wspace, :address => host )
      end
    end

    # Bail if we dont have a host object
    return if not host

    # Look up or generate the service as appropriate
    if port and svc.nil?
      svc = report_service(:workspace => wspace, :host => host, :port => port, :proto => prot ) if port
    end

    if not vuln
      # Create a references map from the module list
      ref_objs = ::Mdm::Ref.where(:name => mrefs.map { |ref|
        if ref.respond_to?(:ctx_id) and ref.respond_to?(:ctx_val)
          "#{ref.ctx_id}-#{ref.ctx_val}"
        else
          ref.to_s
        end
      })

      # Try find a matching vulnerability
      vuln = find_vuln_by_refs(ref_objs, host, svc)
    end

    # We have match, lets create a vuln_attempt record
    if vuln
      attempt_info = {
        :vuln_id      => vuln.id,
        :attempted_at => timestamp || Time.now.utc,
        :exploited    => true,
        :username     => username  || "unknown",
        :module       => mname
      }

      attempt_info[:session_id] = opts[:session_id] if opts[:session_id]
      attempt_info[:loot_id]    = opts[:loot_id]    if opts[:loot_id]

      vuln.vuln_attempts.create(attempt_info)

      # Correct the vuln's associated service if necessary
      if svc and vuln.service_id.nil?
        vuln.service = svc
        vuln.save
      end
    end

    # Report an exploit attempt all the same
    attempt_info = {
      :attempted_at => timestamp || Time.now.utc,
      :exploited    => true,
      :username     => username  || "unknown",
      :module       => mname
    }

    attempt_info[:vuln_id]    = vuln.id           if vuln
    attempt_info[:session_id] = opts[:session_id] if opts[:session_id]
    attempt_info[:loot_id]    = opts[:loot_id]    if opts[:loot_id]

    if svc
      attempt_info[:port]  = svc.port
      attempt_info[:proto] = svc.proto
    end

    if port and svc.nil?
      attempt_info[:port]  = port
      attempt_info[:proto] = prot || "tcp"
    end

    host.exploit_attempts.create(attempt_info)
  }
  end

  def report_exploit_failure(opts)

  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    mrefs  = opts.delete(:refs) || return
    host   = opts.delete(:host)
    port   = opts.delete(:port)
    prot   = opts.delete(:proto)
    svc    = opts.delete(:service)
    vuln   = opts.delete(:vuln)

    timestamp  = opts.delete(:timestamp)
    freason    = opts.delete(:fail_reason)
    fdetail    = opts.delete(:fail_detail)
    username   = opts.delete(:username)
    mname      = opts.delete(:module)

    # Look up the host as appropriate
    if not (host and host.kind_of? ::Mdm::Host)
      if svc.kind_of? ::Mdm::Service
        host = svc.host
      else
        host = get_host( :workspace => wspace, :address => host )
      end
    end

    # Bail if we dont have a host object
    return if not host

    # Look up the service as appropriate
    if port and svc.nil?
      prot ||= "tcp"
      svc = get_service(wspace, host, prot, port) if port
    end

    if not vuln
      # Create a references map from the module list
      ref_objs = ::Mdm::Ref.where(:name => mrefs.map { |ref|
        if ref.respond_to?(:ctx_id) and ref.respond_to?(:ctx_val)
          "#{ref.ctx_id}-#{ref.ctx_val}"
        else
          ref.to_s
        end
      })

      # Try find a matching vulnerability
      vuln = find_vuln_by_refs(ref_objs, host, svc)
    end

    # Report a vuln_attempt if we found a match
    if vuln
      attempt_info = {
        :attempted_at => timestamp || Time.now.utc,
        :exploited    => false,
        :fail_reason  => freason,
        :fail_detail  => fdetail,
        :username     => username  || "unknown",
        :module       => mname
      }

      vuln.vuln_attempts.create(attempt_info)
    end

    # Report an exploit attempt all the same
    attempt_info = {
      :attempted_at => timestamp || Time.now.utc,
      :exploited    => false,
      :username     => username  || "unknown",
      :module       => mname,
      :fail_reason  => freason,
      :fail_detail  => fdetail
    }

    attempt_info[:vuln_id] = vuln.id if vuln

    if svc
      attempt_info[:port]  = svc.port
      attempt_info[:proto] = svc.proto
    end

    if port and svc.nil?
      attempt_info[:port]  = port
      attempt_info[:proto] = prot || "tcp"
    end

    host.exploit_attempts.create(attempt_info)
  }
  end


  def report_vuln_attempt(vuln, opts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    return if not vuln
    info = {}

    # Opts can be keyed by strings or symbols
    ::Mdm::VulnAttempt.column_names.each do |kn|
      k = kn.to_sym
      next if ['id', 'vuln_id'].include?(kn)
      info[k] = opts[kn] if opts[kn]
      info[k] = opts[k]  if opts[k]
    end

    return unless info[:attempted_at]

    vuln.vuln_attempts.create(info)
  }
  end

  def report_exploit_attempt(host, opts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    return if not host
    info = {}

    # Opts can be keyed by strings or symbols
    ::Mdm::VulnAttempt.column_names.each do |kn|
      k = kn.to_sym
      next if ['id', 'host_id'].include?(kn)
      info[k] = opts[kn] if opts[kn]
      info[k] = opts[k]  if opts[k]
    end

    host.exploit_attempts.create(info)
  }
  end

  def get_client(opts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    host   = get_host(:workspace => wspace, :host => opts[:host]) || return
    client = host.clients.where({:ua_string => opts[:ua_string]}).first()
    return client
  }
  end

  def find_or_create_client(opts)
    report_client(opts)
  end

  #
  # Report a client running on a host.
  #
  # opts MUST contain
  # +:ua_string+::  the value of the User-Agent header
  # +:host+::       the host where this client connected from, can be an ip address or a Host object
  #
  # opts can contain
  # +:ua_name+::    one of the Msf::HttpClients constants
  # +:ua_ver+::     detected version of the given client
  # +:campaign+::   an id or Campaign object
  #
  # Returns a Client.
  #
  def report_client(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    addr = opts.delete(:host) || return
    wspace = opts.delete(:workspace) || workspace
    report_host(:workspace => wspace, :host => addr)

    ret = {}

    host = get_host(:workspace => wspace, :host => addr)
    client = host.clients.find_or_initialize_by_ua_string(opts[:ua_string])

    opts[:ua_string] = opts[:ua_string].to_s

    campaign = opts.delete(:campaign)
    if campaign
      case campaign
      when Campaign
        opts[:campaign_id] = campaign.id
      else
        opts[:campaign_id] = campaign
      end
    end

    opts.each { |k,v|
      if (client.attribute_names.include?(k.to_s))
        client[k] = v
      else
        dlog("Unknown attribute for Client: #{k}")
      end
    }
    if (client and client.changed?)
      client.save!
    end
    ret[:client] = client
  }
  end

  #
  # This method iterates the vulns table calling the supplied block with the
  # vuln instance of each entry.
  #
  def each_vuln(wspace=workspace,&block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.vulns.each do |vulns|
      block.call(vulns)
    end
  }
  end

  #
  # This methods returns a list of all vulnerabilities in the database
  #
  def vulns(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.vulns
  }
  end

  #
  # This methods returns a list of all credentials in the database
  #
  def creds(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    Mdm::Cred.includes({:service => :host}).where("hosts.workspace_id = ?", wspace.id)
  }
  end

  #
  # This method returns a list of all exploited hosts in the database.
  #
  def exploited_hosts(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.exploited_hosts
  }
  end

  #
  # This method iterates the notes table calling the supplied block with the
  # note instance of each entry.
  #
  def each_note(wspace=workspace, &block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.notes.each do |note|
      block.call(note)
    end
  }
  end

  #
  # Find or create a note matching this type/data
  #
  def find_or_create_note(opts)
    report_note(opts)
  end

  #
  # Report a Note to the database.  Notes can be tied to a ::Mdm::Workspace, Host, or Service.
  #
  # opts MUST contain
  # +:type+::  The type of note, e.g. smb_peer_os
  #
  # opts can contain
  # +:workspace+::  the workspace to associate with this Note
  # +:host+::       an IP address or a Host object to associate with this Note
  # +:service+::    a Service object to associate with this Note
  # +:data+::       whatever it is you're making a note of
  # +:port+::       along with +:host+ and +:proto+, a service to associate with this Note
  # +:proto+::      along with +:host+ and +:port+, a service to associate with this Note
  # +:update+::     what to do in case a similar Note exists, see below
  #
  # The +:update+ option can have the following values:
  # +:unique+::       allow only a single Note per +:host+/+:type+ pair
  # +:unique_data+::  like +:uniqe+, but also compare +:data+
  # +:insert+::       always insert a new Note even if one with identical values exists
  #
  # If the provided +:host+ is an IP address and does not exist in the
  # database, it will be created.  If +:workspace+, +:host+ and +:service+
  # are all omitted, the new Note will be associated with the current
  # workspace.
  #
  def report_note(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    if wspace.kind_of? String
      wspace = find_workspace(wspace)
    end
    seen = opts.delete(:seen) || false
    crit = opts.delete(:critical) || false
    host = nil
    addr = nil
    # Report the host so it's there for the Proc to use below
    if opts[:host]
      if opts[:host].kind_of? ::Mdm::Host
        host = opts[:host]
      else
        addr = normalize_host(opts[:host])
        host = report_host({:workspace => wspace, :host => addr})
      end
      # Do the same for a service if that's also included.
      if (opts[:port])
        proto = nil
        sname = nil
        case opts[:proto].to_s.downcase # Catch incorrect usages
        when 'tcp','udp'
          proto = opts[:proto]
          sname = opts[:sname] if opts[:sname]
        when 'dns','snmp','dhcp'
          proto = 'udp'
          sname = opts[:proto]
        else
          proto = 'tcp'
          sname = opts[:proto]
        end
        sopts = {
          :workspace => wspace,
          :host  => host,
          :port  => opts[:port],
          :proto => proto
        }
        sopts[:name] = sname if sname
        report_service(sopts)
      end
    end
    # Update Modes can be :unique, :unique_data, :insert
    mode = opts[:update] || :unique

    ret = {}

    if addr and not host
      host = get_host(:workspace => wspace, :host => addr)
    end
    if host and (opts[:port] and opts[:proto])
      service = get_service(wspace, host, opts[:proto], opts[:port])
    elsif opts[:service] and opts[:service].kind_of? ::Mdm::Service
      service = opts[:service]
    end
=begin
    if host
      host.updated_at = host.created_at
      host.state      = HostState::Alive
      host.save!
    end
=end
    ntype  = opts.delete(:type) || opts.delete(:ntype) || (raise RuntimeError, "A note :type or :ntype is required")
    data   = opts[:data]
    method = nil
    args   = []
    note   = nil

    conditions = { :ntype => ntype }
    conditions[:host_id] = host[:id] if host
    conditions[:service_id] = service[:id] if service

    case mode
    when :unique
      notes = wspace.notes.where(conditions)

      # Only one note of this type should exist, make a new one if it
      # isn't there. If it is, grab it and overwrite its data.
      if notes.empty?
        note = wspace.notes.new(conditions)
      else
        note = notes[0]
      end
      note.data = data
    when :unique_data
      notes = wspace.notes.where(conditions)

      # Don't make a new Note with the same data as one that already
      # exists for the given: type and (host or service)
      notes.each do |n|
        # Compare the deserialized data from the table to the raw
        # data we're looking for.  Because of the serialization we
        # can't do this easily or reliably in SQL.
        if n.data == data
          note = n
          break
        end
      end
      if not note
        # We didn't find one with the data we're looking for, make
        # a new one.
        note = wspace.notes.new(conditions.merge(:data => data))
      end
    else
      # Otherwise, assume :insert, which means always make a new one
      note = wspace.notes.new
      if host
        note.host_id = host[:id]
      end
      if opts[:service] and opts[:service].kind_of? ::Mdm::Service
        note.service_id = opts[:service][:id]
      end
      note.seen     = seen
      note.critical = crit
      note.ntype    = ntype
      note.data     = data
    end
    msf_import_timestamps(opts,note)
    note.save!
    ret[:note] = note
  }
  end

  #
  # This methods returns a list of all notes in the database
  #
  def notes(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.notes
  }
  end

  # This is only exercised by MSF3 XML importing for now. Needs the wait
  # conditions and return hash as well.
  def report_host_tag(opts)
    name = opts.delete(:name)
    raise DBImportError.new("Missing required option :name") unless name
    addr = opts.delete(:addr)
    raise DBImportError.new("Missing required option :addr") unless addr
    wspace = opts.delete(:wspace)
    raise DBImportError.new("Missing required option :wspace") unless wspace
  ::ActiveRecord::Base.connection_pool.with_connection {
    if wspace.kind_of? String
      wspace = find_workspace(wspace)
    end

    host = nil
    report_host(:workspace => wspace, :address => addr)


    host = get_host(:workspace => wspace, :address => addr)
    desc = opts.delete(:desc)
    summary = opts.delete(:summary)
    detail = opts.delete(:detail)
    crit = opts.delete(:crit)
    possible_tags = Mdm::Tag.includes(:hosts).where("hosts.workspace_id = ? and tags.name = ?", wspace.id, name).order("tags.id DESC").limit(1)
    tag = (possible_tags.blank? ? Mdm::Tag.new : possible_tags.first)
    tag.name = name
    tag.desc = desc
    tag.report_summary = !!summary
    tag.report_detail = !!detail
    tag.critical = !!crit
    tag.hosts = tag.hosts | [host]
    tag.save! if tag.changed?
  }
  end

  #
  # Store a set of credentials in the database.
  #
  # report_auth_info used to create a note, now it creates
  # an entry in the creds table. It's much more akin to
  # report_vuln() now.
  #
  # opts MUST contain
  # +:host+::   an IP address or Host object reference
  # +:port+::   a port number
  #
  # opts can contain
  # +:user+::   the username
  # +:pass+::   the password, or path to ssh_key
  # +:ptype+::  the type of password (password(ish), hash, or ssh_key)
  # +:proto+::  a transport name for the port
  # +:sname+::  service name
  # +:active+:: by default, a cred is active, unless explicitly false
  # +:proof+::  data used to prove the account is actually active.
  #
  # Sources: Credentials can be sourced from another credential, or from
  # a vulnerability. For example, if an exploit was used to dump the
  # smb_hashes, and this credential comes from there, the source_id would
  # be the Vuln id (as reported by report_vuln) and the type would be "Vuln".
  #
  # +:source_id+::   The Vuln or Cred id of the source of this cred.
  # +:source_type+:: Either Vuln or Cred
  #
  # TODO: This is written somewhat host-centric, when really the
  # Service is the thing. Need to revisit someday.
  def report_auth_info(opts={})
    return if not active
    raise ArgumentError.new("Missing required option :host") if opts[:host].nil?
    raise ArgumentError.new("Missing required option :port") if (opts[:port].nil? and opts[:service].nil?)

    if (not opts[:host].kind_of?(::Mdm::Host)) and (not validate_ips(opts[:host]))
      raise ArgumentError.new("Invalid address or object for :host (#{opts[:host].inspect})")
    end

  ::ActiveRecord::Base.connection_pool.with_connection {
    host = opts.delete(:host)
    ptype = opts.delete(:type) || "password"
    token = [opts.delete(:user), opts.delete(:pass)]
    sname = opts.delete(:sname)
    port = opts.delete(:port)
    proto = opts.delete(:proto) || "tcp"
    proof = opts.delete(:proof)
    source_id = opts.delete(:source_id)
    source_type = opts.delete(:source_type)
    duplicate_ok = opts.delete(:duplicate_ok)
    # Nil is true for active.
    active = (opts[:active] || opts[:active].nil?) ? true : false

    wspace = opts.delete(:workspace) || workspace

    # Service management; assume the user knows what
    # he's talking about.
    service = opts.delete(:service) || report_service(:host => host, :port => port, :proto => proto, :name => sname, :workspace => wspace)

    # Non-US-ASCII usernames are tripping up the database at the moment, this is a temporary fix until we update the tables
    if (token[0])
      # convert the token to US-ASCII from UTF-8 to prevent an error
      token[0] = token[0].unpack("C*").pack("C*")
      token[0] = token[0].gsub(/[\x00-\x1f\x7f-\xff]/n){|m| "\\x%.2x" % m.unpack("C")[0] }
    end

    if (token[1])
      token[1] = token[1].unpack("C*").pack("C*")
      token[1] = token[1].gsub(/[\x00-\x1f\x7f-\xff]/n){|m| "\\x%.2x" % m.unpack("C")[0] }
    end

    ret = {}

    # Check to see if the creds already exist. We look also for a downcased username with the
    # same password because we can fairly safely assume they are not in fact two seperate creds.
    # this allows us to hedge against duplication of creds in the DB.

    if duplicate_ok
    # If duplicate usernames are okay, find by both user and password (allows
    # for actual duplicates to get modified updated_at, sources, etc)
      if token[0].nil? or token[0].empty?
        cred = service.creds.find_or_initialize_by_user_and_ptype_and_pass(token[0] || "", ptype, token[1] || "")
      else
        cred = service.creds.find_by_user_and_ptype_and_pass(token[0] || "", ptype, token[1] || "")
        unless cred
          dcu = token[0].downcase
          cred = service.creds.find_by_user_and_ptype_and_pass( dcu || "", ptype, token[1] || "")
          unless cred
            cred = service.creds.find_or_initialize_by_user_and_ptype_and_pass(token[0] || "", ptype, token[1] || "")
          end
        end
      end
    else
      # Create the cred by username only (so we can change passwords)
      if token[0].nil? or token[0].empty?
        cred = service.creds.find_or_initialize_by_user_and_ptype(token[0] || "", ptype)
      else
        cred = service.creds.find_by_user_and_ptype(token[0] || "", ptype)
        unless cred
          dcu = token[0].downcase
          cred = service.creds.find_by_user_and_ptype_and_pass( dcu || "", ptype, token[1] || "")
          unless cred
            cred = service.creds.find_or_initialize_by_user_and_ptype(token[0] || "", ptype)
          end
        end
      end
    end

    # Update with the password
    cred.pass = (token[1] || "")

    # Annotate the credential
    cred.ptype = ptype
    cred.active = active

    # Update the source ID only if there wasn't already one.
    if source_id and !cred.source_id
      cred.source_id = source_id
      cred.source_type = source_type if source_type
    end

    # Safe proof (lazy way) -- doesn't chop expanded
    # characters correctly, but shouldn't ever be a problem.
    unless proof.nil?
      proof = Rex::Text.to_hex_ascii(proof)
      proof = proof[0,4096]
    end
    cred.proof = proof

    # Update the timestamp
    if cred.changed?
      msf_import_timestamps(opts,cred)
      cred.save!
    end

    # Ensure the updated_at is touched any time report_auth_info is called
    # except when it's set explicitly (as it is for imports)
    unless opts[:updated_at] || opts["updated_at"]
      cred.updated_at = Time.now.utc
      cred.save!
    end


    if opts[:task]
      Mdm::TaskCred.create(
          :task => opts[:task],
          :cred => cred
      )
    end

    ret[:cred] = cred
  }
  end

  alias :report_cred :report_auth_info
  alias :report_auth :report_auth_info

  #
  # Find or create a credential matching this type/data
  #
  def find_or_create_cred(opts)
    report_auth_info(opts)
  end

  #
  # This method iterates the creds table calling the supplied block with the
  # cred instance of each entry.
  #
  def each_cred(wspace=workspace,&block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.creds.each do |cred|
      block.call(cred)
    end
  }
  end

  def each_exploited_host(wspace=workspace,&block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.exploited_hosts.each do |eh|
      block.call(eh)
    end
  }
  end

  #
  # Find or create a vuln matching this service/name
  #
  def find_or_create_vuln(opts)
    report_vuln(opts)
  end

  #
  # opts MUST contain
  # +:host+:: the host where this vulnerability resides
  # +:name+:: the friendly name for this vulnerability (title)
  #
  # opts can contain
  # +:info+::   a human readable description of the vuln, free-form text
  # +:refs+::   an array of Ref objects or string names of references
  # +:details:: a hash with :key pointed to a find criteria hash and the rest containing VulnDetail fields
  #
  def report_vuln(opts)
    return if not active
    raise ArgumentError.new("Missing required option :host") if opts[:host].nil?
    raise ArgumentError.new("Deprecated data column for vuln, use .info instead") if opts[:data]
    name = opts[:name] || return
    info = opts[:info]

  ::ActiveRecord::Base.connection_pool.with_connection {

    wspace = opts.delete(:workspace) || workspace
    exploited_at = opts[:exploited_at] || opts["exploited_at"]
    details = opts.delete(:details)
    rids = opts.delete(:ref_ids)

    if opts[:refs]
      rids ||= []
      opts[:refs].each do |r|
        if (r.respond_to?(:ctx_id)) and (r.respond_to?(:ctx_val))
          r = "#{r.ctx_id}-#{r.ctx_val}"
        end
        rids << find_or_create_ref(:name => r)
      end
    end

    host = nil
    addr = nil
    if opts[:host].kind_of? ::Mdm::Host
      host = opts[:host]
    else
      host = report_host({:workspace => wspace, :host => opts[:host]})
      addr = normalize_host(opts[:host])
    end

    ret = {}

    # Truncate the info field at the maximum field length
    if info
      info = info[0,65535]
    end

    # Truncate the name field at the maximum field length
    name = name[0,255]

    # Placeholder for the vuln object
    vuln = nil

    # Identify the associated service
    service = opts.delete(:service)

    # Treat port zero as no service
    if service or opts[:port].to_i > 0

      if not service
        proto = nil
        case opts[:proto].to_s.downcase # Catch incorrect usages, as in report_note
        when 'tcp','udp'
          proto = opts[:proto]
        when 'dns','snmp','dhcp'
          proto = 'udp'
          sname = opts[:proto]
        else
          proto = 'tcp'
          sname = opts[:proto]
        end

        service = host.services.find_or_create_by_port_and_proto(opts[:port].to_i, proto)
      end

      # Try to find an existing vulnerability with the same service & references
      # If there are multiple matches, choose the one with the most matches
      # If a match is found on a vulnerability with no associated service,
      # update that vulnerability with our service information. This helps
      # prevent dupes of the same vuln found by both local patch and
      # service detection.
      if rids and rids.length > 0
        vuln = find_vuln_by_refs(rids, host, service)
        vuln.service = service if vuln
      end
    else
      # Try to find an existing vulnerability with the same host & references
      # If there are multiple matches, choose the one with the most matches
      if rids and rids.length > 0
        vuln = find_vuln_by_refs(rids, host)
      end
    end

    # Try to match based on vuln_details records
    if not vuln and opts[:details_match]
      vuln = find_vuln_by_details(opts[:details_match], host, service)
      if vuln and service and not vuln.service
        vuln.service = service
      end
    end

    # No matches, so create a new vuln record
    unless vuln
      if service
        vuln = service.vulns.find_by_name(name)
      else
        vuln = host.vulns.find_by_name(name)
      end

      unless vuln

        vinf = {
          :host_id => host.id,
          :name    => name,
          :info    => info
        }

        vinf[:service_id] = service.id if service
        vuln = Mdm::Vuln.create(vinf)
      end
    end

    # Set the exploited_at value if provided
    vuln.exploited_at = exploited_at if exploited_at

    # Merge the references
    if rids
      vuln.refs << (rids - vuln.refs)
    end

    # Finalize
    if vuln.changed?
      msf_import_timestamps(opts,vuln)
      vuln.save!
    end

    # Handle vuln_details parameters
    report_vuln_details(vuln, details) if details

    vuln
  }
  end

  def find_vuln_by_refs(refs, host, service=nil)

    vuln = nil

    # Try to find an existing vulnerability with the same service & references
    # If there are multiple matches, choose the one with the most matches
    if service
      refs_ids = refs.map{|x| x.id }
      vuln = service.vulns.find(:all, :include => [:refs], :conditions => { 'refs.id' => refs_ids }).sort { |a,b|
        ( refs_ids - a.refs.map{|x| x.id } ).length <=> ( refs_ids - b.refs.map{|x| x.id } ).length
      }.first
    end

    # Return if we matched based on service
    return vuln if vuln

    # Try to find an existing vulnerability with the same host & references
    # If there are multiple matches, choose the one with the most matches
    refs_ids = refs.map{|x| x.id }
    vuln = host.vulns.find(:all, :include => [:refs], :conditions => { 'service_id' => nil, 'refs.id' => refs_ids }).sort { |a,b|
      ( refs_ids - a.refs.map{|x| x.id } ).length <=> ( refs_ids - b.refs.map{|x| x.id } ).length
    }.first

    return vuln
  end


  def find_vuln_by_details(details_map, host, service=nil)

    # Create a modified version of the criteria in order to match against
    # the joined version of the fields

    crit = {}
    details_map.each_pair do |k,v|
      crit[ "vuln_details.#{k}" ] = v
    end

    vuln = nil

    if service
      vuln = service.vulns.find(:first, :include => [:vuln_details], :conditions => crit)
    end

    # Return if we matched based on service
    return vuln if vuln

    # Prevent matches against other services
    crit["vulns.service_id"] = nil if service
    vuln = host.vulns.find(:first, :include => [:vuln_details], :conditions => crit)

    return vuln
  end

  def get_vuln(wspace, host, service, name, data='')
    raise RuntimeError, "Not workspace safe: #{caller.inspect}"
  ::ActiveRecord::Base.connection_pool.with_connection {
    vuln = nil
    if (service)
      vuln = ::Mdm::Vuln.find.where("name = ? and service_id = ? and host_id = ?", name, service.id, host.id).order("vulns.id DESC").first()
    else
      vuln = ::Mdm::Vuln.find.where("name = ? and host_id = ?", name, host.id).first()
    end

    return vuln
  }
  end

  #
  # Find or create a reference matching this name
  #
  def find_or_create_ref(opts)
    ret = {}
    ret[:ref] = get_ref(opts[:name])
    return ret[:ref] if ret[:ref]

  ::ActiveRecord::Base.connection_pool.with_connection {
    ref = ::Mdm::Ref.find_or_initialize_by_name(opts[:name])
    if ref and ref.changed?
      ref.save!
    end
    ret[:ref] = ref
  }
  end

  def get_ref(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::Ref.find_by_name(name)
  }
  end

  #
  # Populate the vuln_details table with additional
  # information, matched by a specific criteria
  #
  def report_vuln_details(vuln, details)
  ::ActiveRecord::Base.connection_pool.with_connection {
    detail = ::Mdm::VulnDetail.where(( details.delete(:key) || {} ).merge(:vuln_id => vuln.id)).first
    if detail
      details.each_pair do |k,v|
        detail[k] = v
      end
      detail.save! if detail.changed?
      detail
    else
      detail = ::Mdm::VulnDetail.create(details.merge(:vuln_id => vuln.id))
    end
  }
  end

  #
  # Update vuln_details records en-masse based on specific criteria
  # Note that this *can* update data across workspaces
  #
  def update_vuln_details(details)
  ::ActiveRecord::Base.connection_pool.with_connection {
    criteria = details.delete(:key) || {}
    ::Mdm::VulnDetail.update(key, details)
  }
  end

  #
  # Populate the host_details table with additional
  # information, matched by a specific criteria
  #
  def report_host_details(host, details)
  ::ActiveRecord::Base.connection_pool.with_connection {

    detail = ::Mdm::HostDetail.where(( details.delete(:key) || {} ).merge(:host_id => host.id)).first
    if detail
      details.each_pair do |k,v|
        detail[k] = v
      end
      detail.save! if detail.changed?
      detail
    else
      detail = ::Mdm::HostDetail.create(details.merge(:host_id => host.id))
    end
  }
  end

  # report_exploit() used to be used to track sessions and which modules
  # opened them. That information is now available with the session table
  # directly. TODO: kill this completely some day -- for now just warn if
  # some other UI is actually using it.
  def report_exploit(opts={})
    wlog("Deprecated method call: report_exploit()\n" +
      "report_exploit() options: #{opts.inspect}\n" +
      "report_exploit() call stack:\n\t#{caller.join("\n\t")}"
    )
  end

  #
  # Deletes a host and associated data matching this address/comm
  #
  def del_host(wspace, address, comm='')
  ::ActiveRecord::Base.connection_pool.with_connection {
    address, scope = address.split('%', 2)
    host = wspace.hosts.find_by_address_and_comm(address, comm)
    host.destroy if host
  }
  end

  #
  # Deletes a port and associated vulns matching this port
  #
  def del_service(wspace, address, proto, port, comm='')

    host = get_host(:workspace => wspace, :address => address)
    return unless host

  ::ActiveRecord::Base.connection_pool.with_connection {
    host.services.where({:proto => proto, :port => port}).each { |s| s.destroy }
  }
  end

  #
  # Find a reference matching this name
  #
  def has_ref?(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    Mdm::Ref.find_by_name(name)
  }
  end

  #
  # Find a vulnerability matching this name
  #
  def has_vuln?(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    Mdm::Vuln.find_by_name(name)
  }
  end

  #
  # Look for an address across all comms
  #
  def has_host?(wspace,addr)
  ::ActiveRecord::Base.connection_pool.with_connection {
    address, scope = addr.split('%', 2)
    wspace.hosts.find_by_address(addr)
  }
  end

  def events(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.events.find :all, :order => 'created_at ASC'
  }
  end

  def report_event(opts = {})
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    return if not wspace # Temp fix?
    uname  = opts.delete(:username)

    if ! opts[:host].kind_of? ::Mdm::Host and opts[:host]
      opts[:host] = report_host(:workspace => wspace, :host => opts[:host])
    end

    ::Mdm::Event.create(opts.merge(:workspace_id => wspace[:id], :username => uname))
  }
  end

  #
  # Loot collection
  #
  #
  # This method iterates the loot table calling the supplied block with the
  # instance of each entry.
  #
  def each_loot(wspace=workspace, &block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.loots.each do |note|
      block.call(note)
    end
  }
  end

  #
  # Find or create a loot matching this type/data
  #
  def find_or_create_loot(opts)
    report_loot(opts)
  end

  def report_loot(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    path = opts.delete(:path) || (raise RuntimeError, "A loot :path is required")

    host = nil
    addr = nil

    # Report the host so it's there for the Proc to use below
    if opts[:host]
      if opts[:host].kind_of? ::Mdm::Host
        host = opts[:host]
      else
        host = report_host({:workspace => wspace, :host => opts[:host]})
        addr = normalize_host(opts[:host])
      end
    end

    ret = {}

    ltype  = opts.delete(:type) || opts.delete(:ltype) || (raise RuntimeError, "A loot :type or :ltype is required")
    ctype  = opts.delete(:ctype) || opts.delete(:content_type) || 'text/plain'
    name   = opts.delete(:name)
    info   = opts.delete(:info)
    data   = opts[:data]
    loot   = wspace.loots.new

    if host
      loot.host_id = host[:id]
    end
    if opts[:service] and opts[:service].kind_of? ::Mdm::Service
      loot.service_id = opts[:service][:id]
    end

    loot.path  = path
    loot.ltype = ltype
    loot.content_type = ctype
    loot.data  = data
    loot.name  = name if name
    loot.info  = info if info
    msf_import_timestamps(opts,loot)
    loot.save!

    if !opts[:created_at]
=begin
      if host
        host.updated_at = host.created_at
        host.state      = HostState::Alive
        host.save!
      end
=end
    end

    ret[:loot] = loot
  }
  end

  #
  # This methods returns a list of all loot in the database
  #
  def loots(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.loots
  }
  end

  #
  # Find or create a task matching this type/data
  #
  def find_or_create_task(opts)
    report_task(opts)
  end

  def report_task(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    path = opts.delete(:path) || (raise RuntimeError, "A task :path is required")

    ret = {}

    user      = opts.delete(:user)
    desc      = opts.delete(:desc)
    error     = opts.delete(:error)
    info      = opts.delete(:info)
    mod       = opts.delete(:mod)
    options   = opts.delete(:options)
    prog      = opts.delete(:prog)
    result    = opts.delete(:result)
    completed_at = opts.delete(:completed_at)
    task      = wspace.tasks.new

    task.created_by = user
    task.description = desc
    task.error = error if error
    task.info = info
    task.module = mod
    task.options = options
    task.path = path
    task.progress = prog
    task.result = result if result
    msf_import_timestamps(opts,task)
    # Having blank completed_ats, while accurate, will cause unstoppable tasks.
    if completed_at.nil? || completed_at.empty?
      task.completed_at = opts[:updated_at]
    else
      task.completed_at = completed_at
    end
    task.save!
    ret[:task] = task
  }
  end

  #
  # This methods returns a list of all tasks in the database
  #
  def tasks(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.tasks
  }
  end


  #
  # Find or create a task matching this type/data
  #
  def find_or_create_report(opts)
    report_report(opts)
  end

  def report_report(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    path = opts.delete(:path) || (raise RuntimeError, "A report :path is required")

    ret = {}
    user      = opts.delete(:user)
    options   = opts.delete(:options)
    rtype     = opts.delete(:rtype)
    report    = wspace.reports.new
    report.created_by = user
    report.options = options
    report.rtype = rtype
    report.path = path
    msf_import_timestamps(opts,report)
    report.save!

    ret[:task] = report
  }
  end

  #
  # This methods returns a list of all reports in the database
  #
  def reports(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.reports
  }
  end

  #
  # WMAP
  # Support methods
  #

  #
  # Report a Web Site to the database.  WebSites must be tied to an existing Service
  #
  # opts MUST contain
  # +:service+:: the service object this site should be associated with
  # +:vhost+::   the virtual host name for this particular web site`
  #
  # If +:service+ is NOT specified, the following values are mandatory
  # +:host+:: the ip address of the server hosting the web site
  # +:port+:: the port number of the associated web site
  # +:ssl+::  whether or not SSL is in use on this port
  #
  # These values will be used to create new host and service records
  #
  # opts can contain
  # +:options+:: a hash of options for accessing this particular web site
  # +:info+:: if present, report the service with this info
  #
  # Duplicate records for a given host, port, vhost combination will be overwritten
  #
  def report_web_site(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection { |conn|
    wspace = opts.delete(:workspace) || workspace
    vhost  = opts.delete(:vhost)

    addr = nil
    port = nil
    name = nil
    serv = nil
    info = nil

    if opts[:service] and opts[:service].kind_of?(::Mdm::Service)
      serv = opts[:service]
    else
      addr = opts[:host]
      port = opts[:port]
      name = opts[:ssl] ? 'https' : 'http'
      info = opts[:info]
      if not (addr and port)
        raise ArgumentError, "report_web_site requires service OR host/port/ssl"
      end

      # Force addr to be the address and not hostname
      addr = Rex::Socket.getaddress(addr, true)
    end

    ret = {}

    host = serv ? serv.host : find_or_create_host(
      :workspace => wspace,
      :host      => addr,
      :state     => Msf::HostState::Alive
    )

    if host.name.to_s.empty?
      host.name = vhost
      host.save!
    end

    serv = serv ? serv : find_or_create_service(
      :workspace => wspace,
      :host      => host,
      :port      => port,
      :proto     => 'tcp',
      :state     => 'open'
    )

    # Change the service name if it is blank or it has
    # been explicitly specified.
    if opts.keys.include?(:ssl) or serv.name.to_s.empty?
      name = opts[:ssl] ? 'https' : 'http'
      serv.name = name
    end
    # Add the info if it's there.
    unless info.to_s.empty?
      serv.info = info
    end
    serv.save! if serv.changed?
=begin
    host.updated_at = host.created_at
    host.state      = HostState::Alive
    host.save!
=end

    vhost ||= host.address
    site = ::Mdm::WebSite.find_or_initialize_by_vhost_and_service_id(vhost, serv[:id])
    site.options = opts[:options] if opts[:options]

    # XXX:
    msf_import_timestamps(opts, site)
    site.save!

    ret[:web_site] = site
  }
  end

  #
  # Report a Web Page to the database.  WebPage must be tied to an existing Web Site
  #
  # opts MUST contain
  # +:web_site+:: the web site object that this page should be associated with
  # +:path+::     the virtual host name for this particular web site
  # +:code+::     the http status code from requesting this page
  # +:headers+::  this is a HASH of headers (lowercase name as key) of ARRAYs of values
  # +:body+::     the document body of the server response
  # +:query+::    the query string after the path
  #
  # If web_site is NOT specified, the following values are mandatory
  # +:host+::  the ip address of the server hosting the web site
  # +:port+::  the port number of the associated web site
  # +:vhost+:: the virtual host for this particular web site
  # +:ssl+::   whether or not SSL is in use on this port
  #
  # These values will be used to create new host, service, and web_site records
  #
  # opts can contain
  # +:cookie+::   the Set-Cookie headers, merged into a string
  # +:auth+::     the Authorization headers, merged into a string
  # +:ctype+::    the Content-Type headers, merged into a string
  # +:mtime+::    the timestamp returned from the server of the last modification time
  # +:location+:: the URL that a redirect points to
  #
  # Duplicate records for a given web_site, path, and query combination will be overwritten
  #

  def report_web_page(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace

    path    = opts[:path]
    code    = opts[:code].to_i
    body    = opts[:body].to_s
    query   = opts[:query].to_s
    headers = opts[:headers]
    site    = nil

    if not (path and code and body and headers)
      raise ArgumentError, "report_web_page requires the path, query, code, body, and headers parameters"
    end

    if opts[:web_site] and opts[:web_site].kind_of?(::Mdm::WebSite)
      site = opts.delete(:web_site)
    else
      site = report_web_site(
        :workspace => wspace,
        :host      => opts[:host], :port => opts[:port],
        :vhost     => opts[:host], :ssl  => opts[:ssl]
      )
      if not site
        raise ArgumentError, "report_web_page was unable to create the associated web site"
      end
    end

    ret = {}

    page = ::Mdm::WebPage.find_or_initialize_by_web_site_id_and_path_and_query(site[:id], path, query)
    page.code     = code
    page.body     = body
    page.headers  = headers
    page.cookie   = opts[:cookie] if opts[:cookie]
    page.auth     = opts[:auth]   if opts[:auth]
    page.mtime    = opts[:mtime]  if opts[:mtime]
    page.ctype    = opts[:ctype]  if opts[:ctype]
    page.location = opts[:location] if opts[:location]
    msf_import_timestamps(opts, page)
    page.save!

    ret[:web_page] = page
  }

  end


  #
  # Report a Web Form to the database.  WebForm must be tied to an existing Web Site
  #
  # opts MUST contain
  # +:web_site+:: the web site object that this page should be associated with
  # +:path+::     the virtual host name for this particular web site
  # +:query+::    the query string that is appended to the path (not valid for GET)
  # +:method+::   the form method, one of GET, POST, or PATH
  # +:params+::   an ARRAY of all parameters and values specified in the form
  #
  # If web_site is NOT specified, the following values are mandatory
  # +:host+::  the ip address of the server hosting the web site
  # +:port+::  the port number of the associated web site
  # +:vhost+:: the virtual host for this particular web site
  # +:ssl+::   whether or not SSL is in use on this port
  #
  # Duplicate records for a given web_site, path, method, and params combination will be overwritten
  #

  def report_web_form(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace

    path    = opts[:path]
    meth    = opts[:method].to_s.upcase
    para    = opts[:params]
    quer    = opts[:query].to_s
    site    = nil

    if not (path and meth)
      raise ArgumentError, "report_web_form requires the path and method parameters"
    end

    if not %W{GET POST PATH}.include?(meth)
      raise ArgumentError, "report_web_form requires the method to be one of GET, POST, PATH"
    end

    if opts[:web_site] and opts[:web_site].kind_of?(::Mdm::WebSite)
      site = opts.delete(:web_site)
    else
      site = report_web_site(
        :workspace => wspace,
        :host      => opts[:host], :port => opts[:port],
        :vhost     => opts[:host], :ssl  => opts[:ssl]
      )
      if not site
        raise ArgumentError, "report_web_form was unable to create the associated web site"
      end
    end

    ret = {}

    # Since one of our serialized fields is used as a unique parameter, we must do the final
    # comparisons through ruby and not SQL.

    form = nil
    ::Mdm::WebForm.find_all_by_web_site_id_and_path_and_method_and_query(site[:id], path, meth, quer).each do |xform|
      if xform.params == para
        form = xform
        break
      end
    end
    if not form
      form = ::Mdm::WebForm.new
      form.web_site_id = site[:id]
      form.path        = path
      form.method      = meth
      form.params      = para
      form.query       = quer
    end

    msf_import_timestamps(opts, form)
    form.save!
    ret[:web_form] = form
  }
  end


  #
  # Report a Web Vuln to the database.  WebVuln must be tied to an existing Web Site
  #
  # opts MUST contain
  # +:web_site+::  the web site object that this page should be associated with
  # +:path+::      the virtual host name for this particular web site
  # +:query+::     the query string appended to the path (not valid for GET method flaws)
  # +:method+::    the form method, one of GET, POST, or PATH
  # +:params+::    an ARRAY of all parameters and values specified in the form
  # +:pname+::     the specific field where the vulnerability occurs
  # +:proof+::     the string showing proof of the vulnerability
  # +:risk+::      an INTEGER value from 0 to 5 indicating the risk (5 is highest)
  # +:name+::      the string indicating the type of vulnerability
  #
  # If web_site is NOT specified, the following values are mandatory
  # +:host+::  the ip address of the server hosting the web site
  # +:port+::  the port number of the associated web site
  # +:vhost+:: the virtual host for this particular web site
  # +:ssl+::   whether or not SSL is in use on this port
  #
  #
  # Duplicate records for a given web_site, path, method, pname, and name
  # combination will be overwritten
  #

  def report_web_vuln(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace

    path    = opts[:path]
    meth    = opts[:method]
    para    = opts[:params] || []
    quer    = opts[:query].to_s
    pname   = opts[:pname]
    proof   = opts[:proof]
    risk    = opts[:risk].to_i
    name    = opts[:name].to_s.strip
    blame   = opts[:blame].to_s.strip
    desc    = opts[:description].to_s.strip
    conf    = opts[:confidence].to_i
    cat     = opts[:category].to_s.strip
    payload = opts[:payload].to_s
    owner   = opts[:owner] ? opts[:owner].shortname : nil


    site    = nil

    if not (path and meth and proof and pname)
      raise ArgumentError, "report_web_vuln requires the path, method, proof, risk, name, params, and pname parameters. Received #{opts.inspect}"
    end

    if not %W{GET POST PATH}.include?(meth)
      raise ArgumentError, "report_web_vuln requires the method to be one of GET, POST, PATH. Received '#{meth}'"
    end

    if risk < 0 or risk > 5
      raise ArgumentError, "report_web_vuln requires the risk to be between 0 and 5 (inclusive). Received '#{risk}'"
    end

    if conf < 0 or conf > 100
      raise ArgumentError, "report_web_vuln requires the confidence to be between 1 and 100 (inclusive). Received '#{conf}'"
    end

    if cat.empty?
      raise ArgumentError, "report_web_vuln requires the category to be a valid string"
    end

    if name.empty?
      raise ArgumentError, "report_web_vuln requires the name to be a valid string"
    end

    if opts[:web_site] and opts[:web_site].kind_of?(::Mdm::WebSite)
      site = opts.delete(:web_site)
    else
      site = report_web_site(
        :workspace => wspace,
        :host      => opts[:host], :port => opts[:port],
        :vhost     => opts[:host], :ssl  => opts[:ssl]
      )
      if not site
        raise ArgumentError, "report_web_form was unable to create the associated web site"
      end
    end

    ret = {}

    meth = meth.to_s.upcase

    vuln = ::Mdm::WebVuln.find_or_initialize_by_web_site_id_and_path_and_method_and_pname_and_name_and_category_and_query(site[:id], path, meth, pname, name, cat, quer)
    vuln.name     = name
    vuln.risk     = risk
    vuln.params   = para
    vuln.proof    = proof.to_s
    vuln.category = cat
    vuln.blame    = blame
    vuln.description = desc
    vuln.confidence  = conf
    vuln.payload = payload
    vuln.owner   = owner

    msf_import_timestamps(opts, vuln)
    vuln.save!

    ret[:web_vuln] = vuln
  }
  end

  #
  # WMAP
  # Selected host
  #
  def selected_host
  ::ActiveRecord::Base.connection_pool.with_connection {
    selhost = ::Mdm::WmapTarget.where("selected != 0").first()
    if selhost
      return selhost.host
    else
      return
    end
  }
  end

  #
  # WMAP
  # Selected target
  #
  def selected_wmap_target
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::WmapTarget.find.where("selected != 0")
  }
  end

  #
  # WMAP
  # Selected port
  #
  def selected_port
    selected_wmap_target.port
  end

  #
  # WMAP
  # Selected ssl
  #
  def selected_ssl
    selected_wmap_target.ssl
  end

  #
  # WMAP
  # Selected id
  #
  def selected_id
    selected_wmap_target.object_id
  end

  #
  # WMAP
  # This method iterates the requests table identifiying possible targets
  # This method wiil be remove on second phase of db merging.
  #
  def each_distinct_target(&block)
    request_distinct_targets.each do |target|
      block.call(target)
    end
  end

  #
  # WMAP
  # This method returns a list of all possible targets available in requests
  # This method wiil be remove on second phase of db merging.
  #
  def request_distinct_targets
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::WmapRequest.select('DISTINCT host,address,port,ssl')
  }
  end

  #
  # WMAP
  # This method iterates the requests table returning a list of all requests of a specific target
  #
  def each_request_target_with_path(&block)
    target_requests('AND wmap_requests.path IS NOT NULL').each do |req|
      block.call(req)
    end
  end

  #
  # WMAP
  # This method iterates the requests table returning a list of all requests of a specific target
  #
  def each_request_target_with_query(&block)
    target_requests('AND wmap_requests.query IS NOT NULL').each do |req|
      block.call(req)
    end
  end

  #
  # WMAP
  # This method iterates the requests table returning a list of all requests of a specific target
  #
  def each_request_target_with_body(&block)
    target_requests('AND wmap_requests.body IS NOT NULL').each do |req|
      block.call(req)
    end
  end

  #
  # WMAP
  # This method iterates the requests table returning a list of all requests of a specific target
  #
  def each_request_target_with_headers(&block)
    target_requests('AND wmap_requests.headers IS NOT NULL').each do |req|
      block.call(req)
    end
  end

  #
  # WMAP
  # This method iterates the requests table returning a list of all requests of a specific target
  #
  def each_request_target(&block)
    target_requests('').each do |req|
      block.call(req)
    end
  end

  #
  # WMAP
  # This method returns a list of all requests from target
  #
  def target_requests(extra_condition)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::WmapRequest.where("wmap_requests.host = ? AND wmap_requests.port = ? #{extra_condition}",selected_host,selected_port)
  }
  end

  #
  # WMAP
  # This method iterates the requests table calling the supplied block with the
  # request instance of each entry.
  #
  def each_request(&block)
    requests.each do |request|
      block.call(request)
    end
  end

  #
  # WMAP
  # This method allows to query directly the requests table. To be used mainly by modules
  #
  def request_sql(host,port,extra_condition)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::WmapRequest.where("wmap_requests.host = ? AND wmap_requests.port = ? #{extra_condition}", host , port)
  }
  end

  #
  # WMAP
  # This methods returns a list of all targets in the database
  #
  def requests
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::WmapRequest.find(:all)
  }
  end

  #
  # WMAP
  # This method iterates the targets table calling the supplied block with the
  # target instance of each entry.
  #
  def each_target(&block)
    targets.each do |target|
      block.call(target)
    end
  end

  #
  # WMAP
  # This methods returns a list of all targets in the database
  #
  def targets
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::WmapTarget.find(:all)
  }
  end

  #
  # WMAP
  # This methods deletes all targets from targets table in the database
  #
  def delete_all_targets
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::WmapTarget.delete_all
  }
  end

  #
  # WMAP
  # Find a target matching this id
  #
  def get_target(id)
  ::ActiveRecord::Base.connection_pool.with_connection {
    target = ::Mdm::WmapTarget.where("id = ?", id).first()
    return target
  }
  end

  #
  # WMAP
  # Create a target
  #
  def create_target(host,port,ssl,sel)
  ::ActiveRecord::Base.connection_pool.with_connection {
    tar = ::Mdm::WmapTarget.create(
        :host => host,
        :address => host,
        :port => port,
        :ssl => ssl,
        :selected => sel
      )
    #framework.events.on_db_target(rec)
  }
  end


  #
  # WMAP
  # Create a request (by hand)
  #
  def create_request(host,port,ssl,meth,path,headers,query,body,respcode,resphead,response)
  ::ActiveRecord::Base.connection_pool.with_connection {
    req = ::Mdm::WmapRequest.create(
        :host => host,
        :address => host,
        :port => port,
        :ssl => ssl,
        :meth => meth,
        :path => path,
        :headers => headers,
        :query => query,
        :body => body,
        :respcode => respcode,
        :resphead => resphead,
        :response => response
      )
    #framework.events.on_db_request(rec)
  }
  end

  #
  # WMAP
  # Quick way to query the database (used by wmap_sql)
  #
  def sql_query(sqlquery)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ActiveRecord::Base.connection.select_all(sqlquery)
  }
  end


  # Returns a REXML::Document from the given data.
  def rexmlify(data)
    if data.kind_of?(REXML::Document)
      return data
    else
      # Make an attempt to recover from a REXML import fail, since
      # it's better than dying outright.
      begin
        return REXML::Document.new(data)
      rescue REXML::ParseException => e
        dlog("REXML error: Badly formatted XML, attempting to recover. Error was: #{e.inspect}")
        return REXML::Document.new(data.gsub(/([\x00-\x08\x0b\x0c\x0e-\x1f\x80-\xff])/n){ |x| "\\x%.2x" % x.unpack("C*")[0] })
      end
    end
  end

  # Handles timestamps from Metasploit Express/Pro imports.
  def msf_import_timestamps(opts,obj)
    obj.created_at = opts["created_at"] if opts["created_at"]
    obj.created_at = opts[:created_at] if opts[:created_at]
    obj.updated_at = opts["updated_at"] ? opts["updated_at"] : obj.created_at
    obj.updated_at = opts[:updated_at] ? opts[:updated_at] : obj.created_at
    return obj
  end

  ##
  #
  # Import methods
  #
  ##

  #
  # Generic importer that automatically determines the file type being
  # imported.  Since this looks for vendor-specific strings in the given
  # file, there shouldn't be any false detections, but no guarantees.
  #
  def import_file(args={}, &block)
    filename = args[:filename] || args['filename']
    wspace = args[:wspace] || args['wspace'] || workspace
    @import_filedata            = {}
    @import_filedata[:filename] = filename

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(4)
    end
    if data.nil?
      raise DBImportError.new("Zero-length file")
    end

    case data[0,4]
    when "PK\x03\x04"
      data = Zip::ZipFile.open(filename)
    when "\xd4\xc3\xb2\xa1", "\xa1\xb2\xc3\xd4"
      data = PacketFu::PcapFile.new(:filename => filename)
    else
      ::File.open(filename, 'rb') do |f|
        sz = f.stat.size
        data = f.read(sz)
      end
    end
    if block
      import(args.merge(:data => data)) { |type,data| yield type,data }
    else
      import(args.merge(:data => data))
    end

  end

  # A dispatcher method that figures out the data's file type,
  # and sends it off to the appropriate importer. Note that
  # import_file_detect will raise an error if the filetype
  # is unknown.
  def import(args={}, &block)
    data = args[:data] || args['data']
    wspace = args[:wspace] || args['wspace'] || workspace
    ftype = import_filetype_detect(data)
    yield(:filetype, @import_filedata[:type]) if block
    self.send "import_#{ftype}".to_sym, args, &block
  end

  # Returns one of: :nexpose_simplexml :nexpose_rawxml :nmap_xml :openvas_xml
  # :nessus_xml :nessus_xml_v2 :qualys_scan_xml, :qualys_asset_xml, :msf_xml :nessus_nbe :amap_mlog
  # :amap_log :ip_list, :msf_zip, :libpcap, :foundstone_xml, :acunetix_xml, :appscan_xml
  # :burp_session, :ip360_xml_v3, :ip360_aspl_xml, :nikto_xml
  # If there is no match, an error is raised instead.
  def import_filetype_detect(data)

    if data and data.kind_of? Zip::ZipFile
      raise DBImportError.new("The zip file provided is empty.") if data.entries.empty?
      @import_filedata ||= {}
      @import_filedata[:zip_filename] = File.split(data.to_s).last
      @import_filedata[:zip_basename] = @import_filedata[:zip_filename].gsub(/\.zip$/,"")
      @import_filedata[:zip_entry_names] = data.entries.map {|x| x.name}
      begin
        @import_filedata[:zip_xml] = @import_filedata[:zip_entry_names].grep(/^(.*)_[0-9]+\.xml$/).first || raise
        @import_filedata[:zip_wspace] = @import_filedata[:zip_xml].to_s.match(/^(.*)_[0-9]+\.xml$/)[1]
        @import_filedata[:type] = "Metasploit ZIP Report"
        return :msf_zip
      rescue ::Interrupt
        raise $!
      rescue ::Exception
        raise DBImportError.new("The zip file provided is not a Metasploit ZIP report")
      end
    end

    if data and data.kind_of? PacketFu::PcapFile
      # Don't check for emptiness here because unlike other formats, we
      # haven't read any actual data in yet, only magic bytes to discover
      # that this is indeed a pcap file.
      #raise DBImportError.new("The pcap file provided is empty.") if data.body.empty?
      @import_filedata ||= {}
      @import_filedata[:type] = "Libpcap Packet Capture"
      return :libpcap
    end

    # This is a text string, lets make sure its treated as binary
    data = data.unpack("C*").pack("C*")
    if data and data.to_s.strip.length == 0
      raise DBImportError.new("The data provided to the import function was empty")
    end

    # Parse the first line or 4k of data from the file
    di = data.index("\n") || 4096

    firstline = data[0, di]
    @import_filedata ||= {}
    if (firstline.index("<NeXposeSimpleXML"))
      @import_filedata[:type] = "NeXpose Simple XML"
      return :nexpose_simplexml
    elsif (firstline.index("<FusionVM"))
      @import_filedata[:type] = "FusionVM XML"
      return :fusionvm_xml
    elsif (firstline.index("<NexposeReport"))
      @import_filedata[:type] = "NeXpose XML Report"
      return :nexpose_rawxml
    elsif (firstline.index("Name,Manufacturer,Device Type,Model,IP Address,Serial Number,Location,Operating System"))
      @import_filedata[:type] = "Spiceworks CSV Export"
      return :spiceworks_csv
    elsif (firstline.index("<scanJob>"))
      @import_filedata[:type] = "Retina XML"
      return :retina_xml
    elsif (firstline.index(/<get_reports_response status=['"]200['"] status_text=['"]OK['"]>/))
      @import_filedata[:type] = "OpenVAS XML"
      return :openvas_new_xml
    elsif (firstline.index(/<report id=['"]/))
      @import_filedata[:type] = "OpenVAS XML"
      return :openvas_new_xml
    elsif (firstline.index("<NessusClientData>"))
      @import_filedata[:type] = "Nessus XML (v1)"
      return :nessus_xml
    elsif (firstline.index("<SecScan ID="))
      @import_filedata[:type] = "Microsoft Baseline Security Analyzer"
      return :mbsa_xml
    elsif (data[0,1024] =~ /<!ATTLIST\s+items\s+burpVersion/)
      @import_filedata[:type] = "Burp Session XML"
      return :burp_session_xml
    elsif (firstline.index("<?xml"))
      # it's xml, check for root tags we can handle
      line_count = 0
      data.each_line { |line|
        line =~ /<([a-zA-Z0-9\-\_]+)[ >]/

        case $1
        when "niktoscan"
          @import_filedata[:type] = "Nikto XML"
          return :nikto_xml
        when "nmaprun"
          @import_filedata[:type] = "Nmap XML"
          return :nmap_xml
        when "openvas-report"
          @import_filedata[:type] = "OpenVAS Report"
          return :openvas_xml
        when "NessusClientData"
          @import_filedata[:type] = "Nessus XML (v1)"
          return :nessus_xml
        when "NessusClientData_v2"
          @import_filedata[:type] = "Nessus XML (v2)"
          return :nessus_xml_v2
        when "SCAN"
          @import_filedata[:type] = "Qualys Scan XML"
          return :qualys_scan_xml
        when "report"
          @import_filedata[:type] = "Wapiti XML"
          return :wapiti_xml
        when "ASSET_DATA_REPORT"
          @import_filedata[:type] = "Qualys Asset XML"
          return :qualys_asset_xml
        when /MetasploitExpressV[1234]/
          @import_filedata[:type] = "Metasploit XML"
          return :msf_xml
        when /MetasploitV4/
          @import_filedata[:type] = "Metasploit XML"
          return :msf_xml
        when /netsparker/
          @import_filedata[:type] = "NetSparker XML"
          return :netsparker_xml
        when /audits?/ # <audit> and <audits> are both valid for nCircle. wtfmate.
          @import_filedata[:type] = "IP360 XML v3"
          return :ip360_xml_v3
        when /ontology/
          @import_filedata[:type] = "IP360 ASPL"
          return :ip360_aspl_xml
        when /ReportInfo/
          @import_filedata[:type] = "Foundstone"
          return :foundstone_xml
        when /ScanGroup/
          @import_filedata[:type] = "Acunetix"
          return :acunetix_xml
        when /AppScanInfo/ # Actually the second line
          @import_filedata[:type] = "Appscan"
          return :appscan_xml
        when "entities"
          if  line =~ /creator.*\x43\x4f\x52\x45\x20\x49\x4d\x50\x41\x43\x54/ni
            @import_filedata[:type] = "CI"
            return :ci_xml
          end
        else
          # Give up if we haven't hit the root tag in the first few lines
          break if line_count > 10
        end
        line_count += 1
      }
    elsif (firstline.index("timestamps|||scan_start"))
      @import_filedata[:type] = "Nessus NBE Report"
      # then it's a nessus nbe
      return :nessus_nbe
    elsif (firstline.index("# amap v"))
      # then it's an amap mlog
      @import_filedata[:type] = "Amap Log -m"
      return :amap_mlog
    elsif (firstline.index("amap v"))
      # then it's an amap log
      @import_filedata[:type] = "Amap Log"
      return :amap_log
    elsif ipv46_validator(firstline)
      # then its an IP list
      @import_filedata[:type] = "IP Address List"
      return :ip_list
    elsif (data[0,1024].index("<netsparker"))
      @import_filedata[:type] = "NetSparker XML"
      return :netsparker_xml
    elsif (firstline.index("# Metasploit PWDump Export"))
      # then it's a Metasploit PWDump export
      @import_filedata[:type] = "msf_pwdump"
      return :msf_pwdump
    end

    raise DBImportError.new("Could not automatically determine file type")
  end

  # Boils down the validate_import_file to a boolean
  def validate_import_file(data)
    begin
      import_filetype_detect(data)
    rescue DBImportError
      return false
    end
    return true
  end

  #
  # Imports Nikto scan data from -Format xml as notes.
  #
  def import_nikto_xml(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    doc = rexmlify(data)
    doc.elements.each do |f|
      f.elements.each('scandetails') do |host|
        # Get host information
        addr = host.attributes['targetip']
        next if not addr
        if bl.include? addr
          next
        else
          yield(:address,addr) if block
        end
        # Get service information
        port = host.attributes['targetport']
        next if port.to_i == 0
        uri = URI.parse(host.attributes['sitename']) rescue nil
        next unless uri and uri.scheme
        # Collect and report scan descriptions.
        host.elements.each do |item|
          if item.elements['description']
            desc_text = item.elements['description'].text
            next if desc_text.nil? or desc_text.empty?
            desc_data = {
                :workspace => wspace,
                :host      => addr,
                :type      => "service.nikto.scan.description",
                :data      => desc_text,
                :proto     => "tcp",
                :port      => port.to_i,
                :sname     => uri.scheme,
                :update    => :unique_data,
                :task      => args[:task]
            }
            # Always report it as a note.
            report_note(desc_data)
            # Sometimes report it as a vuln, too.
            # XXX: There's a Vuln.info field but nothing reads from it? See Bug #5837
            if item.attributes['osvdbid'].to_i != 0
              desc_data[:refs] = ["OSVDB-#{item.attributes['osvdbid']}"]
              desc_data[:name] = "NIKTO-#{item.attributes['id']}"
              desc_data.delete(:data)
              desc_data.delete(:type)
              desc_data.delete(:update)
              report_vuln(desc_data)
            end
          end
        end
      end
    end
  end

  def import_wapiti_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_wapiti_xml(args.merge(:data => data))
  end

  def import_wapiti_xml(args={}, &block)
    if block
      doc = Rex::Parser::WapitiDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::WapitiDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_openvas_new_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_wapiti_xml(args.merge(:data => data))
  end

  def import_openvas_new_xml(args={}, &block)
    if block
      doc = Rex::Parser::OpenVASDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::OpenVASDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_libpcap_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = PacketFu::PcapFile.new(:filename => filename)
    import_libpcap(args.merge(:data => data))
  end

  # The libpcap file format is handled by PacketFu for data
  # extraction. TODO: Make this its own mixin, and possibly
  # extend PacketFu to do better stream analysis on the fly.
  def import_libpcap(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    # seen_hosts is only used for determining when to yield an address. Once we get
    # some packet analysis going, the values will have all sorts of info. The plan
    # is to ru through all the packets as a first pass and report host and service,
    # then, once we have everything parsed, we can reconstruct sessions and ngrep
    # out things like authentication sequences, examine ttl's and window sizes, all
    # kinds of crazy awesome stuff like that.
    seen_hosts = {}
    decoded_packets = 0
    last_count = 0
    data.read_packet_bytes do |p|
      if (decoded_packets >= last_count + 1000) and block
        yield(:pcap_count, decoded_packets)
        last_count = decoded_packets
      end
      decoded_packets += 1

      pkt = PacketFu::Packet.parse(p) rescue next # Just silently skip bad packets

      next unless pkt.is_ip? # Skip anything that's not IP. Technically, not Ethernet::Ip
      next if pkt.is_tcp? && (pkt.tcp_src == 0 || pkt.tcp_dst == 0) # Skip port 0
      next if pkt.is_udp? && (pkt.udp_src == 0 || pkt.udp_dst == 0) # Skip port 0
      saddr = pkt.ip_saddr
      daddr = pkt.ip_daddr

      # Handle blacklists and obviously useless IP addresses, and report the host.
      next if (bl | [saddr,daddr]).size == bl.size # Both hosts are blacklisted, skip everything.
      unless( bl.include?(saddr) || rfc3330_reserved(saddr))
        yield(:address,saddr) if block and !seen_hosts.keys.include?(saddr)
        unless seen_hosts[saddr]
          report_host(
              :workspace => wspace,
              :host      => saddr,
              :state     => Msf::HostState::Alive,
              :task      => args[:task]
          )
        end
        seen_hosts[saddr] ||= []

      end
      unless( bl.include?(daddr) || rfc3330_reserved(daddr))
        yield(:address,daddr) if block and !seen_hosts.keys.include?(daddr)
        unless seen_hosts[daddr]
          report_host(
              :workspace => wspace,
              :host      => daddr,
              :state     => Msf::HostState::Alive,
              :task      => args[:task]
          )
        end
        seen_hosts[daddr] ||= []
      end

      if pkt.is_tcp? # First pass on TCP packets
        if (pkt.tcp_flags.syn == 1 and pkt.tcp_flags.ack == 1) or # Oh, this kills me
          pkt.tcp_src < 1024 # If it's a low port, assume it's a proper service.
          if seen_hosts[saddr]
            unless seen_hosts[saddr].include? [pkt.tcp_src,"tcp"]
              report_service(
                  :workspace => wspace, :host => saddr,
                  :proto     => "tcp", :port => pkt.tcp_src,
                  :state     => Msf::ServiceState::Open,
                  :task      => args[:task]
              )
              seen_hosts[saddr] << [pkt.tcp_src,"tcp"]
              yield(:service,"%s:%d/%s" % [saddr,pkt.tcp_src,"tcp"])
            end
          end
        end
      elsif pkt.is_udp? # First pass on UDP packets
        if pkt.udp_src == pkt.udp_dst # Very basic p2p detection.
          [saddr,daddr].each do |xaddr|
            if seen_hosts[xaddr]
              unless seen_hosts[xaddr].include? [pkt.udp_src,"udp"]
                report_service(
                    :workspace => wspace, :host => xaddr,
                    :proto     => "udp", :port => pkt.udp_src,
                    :state     => Msf::ServiceState::Open,
                    :task      => args[:task]
                )
                seen_hosts[xaddr] << [pkt.udp_src,"udp"]
                yield(:service,"%s:%d/%s" % [xaddr,pkt.udp_src,"udp"])
              end
            end
          end
        elsif pkt.udp_src < 1024 # Probably a service
          if seen_hosts[saddr]
            unless seen_hosts[saddr].include? [pkt.udp_src,"udp"]
              report_service(
                  :workspace => wspace, :host => saddr,
                  :proto     => "udp", :port => pkt.udp_src,
                  :state     => Msf::ServiceState::Open,
                  :task      => args[:task]
              )
              seen_hosts[saddr] << [pkt.udp_src,"udp"]
              yield(:service,"%s:%d/%s" % [saddr,pkt.udp_src,"udp"])
            end
          end
        end
      end # tcp or udp

      inspect_single_packet(pkt,wspace,args[:task])

    end # data.body.map

    # Right about here, we should have built up some streams for some stream analysis.
    # Not sure what form that will take, but people like shoving many hundreds of
    # thousands of packets through this thing, so it'll need to be memory efficient.

  end

  # Do all the single packet analysis we can while churning through the pcap
  # the first time. Multiple packet inspection will come later, where we can
  # do stream analysis, compare requests and responses, etc.
  def inspect_single_packet(pkt,wspace,task=nil)
    if pkt.is_tcp? or pkt.is_udp?
      inspect_single_packet_http(pkt,wspace,task)
    end
  end

  # Checks for packets that are headed towards port 80, are tcp, contain an HTTP/1.0
  # line, contains an Authorization line, contains a b64-encoded credential, and
  # extracts it. Reports this credential and solidifies the service as HTTP.
  def inspect_single_packet_http(pkt,wspace,task=nil)
    # First, check the server side (data from port 80).
    if pkt.is_tcp? and pkt.tcp_src == 80 and !pkt.payload.nil? and !pkt.payload.empty?
      if pkt.payload =~ /^HTTP\x2f1\x2e[01]/n
        http_server_match = pkt.payload.match(/\nServer:\s+([^\r\n]+)[\r\n]/n)
        if http_server_match.kind_of?(MatchData) and http_server_match[1]
          report_service(
              :workspace => wspace,
              :host      => pkt.ip_saddr,
              :port      => pkt.tcp_src,
              :proto     => "tcp",
              :name      => "http",
              :info      => http_server_match[1],
              :state     => Msf::ServiceState::Open,
              :task      => task
          )
          # That's all we want to know from this service.
          return :something_significant
        end
      end
    end

    # Next, check the client side (data to port 80)
    if pkt.is_tcp? and pkt.tcp_dst == 80 and !pkt.payload.nil? and !pkt.payload.empty?
      if pkt.payload.match(/[\x00-\x20]HTTP\x2f1\x2e[10]/n)
        auth_match = pkt.payload.match(/\nAuthorization:\s+Basic\s+([A-Za-z0-9=\x2b]+)/n)
        if auth_match.kind_of?(MatchData) and auth_match[1]
          b64_cred = auth_match[1]
        else
          return false
        end
        # If we're this far, we can surmise that at least the client is a web browser,
        # he thinks the server is HTTP and he just made an authentication attempt. At
        # this point, we'll just believe everything the packet says -- validation ought
        # to come later.
        user,pass = b64_cred.unpack("m*").first.split(/:/,2)
        report_service(
            :workspace => wspace,
            :host      => pkt.ip_daddr,
            :port      => pkt.tcp_dst,
            :proto     => "tcp",
            :name      => "http",
            :task      => task
        )
        report_auth_info(
            :workspace => wspace,
            :host      => pkt.ip_daddr,
            :port      => pkt.tcp_dst,
            :proto     => "tcp",
            :type      => "password",
            :active    => true, # Once we can build a stream, determine if the auth was successful. For now, assume it is.
            :user      => user,
            :pass      => pass,
            :task      => task
        )
        # That's all we want to know from this service.
        return :something_significant
      end
    end
  end

  def import_spiceworks_csv(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    CSV.parse(data) do |row|
      next unless (["Name", "Manufacturer", "Device Type"] & row).empty? #header
      name = row[0]
      manufacturer = row[1]
      device = row[2]
      model = row[3]
      ip = row[4]
      serialno = row[5]
      location = row[6]
      os = row[7]

      next unless ip
      next if bl.include? ip

      conf = {
      :workspace => wspace,
      :host      => ip,
      :name      => name,
      :task      => args[:task]
      }

      conf[:os_name] = os if os

      info = []
      info << "Serial Number: #{serialno}" unless (serialno.blank? or serialno == name)
      info << "Location: #{location}" unless location.blank?
      conf[:info] = info.join(", ") unless info.empty?

      host = report_host(conf)
      report_import_note(wspace, host)
    end
  end

  #
  # Metasploit PWDump Export
  #
  # This file format is generated by the db_export -f pwdump and
  # the Metasploit Express and Pro report types of "PWDump."
  #
  # This particular block scheme is temporary, since someone is
  # bound to want to import gigantic lists, so we'll want a
  # stream parser eventually (just like the other non-nmap formats).
  #
  # The file format is:
  # # 1.2.3.4:23/tcp (telnet)
  # username password
  # user2 p\x01a\x02ss2
  # <BLANK> pass3
  # user3 <BLANK>
  # smbuser:sid:lmhash:nthash:::
  #
  # Note the leading hash for the host:port line. Note also all usernames
  # and passwords must be in 7-bit ASCII (character sequences of "\x01"
  # will be interpolated -- this includes spaces, which must be notated
  # as "\x20". Blank usernames or passwords should be <BLANK>.
  #
  def import_msf_pwdump(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    last_host = nil

    addr  = nil
    port  = nil
    proto = nil
    sname = nil
    ptype = nil
    active = false # Are there cases where imported creds are good? I just hate trusting the import right away.

    data.each_line do |line|
      case line
      when /^[\s]*#/ # Comment lines
        if line[/^#[\s]*([0-9.]+):([0-9]+)(\x2f(tcp|udp))?[\s]*(\x28([^\x29]*)\x29)?/n]
          addr = $1
          port = $2
          proto = $4
          sname = $6
        end
      when /^[\s]*Warning:/
        # Discard warning messages.
        next

      # SMB Hash
      when /^[\s]*([^\s:]+):[0-9]+:([A-Fa-f0-9]+:[A-Fa-f0-9]+):[^\s]*$/
        user = ([nil, "<BLANK>"].include?($1)) ? "" : $1
        pass = ([nil, "<BLANK>"].include?($2)) ? "" : $2
        ptype = "smb_hash"

      # SMB Hash
      when /^[\s]*([^\s:]+):([0-9]+):NO PASSWORD\*+:NO PASSWORD\*+[^\s]*$/
        user = ([nil, "<BLANK>"].include?($1)) ? "" : $1
        pass = ""
        ptype = "smb_hash"

      # SMB Hash with cracked plaintext, or just plain old plaintext
      when /^[\s]*([^\s:]+):(.+):[A-Fa-f0-9]*:[A-Fa-f0-9]*:::$/
        user = ([nil, "<BLANK>"].include?($1)) ? "" : $1
        pass = ([nil, "<BLANK>"].include?($2)) ? "" : $2
        ptype = "password"

      # Must be a user pass
      when /^[\s]*([\x21-\x7f]+)[\s]+([\x21-\x7f]+)?/n
        user = ([nil, "<BLANK>"].include?($1)) ? "" : dehex($1)
        pass = ([nil, "<BLANK>"].include?($2)) ? "" : dehex($2)
        ptype = "password"
      else # Some unknown line not broken by a space.
        next
      end

      next unless [addr,port,user,pass].compact.size == 4
      next unless ipv46_validator(addr) # Skip Malformed addrs
      next unless port[/^[0-9]+$/] # Skip malformed ports
      if bl.include? addr
        next
      else
        yield(:address,addr) if block and addr != last_host
        last_host = addr
      end

      cred_info = {
        :host      => addr,
        :port      => port,
        :user      => user,
        :pass      => pass,
        :type      => ptype,
        :workspace => wspace,
        :task      => args[:task]
      }
      cred_info[:proto] = proto if proto
      cred_info[:sname] = sname if sname
      cred_info[:active] = active

      report_auth_info(cred_info)
      user = pass = ptype = nil
    end

  end

  # If hex notation is present, turn them into a character.
  def dehex(str)
    hexen = str.scan(/\x5cx[0-9a-fA-F]{2}/n)
    hexen.each { |h|
      str.gsub!(h,h[2,2].to_i(16).chr)
    }
    return str
  end


  #
  # Nexpose Simple XML
  #
  # XXX At some point we'll want to make this a stream parser for dealing
  # with large results files
  #
  def import_nexpose_simplexml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_nexpose_simplexml(args.merge(:data => data))
  end

  # Import a Metasploit XML file.
  def import_msf_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_msf_xml(args.merge(:data => data))
  end

  # Import a Metasploit Express ZIP file. Note that this requires
  # a fair bit of filesystem manipulation, and is very much tied
  # up with the Metasploit Express ZIP file format export (for
  # obvious reasons). In the event directories exist, they will
  # be reused. If target files exist, they will be overwritten.
  #
  # XXX: Refactor so it's not quite as sanity-blasting.
  def import_msf_zip(args={}, &block)
    data = args[:data]
    wpsace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    new_tmp = ::File.join(Dir::tmpdir,"msf","imp_#{Rex::Text::rand_text_alphanumeric(4)}",@import_filedata[:zip_basename])
    if ::File.exists? new_tmp
      unless (::File.directory?(new_tmp) && ::File.writable?(new_tmp))
        raise DBImportError.new("Could not extract zip file to #{new_tmp}")
      end
    else
      FileUtils.mkdir_p(new_tmp)
    end
    @import_filedata[:zip_tmp] = new_tmp

    # Grab the list of unique basedirs over all entries.
    @import_filedata[:zip_tmp_subdirs] = @import_filedata[:zip_entry_names].map {|x| ::File.split(x)}.map {|x| x[0]}.uniq.reject {|x| x == "."}

    # mkdir all of the base directores we just pulled out, if they don't
    # already exist
    @import_filedata[:zip_tmp_subdirs].each {|sub|
      tmp_subdirs = ::File.join(@import_filedata[:zip_tmp],sub)
      if File.exists? tmp_subdirs
        unless (::File.directory?(tmp_subdirs) && File.writable?(tmp_subdirs))
          # if it exists but we can't write to it, give up
          raise DBImportError.new("Could not extract zip file to #{tmp_subdirs}")
        end
      else
        ::FileUtils.mkdir(tmp_subdirs)
      end
    }


    data.entries.each do |e|
      target = ::File.join(@import_filedata[:zip_tmp],e.name)
      ::File.unlink target if ::File.exists?(target) # Yep. Deleted.
      data.extract(e,target)
      if target =~ /^.*.xml$/
        target_data = ::File.open(target, "rb") {|f| f.read 1024}
        if import_filetype_detect(target_data) == :msf_xml
          @import_filedata[:zip_extracted_xml] = target
          #break
        end
      end
    end

    # This will kick the newly-extracted XML file through
    # the import_file process all over again.
    if @import_filedata[:zip_extracted_xml]
      new_args = args.dup
      new_args[:filename] = @import_filedata[:zip_extracted_xml]
      new_args[:data] = nil
      new_args[:ifd] = @import_filedata.dup
      if block
        import_file(new_args, &block)
      else
        import_file(new_args)
      end
    end

    # Kick down to all the MSFX ZIP specific items
    if block
      import_msf_collateral(new_args, &block)
    else
      import_msf_collateral(new_args)
    end
  end

  # Imports loot, tasks, and reports from an MSF ZIP report.
  # XXX: This function is stupidly long. It needs to be refactored.
  def import_msf_collateral(args={}, &block)
    data = ::File.open(args[:filename], "rb") {|f| f.read(f.stat.size)}
    wspace = args[:wspace] || args['wspace'] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    basedir = args[:basedir] || args['basedir'] || ::File.join(Msf::Config.install_root, "data", "msf")

    allow_yaml = false
    btag = nil

    doc = rexmlify(data)
    if doc.elements["MetasploitExpressV1"]
      m_ver = 1
      allow_yaml = true
      btag = "MetasploitExpressV1"
    elsif doc.elements["MetasploitExpressV2"]
      m_ver = 2
      allow_yaml = true
      btag = "MetasploitExpressV2"
    elsif doc.elements["MetasploitExpressV3"]
      m_ver = 3
      btag = "MetasploitExpressV3"
    elsif doc.elements["MetasploitExpressV4"]
      m_ver = 4
      btag = "MetasploitExpressV4"
    elsif doc.elements["MetasploitV4"]
      m_ver = 4
      btag = "MetasploitV4"
    else
      m_ver = nil
    end
    unless m_ver and btag
      raise DBImportError.new("Unsupported Metasploit XML document format")
    end

    host_info = {}
    doc.elements.each("/#{btag}/hosts/host") do |host|
      host_info[host.elements["id"].text.to_s.strip] = nils_for_nulls(host.elements["address"].text.to_s.strip)
    end

    # Import Loot
    doc.elements.each("/#{btag}/loots/loot") do |loot|
      next if bl.include? host_info[loot.elements["host-id"].text.to_s.strip]
      loot_info              = {}
      loot_info[:host]       = host_info[loot.elements["host-id"].text.to_s.strip]
      loot_info[:workspace]  = args[:wspace]
      loot_info[:ctype]      = nils_for_nulls(loot.elements["content-type"].text.to_s.strip)
      loot_info[:info]       = nils_for_nulls(unserialize_object(loot.elements["info"], allow_yaml))
      loot_info[:ltype]      = nils_for_nulls(loot.elements["ltype"].text.to_s.strip)
      loot_info[:name]       = nils_for_nulls(loot.elements["name"].text.to_s.strip)
      loot_info[:created_at] = nils_for_nulls(loot.elements["created-at"].text.to_s.strip)
      loot_info[:updated_at] = nils_for_nulls(loot.elements["updated-at"].text.to_s.strip)
      loot_info[:name]       = nils_for_nulls(loot.elements["name"].text.to_s.strip)
      loot_info[:orig_path]  = nils_for_nulls(loot.elements["path"].text.to_s.strip)
      loot_info[:task]       = args[:task]
      tmp = args[:ifd][:zip_tmp]
      loot_info[:orig_path].gsub!(/^\./,tmp) if loot_info[:orig_path]
      if !loot.elements["service-id"].text.to_s.strip.empty?
        unless loot.elements["service-id"].text.to_s.strip == "NULL"
          loot_info[:service] = loot.elements["service-id"].text.to_s.strip
        end
      end

      # Only report loot if we actually have it.
      # TODO: Copypasta. Seperate this out.
      if ::File.exists? loot_info[:orig_path]
        loot_dir = ::File.join(basedir,"loot")
        loot_file = ::File.split(loot_info[:orig_path]).last
        if ::File.exists? loot_dir
          unless (::File.directory?(loot_dir) && ::File.writable?(loot_dir))
            raise DBImportError.new("Could not move files to #{loot_dir}")
          end
        else
          ::FileUtils.mkdir_p(loot_dir)
        end
        new_loot = ::File.join(loot_dir,loot_file)
        loot_info[:path] = new_loot
        if ::File.exists?(new_loot)
          ::File.unlink new_loot # Delete it, and don't report it.
        else
          report_loot(loot_info) # It's new, so report it.
        end
        ::FileUtils.copy(loot_info[:orig_path], new_loot)
        yield(:msf_loot, new_loot) if block
      end
    end

    # Import Tasks
    doc.elements.each("/#{btag}/tasks/task") do |task|
      task_info = {}
      task_info[:workspace] = args[:wspace]
      # Should user be imported (original) or declared (the importing user)?
      task_info[:user] = nils_for_nulls(task.elements["created-by"].text.to_s.strip)
      task_info[:desc] = nils_for_nulls(task.elements["description"].text.to_s.strip)
      task_info[:info] = nils_for_nulls(unserialize_object(task.elements["info"], allow_yaml))
      task_info[:mod] = nils_for_nulls(task.elements["module"].text.to_s.strip)
      task_info[:options] = nils_for_nulls(task.elements["options"].text.to_s.strip)
      task_info[:prog] = nils_for_nulls(task.elements["progress"].text.to_s.strip).to_i
      task_info[:created_at] = nils_for_nulls(task.elements["created-at"].text.to_s.strip)
      task_info[:updated_at] = nils_for_nulls(task.elements["updated-at"].text.to_s.strip)
      if !task.elements["completed-at"].text.to_s.empty?
        task_info[:completed_at] = nils_for_nulls(task.elements["completed-at"].text.to_s.strip)
      end
      if !task.elements["error"].text.to_s.empty?
        task_info[:error] = nils_for_nulls(task.elements["error"].text.to_s.strip)
      end
      if !task.elements["result"].text.to_s.empty?
        task_info[:result] = nils_for_nulls(task.elements["result"].text.to_s.strip)
      end
      task_info[:orig_path] = nils_for_nulls(task.elements["path"].text.to_s.strip)
      tmp = args[:ifd][:zip_tmp]
      task_info[:orig_path].gsub!(/^\./,tmp) if task_info[:orig_path]

      # Only report a task if we actually have it.
      # TODO: Copypasta. Seperate this out.
      if ::File.exists? task_info[:orig_path]
        tasks_dir = ::File.join(basedir,"tasks")
        task_file = ::File.split(task_info[:orig_path]).last
        if ::File.exists? tasks_dir
          unless (::File.directory?(tasks_dir) && ::File.writable?(tasks_dir))
            raise DBImportError.new("Could not move files to #{tasks_dir}")
          end
        else
          ::FileUtils.mkdir_p(tasks_dir)
        end
        new_task = ::File.join(tasks_dir,task_file)
        task_info[:path] = new_task
        if ::File.exists?(new_task)
          ::File.unlink new_task # Delete it, and don't report it.
        else
          report_task(task_info) # It's new, so report it.
        end
        ::FileUtils.copy(task_info[:orig_path], new_task)
        yield(:msf_task, new_task) if block
      end
    end

    # Import Reports
    doc.elements.each("/#{btag}/reports/report") do |report|
      tmp = args[:ifd][:zip_tmp]
      report_info              = {}
      report_info[:workspace]  = args[:wspace]
      # Should user be imported (original) or declared (the importing user)?
      report_info[:user]       = nils_for_nulls(report.elements["created-by"].text.to_s.strip)
      report_info[:options]    = nils_for_nulls(report.elements["options"].text.to_s.strip)
      report_info[:rtype]      = nils_for_nulls(report.elements["rtype"].text.to_s.strip)
      report_info[:created_at] = nils_for_nulls(report.elements["created-at"].text.to_s.strip)
      report_info[:updated_at] = nils_for_nulls(report.elements["updated-at"].text.to_s.strip)
      report_info[:orig_path]  = nils_for_nulls(report.elements["path"].text.to_s.strip)
      report_info[:task]       = args[:task]
      report_info[:orig_path].gsub!(/^\./, tmp) if report_info[:orig_path]

      # Only report a report if we actually have it.
      # TODO: Copypasta. Seperate this out.
      if ::File.exists? report_info[:orig_path]
        reports_dir = ::File.join(basedir,"reports")
        report_file = ::File.split(report_info[:orig_path]).last
        if ::File.exists? reports_dir
          unless (::File.directory?(reports_dir) && ::File.writable?(reports_dir))
            raise DBImportError.new("Could not move files to #{reports_dir}")
          end
        else
          ::FileUtils.mkdir_p(reports_dir)
        end
        new_report = ::File.join(reports_dir,report_file)
        report_info[:path] = new_report
        if ::File.exists?(new_report)
          ::File.unlink new_report
        else
          report_report(report_info)
        end
        ::FileUtils.copy(report_info[:orig_path], new_report)
        yield(:msf_report, new_report) if block
      end
    end

  end

  # Convert the string "NULL" to actual nil
  def nils_for_nulls(str)
    str == "NULL" ? nil : str
  end

  def import_nexpose_simplexml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_nexpose_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_nexpose_noko_stream(noko_args)
      end
      return true
    end
    data = args[:data]

    doc = rexmlify(data)
    doc.elements.each('/NeXposeSimpleXML/devices/device') do |dev|
      addr = dev.attributes['address'].to_s
      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end

      fprint = {}

      dev.elements.each('fingerprint/description') do |str|
        fprint[:desc] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/vendor') do |str|
        fprint[:vendor] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/family') do |str|
        fprint[:family] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/product') do |str|
        fprint[:product] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/version') do |str|
        fprint[:version] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/architecture') do |str|
        fprint[:arch] = str.text.to_s.upcase.strip
      end

      conf = {
        :workspace => wspace,
        :host      => addr,
        :state     => Msf::HostState::Alive,
        :task      => args[:task]
      }

      host = report_host(conf)
      report_import_note(wspace, host)

      report_note(
        :workspace => wspace,
        :host      => host,
        :type      => 'host.os.nexpose_fingerprint',
        :data      => fprint,
        :task      => args[:task]
      )

      # Load vulnerabilities not associated with a service
      dev.elements.each('vulnerabilities/vulnerability') do |vuln|
        vid  = vuln.attributes['id'].to_s.downcase
        refs = process_nexpose_data_sxml_refs(vuln)
        next if not refs
        report_vuln(
          :workspace => wspace,
          :host      => host,
          :name      => 'NEXPOSE-' + vid,
          :info      => vid,
          :refs      => refs,
          :task      => args[:task]
        )
      end

      # Load the services
      dev.elements.each('services/service') do |svc|
        sname = svc.attributes['name'].to_s
        sprot = svc.attributes['protocol'].to_s.downcase
        sport = svc.attributes['port'].to_s.to_i
        next if sport == 0

        name = sname.split('(')[0].strip
        info = ''

        svc.elements.each('fingerprint/description') do |str|
          info = str.text.to_s.strip
        end

        if(sname.downcase != '<unknown>')
          report_service(
              :workspace => wspace,
              :host      => host,
              :proto     => sprot,
              :port      => sport,
              :name      => name,
              :info      => info,
              :task      => args[:task]
          )
        else
          report_service(
              :workspace => wspace,
              :host      => host,
              :proto     => sprot,
              :port      => sport,
              :info      => info,
              :task      => args[:task]
          )
        end

        # Load vulnerabilities associated with this service
        svc.elements.each('vulnerabilities/vulnerability') do |vuln|
          vid  = vuln.attributes['id'].to_s.downcase
          refs = process_nexpose_data_sxml_refs(vuln)
          next if not refs
          report_vuln(
              :workspace => wspace,
              :host      => host,
              :port      => sport,
              :proto     => sprot,
              :name      => 'NEXPOSE-' + vid,
              :info      => vid,
              :refs      => refs,
              :task      => args[:task]
          )
        end
      end
    end
  end


  #
  # Nexpose Raw XML
  #
  def import_nexpose_rawxml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_nexpose_rawxml(args.merge(:data => data))
  end

  def import_nexpose_rawxml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_nexpose_raw_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_nexpose_raw_noko_stream(noko_args)
      end
      return true
    end
    data = args[:data]

    # Use a stream parser instead of a tree parser so we can deal with
    # huge results files without running out of memory.
    parser = Rex::Parser::NexposeXMLStreamParser.new

    # Since all the Refs have to be in the database before we can use them
    # in a Vuln, we store all the hosts until we finish parsing and only
    # then put everything in the database.  This is memory-intensive for
    # large files, but should be much less so than a tree parser.
    #
    # This method is also considerably faster than parsing through the tree
    # looking for references every time we hit a vuln.
    hosts = []
    vulns = []

    # The callback merely populates our in-memory table of hosts and vulns
    parser.callback = Proc.new { |type, value|
      case type
      when :host
        # XXX: Blacklist should be checked here instead of saving a
        # host we're just going to throw away later
        hosts.push(value)
      when :vuln
        value["id"] = value["id"].downcase if value["id"]
        vulns.push(value)
      end
    }

    REXML::Document.parse_stream(data, parser)

    vuln_refs = nexpose_refs_to_struct(vulns)
    hosts.each do |host|
      if bl.include? host["addr"]
        next
      else
        yield(:address,host["addr"]) if block
      end
      nexpose_host_from_rawxml(host, vuln_refs, wspace)
    end
  end

  #
  # Takes an array of vuln hashes, as returned by the NeXpose rawxml stream
  # parser, like:
  #   [
  #     {"id"=>"winreg-notes-protocol-handler", severity="8", "refs"=>[{"source"=>"BID", "value"=>"10600"}, ...]}
  #     {"id"=>"windows-zotob-c", severity="8", "refs"=>[{"source"=>"BID", "value"=>"14513"}, ...]}
  #   ]
  # and transforms it into a struct, containing :id, :refs, :title, and :severity
  #
  # Other attributes can be added later, as needed.
  def nexpose_refs_to_struct(vulns)
    ret = []
    vulns.each do |vuln|
      next if ret.map {|v| v.id}.include? vuln["id"]
      vstruct = Struct.new(:id, :refs, :title, :severity).new
      vstruct.id = vuln["id"]
      vstruct.title = vuln["title"]
      vstruct.severity = vuln["severity"]
      vstruct.refs = []
      vuln["refs"].each do |ref|
        if ref['source'] == 'BID'
          vstruct.refs.push('BID-' + ref["value"])
        elsif ref['source'] == 'CVE'
          # value is CVE-$ID
          vstruct.refs.push(ref["value"])
        elsif ref['source'] == 'MS'
          vstruct.refs.push('MSB-' + ref["value"])
        elsif ref['source'] == 'URL'
          vstruct.refs.push('URL-' + ref["value"])
        end
      end
      ret.push vstruct
    end
    return ret
  end

  # Takes a Host object, an array of vuln structs (generated by nexpose_refs_to_struct()),
  # and a workspace, and reports the vulns on that host.
  def nexpose_host_from_rawxml(h, vstructs, wspace,task=nil)
    hobj = nil
    data = {:workspace => wspace}
    if h["addr"]
      addr = h["addr"]
    else
      # Can't report it if it doesn't have an IP
      return
    end
    data[:host] = addr
    if (h["hardware-address"])
      # Put colons between each octet of the MAC address
      data[:mac] = h["hardware-address"].gsub(':', '').scan(/../).join(':')
    end
    data[:state] = (h["status"] == "alive") ? Msf::HostState::Alive : Msf::HostState::Dead

    # Since we only have one name field per host in the database, just
    # take the first one.
    if (h["names"] and h["names"].first)
      data[:name] = h["names"].first
    end

    if (data[:state] != Msf::HostState::Dead)
      hobj = report_host(data)
      report_import_note(wspace, hobj)
    end

    if h["notes"]
      note = {
          :workspace => wspace,
          :host      => (hobj || addr),
          :type      => "host.vuln.nexpose_keys",
          :data      => {},
          :mode      => :unique_data,
          :task      => task
      }
      h["notes"].each do |v,k|
        note[:data][v] ||= []
        next if note[:data][v].include? k
        note[:data][v] << k
      end
      report_note(note)
    end

    if h["os_family"]
      note = {
          :workspace => wspace,
          :host      => hobj || addr,
          :type      => 'host.os.nexpose_fingerprint',
          :task      => task,
          :data      => {
              :family    => h["os_family"],
              :certainty => h["os_certainty"]
          }
      }
      note[:data][:vendor]  = h["os_vendor"]  if h["os_vendor"]
      note[:data][:product] = h["os_product"] if h["os_product"]
      note[:data][:version] = h["os_version"] if h["os_version"]
      note[:data][:arch]    = h["arch"]       if h["arch"]

      report_note(note)
    end

    h["endpoints"].each { |p|
      extra = ""
      extra << p["product"] + " " if p["product"]
      extra << p["version"] + " " if p["version"]

      # Skip port-0 endpoints
      next if p["port"].to_i == 0

      # XXX This should probably be handled in a more standard way
      # extra << "(" + p["certainty"] + " certainty) " if p["certainty"]

      data             = {}
      data[:workspace] = wspace
      data[:proto]     = p["protocol"].downcase
      data[:port]      = p["port"].to_i
      data[:state]     = p["status"]
      data[:host]      = hobj || addr
      data[:info]      = extra if not extra.empty?
      data[:task]      = task
      if p["name"] != "<unknown>"
        data[:name] = p["name"]
      end
      report_service(data)
    }

    h["vulns"].each_pair { |k,v|

      next if v["status"] !~ /^vulnerable/
      vstruct = vstructs.select {|vs| vs.id.to_s.downcase == v["id"].to_s.downcase}.first
      next unless vstruct
      data             = {}
      data[:workspace] = wspace
      data[:host]      = hobj || addr
      data[:proto]     = v["protocol"].downcase if v["protocol"]
      data[:port]      = v["port"].to_i if v["port"]
      data[:name]      = "NEXPOSE-" + v["id"]
      data[:info]      = vstruct.title
      data[:refs]      = vstruct.refs
      data[:task]      = task
      report_vuln(data)
    }
  end


  #
  # Retina XML
  #

  # Process a Retina XML file
  def import_retina_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_retina_xml(args.merge(:data => data))
  end

  # Process Retina XML
  def import_retina_xml(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    msg =  "Warning: The Retina XML format does not associate vulnerabilities with the\n"
    msg << "specific service on which they were found.\n"
    msg << "This makes it impossible to correlate exploits to discovered vulnerabilities\n"
    msg << "in a reliable fashion."

    yield(:warning,msg) if block

    parser = Rex::Parser::RetinaXMLStreamParser.new
    parser.on_found_host = Proc.new do |host|
      hobj = nil
      data = {:workspace => wspace}
      addr = host['address']
      next if not addr

      next if bl.include? addr
      data[:host] = addr

      if host['mac']
        data[:mac] = host['mac']
      end

      data[:state] = Msf::HostState::Alive

      if host['hostname']
        data[:name] = host['hostname']
      end

      if host['netbios']
        data[:name] = host['netbios']
      end

      yield(:address, data[:host]) if block

      # Import Host
      hobj = report_host(data)
      report_import_note(wspace, hobj)

      # Import OS fingerprint
      if host["os"]
        note = {
            :workspace => wspace,
            :host      => addr,
            :type      => 'host.os.retina_fingerprint',
            :task      => args[:task],
            :data      => {
                :os => host["os"]
            }
        }
        report_note(note)
      end

      # Import vulnerabilities
      host['vulns'].each do |vuln|
        refs = vuln['refs'].map{|v| v.join("-")}
        refs << "RETINA-#{vuln['rthid']}" if vuln['rthid']

        vuln_info = {
            :workspace => wspace,
            :host      => addr,
            :name      => vuln['name'],
            :info      => vuln['description'],
            :refs      => refs,
            :task      => args[:task]
        }

        report_vuln(vuln_info)
      end
    end

    REXML::Document.parse_stream(data, parser)
  end

  #
  # NetSparker XML
  #

  # Process a NetSparker XML file
  def import_netsparker_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_netsparker_xml(args.merge(:data => data))
  end

  # Process NetSparker XML
  def import_netsparker_xml(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    addr = nil
    parser = Rex::Parser::NetSparkerXMLStreamParser.new
    parser.on_found_vuln = Proc.new do |vuln|
      data = {:workspace => wspace}

      # Parse the URL
      url  = vuln['url']
      return if not url

      # Crack the URL into a URI
      uri = URI(url) rescue nil
      return if not uri

      # Resolve the host and cache the IP
      if not addr
        baddr = Rex::Socket.addr_aton(uri.host) rescue nil
        if baddr
          addr = Rex::Socket.addr_ntoa(baddr)
          yield(:address, addr) if block
        end
      end

      # Bail early if we have no IP address
      if not addr
        raise Interrupt, "Not a valid IP address"
      end

      if bl.include?(addr)
        raise Interrupt, "IP address is on the blacklist"
      end

      data[:host]  = addr
      data[:vhost] = uri.host
      data[:port]  = uri.port
      data[:ssl]   = (uri.scheme == "ssl")

      body = nil
      # First report a web page
      if vuln['response']
        headers = {}
        code    = 200
        head,body = vuln['response'].to_s.split(/\r?\n\r?\n/, 2)
        if body

          if head =~ /^HTTP\d+\.\d+\s+(\d+)\s*/
            code = $1.to_i
          end

          headers = {}
          head.split(/\r?\n/).each do |line|
            hname,hval = line.strip.split(/\s*:\s*/, 2)
            next if hval.to_s.strip.empty?
            headers[hname.downcase] ||= []
            headers[hname.downcase] << hval
          end

          info = {
            :path     => uri.path,
            :query    => uri.query,
            :code     => code,
            :body     => body,
            :headers  => headers,
            :task     => args[:task]
          }
          info.merge!(data)

          if headers['content-type']
            info[:ctype] = headers['content-type'][0]
          end

          if headers['set-cookie']
            info[:cookie] = headers['set-cookie'].join("\n")
          end

          if headers['authorization']
            info[:auth] = headers['authorization'].join("\n")
          end

          if headers['location']
            info[:location] = headers['location'][0]
          end

          if headers['last-modified']
            info[:mtime] = headers['last-modified'][0]
          end

          # Report the web page to the database
          report_web_page(info)

          yield(:web_page, url) if block
        end
      end # End web_page reporting


      details = netsparker_vulnerability_map(vuln)

      method = netsparker_method_map(vuln)
      pname  = netsparker_pname_map(vuln)
      params = netsparker_params_map(vuln)

      proof  = ''

      if vuln['info'] and vuln['info'].length > 0
        proof << vuln['info'].map{|x| "#{x[0]}: #{x[1]}\n" }.join + "\n"
      end

      if proof.empty?
        if body
          proof << body + "\n"
        else
          proof << vuln['response'].to_s + "\n"
        end
      end

      if params.empty? and pname
        params = [[pname, vuln['vparam_name'].to_s]]
      end

      info = {
        # XXX: There is a :request attr in the model, but report_web_vuln
        # doesn't seem to know about it, so this gets ignored.
        #:request  => vuln['request'],
        :path        => uri.path,
        :query       => uri.query,
        :method      => method,
        :params      => params,
        :pname       => pname.to_s,
        :proof       => proof,
        :risk        => details[:risk],
        :name        => details[:name],
        :blame       => details[:blame],
        :category    => details[:category],
        :description => details[:description],
        :confidence  => details[:confidence],
        :task        => args[:task]
      }
      info.merge!(data)

      next if vuln['type'].to_s.empty?

      report_web_vuln(info)
      yield(:web_vuln, url) if block
    end

    # We throw interrupts in our parser when the job is hopeless
    begin
      REXML::Document.parse_stream(data, parser)
    rescue ::Interrupt => e
      wlog("The netsparker_xml_import() job was interrupted: #{e}")
    end
  end

  def netsparker_method_map(vuln)
    case vuln['vparam_type']
    when "FullQueryString"
      "GET"
    when "Querystring"
      "GET"
    when "Post"
      "POST"
    when "RawUrlInjection"
      "GET"
    else
      "GET"
    end
  end

  def netsparker_pname_map(vuln)
    case vuln['vparam_name']
    when "URI-BASED", "Query Based"
      "PATH"
    else
      vuln['vparam_name']
    end
  end

  def netsparker_params_map(vuln)
    []
  end

  def netsparker_vulnerability_map(vuln)
    res = {
      :risk => 1,
      :name  => 'Information Disclosure',
      :blame => 'System Administrator',
      :category => 'info',
      :description => "This is an information leak",
      :confidence => 100
    }

    # Risk is a value from 1-5 indicating the severity of the issue
    #	Examples: 1, 4, 5

    # Name is a descriptive name for this vulnerability.
    #	Examples: XSS, ReflectiveXSS, PersistentXSS

    # Blame indicates who is at fault for the vulnerability
    #	Examples: App Developer, Server Developer, System Administrator

    # Category indicates the general class of vulnerability
    #	Examples: info, xss, sql, rfi, lfi, cmd

    # Description is a textual summary of the vulnerability
    #	Examples: "A reflective cross-site scripting attack"
    #             "The web server leaks the internal IP address"
    #             "The cookie is not set to HTTP-only"

    #
    # Confidence is a value from 1 to 100 indicating how confident the
    # software is that the results are valid.
    #	Examples: 100, 90, 75, 15, 10, 0

    case vuln['type'].to_s
    when "ApacheDirectoryListing"
      res = {
        :risk => 1,
        :name  => 'Directory Listing',
        :blame => 'System Administrator',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "ApacheMultiViewsEnabled"
      res = {
        :risk => 1,
        :name  => 'Apache MultiViews Enabled',
        :blame => 'System Administrator',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "ApacheVersion"
      res = {
        :risk => 1,
        :name  => 'Web Server Version',
        :blame => 'System Administrator',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PHPVersion"
      res = {
        :risk => 1,
        :name  => 'PHP Module Version',
        :blame => 'System Administrator',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "AutoCompleteEnabled"
      res = {
        :risk => 1,
        :name  => 'Form AutoComplete Enabled',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "CookieNotMarkedAsHttpOnly"
      res = {
        :risk => 1,
        :name  => 'Cookie Not HttpOnly',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "EmailDisclosure"
      res = {
        :risk => 1,
        :name  => 'Email Address Disclosure',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "ForbiddenResource"
      res = {
        :risk => 1,
        :name  => 'Forbidden Resource',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "FileUploadFound"
      res = {
        :risk => 1,
        :name  => 'File Upload Form',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PasswordOverHTTP"
      res = {
        :risk => 2,
        :name  => 'Password Over HTTP',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "MySQL5Identified"
      res = {
        :risk => 1,
        :name  => 'MySQL 5 Identified',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PossibleInternalWindowsPathLeakage"
      res = {
        :risk => 1,
        :name  => 'Path Leakage - Windows',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PossibleInternalUnixPathLeakage"
      res = {
        :risk => 1,
        :name  => 'Path Leakage - Unix',
        :blame => 'App Developer',
        :category => 'info',
        :description => "",
        :confidence => 100
      }
    when "PossibleXSS", "LowPossibilityPermanentXSS", "XSS", "PermanentXSS"
      conf = 100
      conf = 25  if vuln['type'].to_s == "LowPossibilityPermanentXSS"
      conf = 50  if vuln['type'].to_s == "PossibleXSS"
      res = {
        :risk => 3,
        :name  => 'Cross-Site Scripting',
        :blame => 'App Developer',
        :category => 'xss',
        :description => "",
        :confidence => conf
      }

    when "ConfirmedBlindSQLInjection", "ConfirmedSQLInjection", "HighlyPossibleSqlInjection", "DatabaseErrorMessages"
      conf = 100
      conf = 90  if vuln['type'].to_s == "HighlyPossibleSqlInjection"
      conf = 25  if vuln['type'].to_s == "DatabaseErrorMessages"
      res = {
        :risk => 5,
        :name  => 'SQL Injection',
        :blame => 'App Developer',
        :category => 'sql',
        :description => "",
        :confidence => conf
      }
    else
    conf = 100
    res = {
      :risk => 1,
      :name  => vuln['type'].to_s,
      :blame => 'App Developer',
      :category => 'info',
      :description => "",
      :confidence => conf
    }
    end

    res
  end

  def import_fusionvm_xml(args={})
    args[:wspace] ||= workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    doc = Rex::Parser::FusionVMDocument.new(args,self)
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end


  #
  # Import Nmap's -oX xml output
  #
  def import_nmap_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_nmap_xml(args.merge(:data => data))
  end

  def import_nexpose_raw_noko_stream(args, &block)
    if block
      doc = Rex::Parser::NexposeRawDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::NexposeRawDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_nexpose_noko_stream(args, &block)
    if block
      doc = Rex::Parser::NexposeSimpleDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::NexposeSimpleDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_nmap_noko_stream(args, &block)
    if block
      doc = Rex::Parser::NmapDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::NmapDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  # If you have Nokogiri installed, you'll be shunted over to
  # that. Otherwise, you'll hit the old NmapXMLStreamParser.
  def import_nmap_xml(args={}, &block)
    return nil if args[:data].nil? or args[:data].empty?
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    if Rex::Parser.nokogiri_loaded
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, "Nokogiri v#{::Nokogiri::VERSION}")
        import_nmap_noko_stream(noko_args) {|type, data| yield type,data }
      else
        import_nmap_noko_stream(noko_args)
      end
      return true
    end

    # XXX: Legacy nmap xml parser starts here.

    fix_services = args[:fix_services]
    data = args[:data]

    # Use a stream parser instead of a tree parser so we can deal with
    # huge results files without running out of memory.
    parser = Rex::Parser::NmapXMLStreamParser.new
    yield(:parser, parser.class.name) if block

    # Whenever the parser pulls a host out of the nmap results, store
    # it, along with any associated services, in the database.
    parser.on_found_host = Proc.new { |h|
      hobj = nil
      data = {:workspace => wspace}
      if (h["addrs"].has_key?("ipv4"))
        addr = h["addrs"]["ipv4"]
      elsif (h["addrs"].has_key?("ipv6"))
        addr = h["addrs"]["ipv6"]
      else
        # Can't report it if it doesn't have an IP
        raise RuntimeError, "At least one IPv4 or IPv6 address is required"
      end
      next if bl.include? addr
      data[:host] = addr
      if (h["addrs"].has_key?("mac"))
        data[:mac] = h["addrs"]["mac"]
      end
      data[:state] = (h["status"] == "up") ? Msf::HostState::Alive : Msf::HostState::Dead
      data[:task] = args[:task]

      if ( h["reverse_dns"] )
        data[:name] = h["reverse_dns"]
      end

      # Only report alive hosts with ports to speak of.
      if(data[:state] != Msf::HostState::Dead)
        if h["ports"].size > 0
          if fix_services
            port_states = h["ports"].map {|p| p["state"]}.reject {|p| p == "filtered"}
            next if port_states.compact.empty?
          end
          yield(:address,data[:host]) if block
          hobj = report_host(data)
          report_import_note(wspace,hobj)
        end
      end

      if( h["os_vendor"] )
        note = {
          :workspace => wspace,
          :host => hobj || addr,
          :type => 'host.os.nmap_fingerprint',
          :task => args[:task],
          :data => {
            :os_vendor   => h["os_vendor"],
            :os_family   => h["os_family"],
            :os_version  => h["os_version"],
            :os_accuracy => h["os_accuracy"]
          }
        }

        if(h["os_match"])
          note[:data][:os_match] = h['os_match']
        end

        report_note(note)
      end

      if (h["last_boot"])
        report_note(
          :workspace => wspace,
          :host => hobj || addr,
          :type => 'host.last_boot',
          :task => args[:task],
          :data => {
            :time => h["last_boot"]
          }
        )
      end

      if (h["trace"])
        hops = []
        h["trace"]["hops"].each do |hop|
          hops << {
            "ttl"     => hop["ttl"].to_i,
            "address" => hop["ipaddr"].to_s,
            "rtt"     => hop["rtt"].to_f,
            "name"    => hop["host"].to_s
          }
        end
        report_note(
          :workspace => wspace,
          :host => hobj || addr,
          :type => 'host.nmap.traceroute',
          :task => args[:task],
          :data => {
            'port'  => h["trace"]["port"].to_i,
            'proto' => h["trace"]["proto"].to_s,
            'hops'  => hops
          }
        )
      end


      # Put all the ports, regardless of state, into the db.
      h["ports"].each { |p|
        # Localhost port results are pretty unreliable -- if it's
        # unknown, it's no good (possibly Windows-only)
        if (
          p["state"] == "unknown" &&
          h["status_reason"] == "localhost-response"
        )
          next
        end
        extra = ""
        extra << p["product"]   + " " if p["product"]
        extra << p["version"]   + " " if p["version"]
        extra << p["extrainfo"] + " " if p["extrainfo"]

        data = {}
        data[:workspace] = wspace
        if fix_services
          data[:proto] = nmap_msf_service_map(p["protocol"])
        else
          data[:proto] = p["protocol"].downcase
        end
        data[:port]  = p["portid"].to_i
        data[:state] = p["state"]
        data[:host]  = hobj || addr
        data[:info]  = extra if not extra.empty?
        data[:task]  = args[:task]
        if p["name"] != "unknown"
          data[:name] = p["name"]
        end
        report_service(data)
      }
      #Parse the scripts output
      if h["scripts"]
        h["scripts"].each do |key,val|
          if key == "smb-check-vulns"
            if val =~ /MS08-067: VULNERABLE/
              vuln_info = {
                :workspace => wspace,
                :task => args[:task],
                :host =>  hobj || addr,
                :port => 445,
                :proto => 'tcp',
                :name => 'MS08-067',
                :info => 'Microsoft Windows Server Service Crafted RPC Request Handling Unspecified Remote Code Execution',
                :refs =>['CVE-2008-4250',
                  'BID-31874',
                  'OSVDB-49243',
                  'CWE-94',
                  'MSFT-MS08-067',
                  'MSF-Microsoft Server Service Relative Path Stack Corruption',
                  'NSS-34476']
              }
              report_vuln(vuln_info)
            end
            if val =~ /MS06-025: VULNERABLE/
              vuln_info = {
                :workspace => wspace,
                :task => args[:task],
                :host =>  hobj || addr,
                :port => 445,
                :proto => 'tcp',
                :name => 'MS06-025',
                :info => 'Vulnerability in Routing and Remote Access Could Allow Remote Code Execution',
                :refs =>['CVE-2006-2370',
                  'CVE-2006-2371',
                  'BID-18325',
                  'BID-18358',
                  'BID-18424',
                  'OSVDB-26436',
                  'OSVDB-26437',
                  'MSFT-MS06-025',
                  'MSF-Microsoft RRAS Service RASMAN Registry Overflow',
                  'NSS-21689']
              }
              report_vuln(vuln_info)
            end
            # This one has NOT been  Tested , remove this comment if confirmed working
            if val =~ /MS07-029: VULNERABLE/
              vuln_info = {
                :workspace => wspace,
                :task => args[:task],
                :host =>  hobj || addr,
                :port => 445,
                :proto => 'tcp',
                :name => 'MS07-029',
                :info => 'Vulnerability in Windows DNS RPC Interface Could Allow Remote Code Execution',
                # Add more refs based on nessus/nexpose .. results
                :refs =>['CVE-2007-1748',
                  'OSVDB-34100',
                  'MSF-Microsoft DNS RPC Service extractQuotedChar()',
                  'NSS-25168']
              }
              report_vuln(vuln_info)
            end
          end
        end
      end
    }

    # XXX: Legacy nmap xml parser ends here.

    REXML::Document.parse_stream(data, parser)
  end

  def nmap_msf_service_map(proto)
    service_name_map(proto)
  end

  #
  # This method normalizes an incoming service name to one of the
  # the standard ones recognized by metasploit
  #
  def service_name_map(proto)
    return proto unless proto.kind_of? String
    case proto.downcase
    when "msrpc", "nfs-or-iis", "dce endpoint resolution"
      "dcerpc"
    when "ms-sql-s", "tds"
      "mssql"
    when "ms-sql-m","microsoft sql monitor"
      "mssql-m"
    when "postgresql";                  "postgres"
    when "http-proxy";                  "http"
    when "iiimsf";                      "db2"
    when "oracle-tns";                  "oracle"
    when "quickbooksrds";               "metasploit"
    when "microsoft remote display protocol"
      "rdp"
    when "vmware authentication daemon"
      "vmauthd"
    when "netbios-ns", "cifs name service"
      "netbios"
    when "netbios-ssn", "microsoft-ds", "cifs"
      "smb"
    when "remote shell"
      "shell"
    when "remote login"
      "login"
    when "nfs lockd"
      "lockd"
    when "hp jetdirect"
      "jetdirect"
    when "dhcp server"
      "dhcp"
    when /^dns-(udp|tcp)$/;             "dns"
    when /^dce[\s+]rpc$/;               "dcerpc"
    else
      proto.downcase.gsub(/\s*\(.*/, '')   # "service (some service)"
    end
  end

  def report_import_note(wspace,addr)
    if @import_filedata.kind_of?(Hash) && @import_filedata[:filename] && @import_filedata[:filename] !~ /msfe-nmap[0-9]{8}/
    report_note(
      :workspace => wspace,
      :host => addr,
      :type => 'host.imported',
      :data => @import_filedata.merge(:time=> Time.now.utc)
    )
    end
  end

  #
  # Import Nessus NBE files
  #
  def import_nessus_nbe_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_nessus_nbe(args.merge(:data => data))
  end

  # There is no place the NBE actually stores the plugin name used to
  # scan. You get "Security Note" or "Security Warning," and that's it.
  def import_nessus_nbe(args={}, &block)
    nbe_data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    nbe_copy = nbe_data.dup
    # First pass, just to build the address map.
    addr_map = {}

    # Cache host objects before passing into handle_nessus()
    hobj_map = {}

    nbe_copy.each_line do |line|
      r = line.split('|')
      next if r[0] != 'results'
      next if r[4] != "12053"
      data = r[6]
      addr,hname = data.match(/([0-9\x2e]+) resolves as (.+)\x2e\\n/n)[1,2]
      addr_map[hname] = addr
    end

    nbe_data.each_line do |line|
      r = line.split('|')
      next if r[0] != 'results'
      hname = r[2]
      if addr_map[hname]
        addr = addr_map[hname]
      else
        addr = hname # Must be unresolved, probably an IP address.
      end
      port = r[3]
      nasl = r[4]
      type = r[5]
      data = r[6]

      # If there's no resolution, or if it's malformed, skip it.
      next unless ipv46_validator(addr)

      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end

      hobj_map[ addr ] ||= report_host(:host => addr, :workspace => wspace, :task => args[:task])

      # Match the NBE types with the XML severity ratings
      case type
      # log messages don't actually have any data, they are just
      # complaints about not being able to perform this or that test
      # because such-and-such was missing
      when "Log Message"; next
      when "Security Hole"; severity = 3
      when "Security Warning"; severity = 2
      when "Security Note"; severity = 1
      # a severity 0 means there's no extra data, it's just an open port
      else; severity = 0
      end
      if nasl == "11936"
        os = data.match(/The remote host is running (.*)\\n/)[1]
        report_note(
          :workspace => wspace,
          :task => args[:task],
          :host => hobj_map[ addr ],
          :type => 'host.os.nessus_fingerprint',
          :data => {
            :os => os.to_s.strip
          }
        )
      end

      next if nasl.to_s.strip.empty?
      plugin_name = nil # NBE doesn't ever populate this
      handle_nessus(wspace, hobj_map[ addr ], port, nasl, plugin_name, severity, data)
    end
  end

  #
  # Of course they had to change the nessus format.
  #
  def import_openvas_xml(args={}, &block)
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    raise DBImportError.new("No OpenVAS XML support. Please submit a patch to msfdev[at]metasploit.com")
  end

  #
  # Import IP360 XML v3 output
  #
  def import_ip360_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_ip360_xml_v3(args.merge(:data => data))
  end

  #
  # Import Nessus XML v1 and v2 output
  #
  # Old versions of openvas exported this as well
  #
  def import_nessus_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end

    if data.index("NessusClientData_v2")
      import_nessus_xml_v2(args.merge(:data => data))
    else
      import_nessus_xml(args.merge(:data => data))
    end
  end

  def import_nessus_xml(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    doc = rexmlify(data)
    doc.elements.each('/NessusClientData/Report/ReportHost') do |host|
      hobj = nil
      addr = nil
      hname = nil
      os = nil
      # If the name is resolved, the Nessus plugin for DNS
      # resolution should be there. If not, fall back to the
      # HostName
      host.elements.each('ReportItem') do |item|
        next unless item.elements['pluginID'].text == "12053"
        addr = item.elements['data'].text.match(/([0-9\x2e]+) resolves as/n)[1]
        hname = host.elements['HostName'].text
      end
      addr ||= host.elements['HostName'].text
      next unless ipv46_validator(addr) # Skip resolved names and SCAN-ERROR.
      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end

      hinfo = {
        :workspace => wspace,
        :host => addr,
        :task => args[:task]
      }

      # Record the hostname
      hinfo.merge!(:name => hname.to_s.strip) if hname
      hobj = report_host(hinfo)
      report_import_note(wspace,hobj)

      # Record the OS
      os ||= host.elements["os_name"]
      if os
        report_note(
          :workspace => wspace,
          :task => args[:task],
          :host => hobj,
          :type => 'host.os.nessus_fingerprint',
          :data => {
            :os => os.text.to_s.strip
          }
        )
      end

      host.elements.each('ReportItem') do |item|
        nasl = item.elements['pluginID'].text
        plugin_name = item.elements['pluginName'].text
        port = item.elements['port'].text
        data = item.elements['data'].text
        severity = item.elements['severity'].text

        handle_nessus(wspace, hobj, port, nasl, plugin_name, severity, data, args[:task])
      end
    end
  end

  def import_nessus_xml_v2(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    #@host = {
        #'hname'             => nil,
        #'addr'              => nil,
        #'mac'               => nil,
        #'os'                => nil,
        #'ports'             => [ 'port' => {    'port'              	=> nil,
        #					'svc_name'              => nil,
        #					'proto'              	=> nil,
        #					'severity'              => nil,
        #					'nasl'              	=> nil,
        #					'description'           => nil,
        #					'cve'                   => [],
        #					'bid'                   => [],
        #					'xref'                  => []
        #				}
        #			]
        #}
    parser = Rex::Parser::NessusXMLStreamParser.new
    parser.on_found_host = Proc.new { |host|

      hobj = nil
      addr = host['addr'] || host['hname']

      next unless ipv46_validator(addr) # Catches SCAN-ERROR, among others.

      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end

      os = host['os']
      hname = host['hname']
      mac = host['mac']

      host_info = {
        :workspace => wspace,
        :host => addr,
        :task => args[:task]
      }
      host_info[:name] = hname.to_s.strip if hname
      # Short mac, protect against Nessus's habit of saving multiple macs
      # We can't use them anyway, so take just the first.
      host_info[:mac]  = mac.to_s.strip.upcase.split(/\s+/).first if mac

      hobj = report_host(host_info)
      report_import_note(wspace,hobj)

      os = host['os']
      yield(:os,os) if block
      if os
        report_note(
          :workspace => wspace,
          :task => args[:task],
          :host => hobj,
          :type => 'host.os.nessus_fingerprint',
          :data => {
            :os => os.to_s.strip
          }
        )
      end

      host['ports'].each do |item|
        next if item['port'] == 0
        msf = nil
        nasl = item['nasl'].to_s
        nasl_name = item['nasl_name'].to_s
        port = item['port'].to_s
        proto = item['proto'] || "tcp"
        sname = item['svc_name']
        severity = item['severity']
        description = item['description']
        cve = item['cve']
        bid = item['bid']
        xref = item['xref']
        msf = item['msf']

        yield(:port,port) if block

        handle_nessus_v2(wspace, hobj, port, proto, sname, nasl, nasl_name, severity, description, cve, bid, xref, msf, args[:task])

      end
      yield(:end,hname) if block
    }

    REXML::Document.parse_stream(data, parser)

  end

  def import_mbsa_xml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_mbsa_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_mbsa_noko_stream(noko_args)
      end
      return true
    else # Sorry
      raise DBImportError.new("Could not import due to missing Nokogiri parser. Try 'gem install nokogiri'.")
    end
  end

  def import_mbsa_noko_stream(args={},&block)
    if block
      doc = Rex::Parser::MbsaDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::MbsaDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_foundstone_xml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_foundstone_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_foundstone_noko_stream(noko_args)
      end
      return true
    else # Sorry
      raise DBImportError.new("Could not import due to missing Nokogiri parser. Try 'gem install nokogiri'.")
    end
  end

  def import_foundstone_noko_stream(args={},&block)
    if block
      doc = Rex::Parser::FoundstoneDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::FoundstoneDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_acunetix_xml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_acunetix_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_acunetix_noko_stream(noko_args)
      end
      return true
    else # Sorry
      raise DBImportError.new("Could not import due to missing Nokogiri parser. Try 'gem install nokogiri'.")
    end
  end

  def import_ci_xml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_ci_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_ci_noko_stream(noko_args)
      end
      return true
    else # Sorry
      raise DBImportError.new("Could not import due to missing Nokogiri parser. Try 'gem install nokogiri'.")
    end
  end

  def import_acunetix_noko_stream(args={},&block)
    if block
      doc = Rex::Parser::AcunetixDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::AcunetixFoundstoneDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end


  def import_appscan_xml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_appscan_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_appscan_noko_stream(noko_args)
      end
      return true
    else # Sorry
      raise DBImportError.new("Could not import due to missing Nokogiri parser. Try 'gem install nokogiri'.")
    end
  end

  def import_appscan_noko_stream(args={},&block)
    if block
      doc = Rex::Parser::AppscanDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::AppscanDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_burp_session_xml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || workspace
    if Rex::Parser.nokogiri_loaded
      # Rex::Parser.reload("burp_session_nokogiri.rb")
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_burp_session_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_burp_session_noko_stream(noko_args)
      end
      return true
    else # Sorry
      raise DBImportError.new("Could not import due to missing Nokogiri parser. Try 'gem install nokogiri'.")
    end
  end

  def import_burp_session_noko_stream(args={},&block)
    if block
      doc = Rex::Parser::BurpSessionDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::BurpSessionDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end


  #
  # Import IP360's ASPL database
  #
  def import_ip360_aspl_xml(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    if not data.index("<ontology")
      raise DBImportError.new("The ASPL file does not appear to be valid or may still be compressed")
    end

    base = ::File.join(Msf::Config.config_directory, "data", "ncircle")
    ::FileUtils.mkdir_p(base)
    ::File.open(::File.join(base, "ip360.aspl"), "wb") do |fd|
      fd.write(data)
    end
    yield(:notice, "Saved the IP360 ASPL database to #{base}...")
  end


  #
  # Import IP360's xml output
  #
  def import_ip360_xml_v3(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    # @aspl = {'vulns' => {'name' => { }, 'cve' => { }, 'bid' => { } }
    # 'oses' => {'name' } }

    aspl_path  = nil
    aspl_paths = [
      ::File.join(Msf::Config.config_directory, "data", "ncircle", "ip360.aspl"),
      ::File.join(Msf::Config.data_directory, "ncircle", "ip360.aspl")
    ]

    aspl_paths.each do |tpath|
      next if not (::File.exist?(tpath) and ::File.readable?(tpath))
      aspl_path = tpath
      break
    end

    if not aspl_path
      raise DBImportError.new("The nCircle IP360 ASPL file is not present.\n    Download ASPL from nCircle VNE | Administer | Support | Resources, unzip it, and import it first")
    end

    # parse nCircle ASPL file
    aspl = ""
    ::File.open(aspl_path, "rb") do |f|
      aspl = f.read(f.stat.size)
    end

    @asplhash = nil
    parser = Rex::Parser::IP360ASPLXMLStreamParser.new
    parser.on_found_aspl = Proc.new { |asplh|
      @asplhash = asplh
    }
    REXML::Document.parse_stream(aspl, parser)

    # nCircle has some quotes escaped which causes the parser to break
    # we don't need these lines so just replace \" with "
    data.gsub!(/\\"/,'"')

    # parse nCircle Scan Output
    parser = Rex::Parser::IP360XMLStreamParser.new
    parser.on_found_host = Proc.new { |host|
      hobj = nil
      addr = host['addr'] || host['hname']

      next unless ipv46_validator(addr) # Catches SCAN-ERROR, among others.

      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end

      os = host['os']
      hname = host['hname']
      mac = host['mac']

      host_hash = {
        :workspace => wspace,
        :host => addr,
        :task => args[:task]
      }
      host_hash[:name] = hname.to_s.strip if hname
      host_hash[:mac]  = mac.to_s.strip.upcase if mac

      hobj = report_host(host_hash)

      yield(:os, os) if block
      if os
        report_note(
          :workspace => wspace,
          :task => args[:task],
          :host => hobj,
          :type => 'host.os.ip360_fingerprint',
          :data => {
            :os => @asplhash['oses'][os].to_s.strip
          }
        )
      end

      host['apps'].each do |item|
        port = item['port'].to_s
        proto = item['proto'].to_s

        handle_ip360_v3_svc(wspace, hobj, port, proto, hname, args[:task])
      end


      host['vulns'].each do |item|
        vulnid = item['vulnid'].to_s
        port = item['port'].to_s
        proto = item['proto'] || "tcp"
        vulnname = @asplhash['vulns']['name'][vulnid]
        cves = @asplhash['vulns']['cve'][vulnid]
        bids = @asplhash['vulns']['bid'][vulnid]

        yield(:port, port) if block

        handle_ip360_v3_vuln(wspace, hobj, port, proto, hname, vulnid, vulnname, cves, bids, args[:task])

      end

      yield(:end, hname) if block
    }

    REXML::Document.parse_stream(data, parser)
  end

  def find_qualys_asset_vuln_refs(doc)
    vuln_refs = {}
    doc.elements.each("/ASSET_DATA_REPORT/GLOSSARY/VULN_DETAILS_LIST/VULN_DETAILS") do |vuln|
      next unless vuln.elements['QID'] && vuln.elements['QID'].first
      qid = vuln.elements['QID'].first.to_s
      vuln_refs[qid] ||= []
      vuln.elements.each('CVE_ID_LIST/CVE_ID') do |ref|
        vuln_refs[qid].push('CVE-' + /C..-([0-9\-]{9})/.match(ref.elements['ID'].text.to_s)[1])
      end
      vuln.elements.each('BUGTRAQ_ID_LIST/BUGTRAQ_ID') do |ref|
        vuln_refs[qid].push('BID-' + ref.elements['ID'].text.to_s)
      end
    end
    return vuln_refs
  end

  # Pull out vulnerabilities that have at least one matching
  # ref -- many "vulns" are not vulns, just audit information.
  def find_qualys_asset_vulns(host,wspace,hobj,vuln_refs,&block)
    host.elements.each("VULN_INFO_LIST/VULN_INFO") do |vi|
      next unless vi.elements["QID"]
      vi.elements.each("QID") do |qid|
        next if vuln_refs[qid.text].nil? || vuln_refs[qid.text].empty?
        handle_qualys(wspace, hobj, nil, nil, qid.text, nil, vuln_refs[qid.text], nil,nil, args[:task])
      end
    end
  end

  # Takes QID numbers and finds the discovered services in
  # a qualys_asset_xml.
  def find_qualys_asset_ports(i,host,wspace,hobj)
    return unless (i == 82023 || i == 82004)
    proto = i == 82023 ? 'tcp' : 'udp'
    qid = host.elements["VULN_INFO_LIST/VULN_INFO/QID[@id='qid_#{i}']"]
    qid_result = qid.parent.elements["RESULT[@format='table']"] if qid
    hports = qid_result.first.to_s if qid_result
    if hports
      hports.scan(/([0-9]+)\t(.*?)\t.*?\t([^\t\n]*)/) do |match|
        if match[2] == nil or match[2].strip == 'unknown'
          name = match[1].strip
        else
          name = match[2].strip
        end
        handle_qualys(wspace, hobj, match[0].to_s, proto, 0, nil, nil, name, nil, args[:task])
      end
    end
  end

  #
  # Import Qualys's Asset Data Report format
  #
  def import_qualys_asset_xml(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    doc = rexmlify(data)
    vuln_refs = find_qualys_asset_vuln_refs(doc)

    # 2nd pass, actually grab the hosts.
    doc.elements.each("/ASSET_DATA_REPORT/HOST_LIST/HOST") do |host|
      hobj = nil
      addr = host.elements["IP"].text if host.elements["IP"]
      next unless validate_ips(addr)
      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end
      hname = ( # Prefer NetBIOS over DNS
        (host.elements["NETBIOS"].text if host.elements["NETBIOS"]) ||
         (host.elements["DNS"].text if host.elements["DNS"]) ||
         "" )
      hobj = report_host(:workspace => wspace, :host => addr, :name => hname, :state => Msf::HostState::Alive, :task => args[:task])
      report_import_note(wspace,hobj)

      if host.elements["OPERATING_SYSTEM"]
        hos = host.elements["OPERATING_SYSTEM"].text
        report_note(
          :workspace => wspace,
          :task => args[:task],
          :host => hobj,
          :type => 'host.os.qualys_fingerprint',
          :data => { :os => hos }
        )
      end

      # Report open ports.
      find_qualys_asset_ports(82023,host,wspace,hobj) # TCP
      find_qualys_asset_ports(82004,host,wspace,hobj) # UDP

      # Report vulns
      find_qualys_asset_vulns(host,wspace,hobj,vuln_refs,&block)

    end # host

  end

  #
  # Import Qualys' Scan xml output
  #
  def import_qualys_scan_xml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_qualys_scan_xml(args.merge(:data => data))
  end

  def import_qualys_scan_xml(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []


    doc = rexmlify(data)
    doc.elements.each('/SCAN/IP') do |host|
      hobj = nil
      addr  = host.attributes['value']
      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end
      hname = host.attributes['name'] || ''

      hobj = report_host(:workspace => wspace, :host => addr, :name => hname, :state => Msf::HostState::Alive, :task => args[:task])
      report_import_note(wspace,hobj)

      if host.elements["OS"]
        hos = host.elements["OS"].text
        report_note(
          :workspace => wspace,
          :task => args[:task],
          :host => hobj,
          :type => 'host.os.qualys_fingerprint',
          :data => {
            :os => hos
          }
        )
      end

      # Open TCP Services List (Qualys ID 82023)
      services_tcp = host.elements["SERVICES/CAT/SERVICE[@number='82023']/RESULT"]
      if services_tcp
        services_tcp.text.scan(/([0-9]+)\t(.*?)\t.*?\t([^\t\n]*)/) do |match|
          if match[2] == nil or match[2].strip == 'unknown'
            name = match[1].strip
          else
            name = match[2].strip
          end
          handle_qualys(wspace, hobj, match[0].to_s, 'tcp', 0, nil, nil, name, nil, args[:task])
        end
      end
      # Open UDP Services List (Qualys ID 82004)
      services_udp = host.elements["SERVICES/CAT/SERVICE[@number='82004']/RESULT"]
      if services_udp
        services_udp.text.scan(/([0-9]+)\t(.*?)\t.*?\t([^\t\n]*)/) do |match|
          if match[2] == nil or match[2].strip == 'unknown'
            name = match[1].strip
          else
            name = match[2].strip
          end
          handle_qualys(wspace, hobj, match[0].to_s, 'udp', 0, nil, nil, name, nil, args[:task])
        end
      end

      # VULNS are confirmed, PRACTICES are unconfirmed vulnerabilities
      host.elements.each('VULNS/CAT | PRACTICES/CAT') do |cat|
        port = cat.attributes['port']
        protocol = cat.attributes['protocol']
        cat.elements.each('VULN | PRACTICE') do |vuln|
          refs = []
          qid = vuln.attributes['number']
          severity = vuln.attributes['severity']
          title = vuln.elements['TITLE'].text.to_s
          vuln.elements.each('VENDOR_REFERENCE_LIST/VENDOR_REFERENCE') do |ref|
            refs.push(ref.elements['ID'].text.to_s)
          end
          vuln.elements.each('CVE_ID_LIST/CVE_ID') do |ref|
            refs.push('CVE-' + /C..-([0-9\-]{9})/.match(ref.elements['ID'].text.to_s)[1])
          end
          vuln.elements.each('BUGTRAQ_ID_LIST/BUGTRAQ_ID') do |ref|
            refs.push('BID-' + ref.elements['ID'].text.to_s)
          end

          handle_qualys(wspace, hobj, port, protocol, qid, severity, refs, nil,title, args[:task])
        end
      end
    end
  end

  def import_ip_list_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_ip_list(args.merge(:data => data))
  end

  def import_ip_list(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    data.each_line do |ip|
      ip.strip!
      if bl.include? ip
        next
      else
        yield(:address,ip) if block
      end
      host = find_or_create_host(:workspace => wspace, :host=> ip, :state => Msf::HostState::Alive, :task => args[:task])
    end
  end

  def import_amap_log_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace
    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end

    case import_filetype_detect(data)
    when :amap_log
      import_amap_log(args.merge(:data => data))
    when :amap_mlog
      import_amap_mlog(args.merge(:data => data))
    else
      raise DBImportError.new("Could not determine file type")
    end
  end

  def import_amap_log(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    data.each_line do |line|
      next if line =~ /^#/
      next if line !~ /^Protocol on ([^:]+):([^\x5c\x2f]+)[\x5c\x2f](tcp|udp) matches (.*)$/n
      addr   = $1
      next if bl.include? addr
      port   = $2.to_i
      proto  = $3.downcase
      name   = $4
      host = find_or_create_host(:workspace => wspace, :host => addr, :state => Msf::HostState::Alive, :task => args[:task])
      next if not host
      yield(:address,addr) if block
      info = {
        :workspace => wspace,
        :task => args[:task],
        :host => host,
        :proto => proto,
        :port => port
      }
      if name != "unidentified"
        info[:name] = name
      end
      service = find_or_create_service(info)
    end
  end

  def import_amap_mlog(args={}, &block)
    data = args[:data]
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    data.each_line do |line|
      next if line =~ /^#/
      r = line.split(':')
      next if r.length < 6

      addr   = r[0]
      next if bl.include? addr
      port   = r[1].to_i
      proto  = r[2].downcase
      status = r[3]
      name   = r[5]
      next if status != "open"

      host = find_or_create_host(:workspace => wspace, :host => addr, :state => Msf::HostState::Alive, :task => args[:task])
      next if not host
      yield(:address,addr) if block
      info = {
        :workspace => wspace,
        :task => args[:task],
        :host => host,
        :proto => proto,
        :port => port
      }
      if name != "unidentified"
        info[:name] = name
      end
      service = find_or_create_service(info)
    end
  end

  def import_ci_noko_stream(args, &block)
    if block
      doc = Rex::Parser::CIDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::CI.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end


  def unserialize_object(xml_elem, allow_yaml = false)
    return nil unless xml_elem
    string = xml_elem.text.to_s.strip
    return string unless string.is_a?(String)
    return nil if (string.empty? || string.nil?)

    begin
      # Validate that it is properly formed base64 first
      if string.gsub(/\s+/, '') =~ /^([a-z0-9A-Z\+\/=]+)$/
        Marshal.load($1.unpack("m")[0])
      else
        if allow_yaml
          begin
            YAML.load(string)
          rescue
            dlog("Badly formatted YAML: '#{string}'")
            string
          end
        else
          string
        end
      end
    rescue ::Exception => e
      if allow_yaml
        YAML.load(string) rescue string
      else
        string
      end
    end
  end

  #
  # Returns something suitable for the +:host+ parameter to the various report_* methods
  #
  # Takes a Host object, a Session object, an Msf::Session object or a String
  # address
  #
  def normalize_host(host)
    return host if host.kind_of? ::Mdm::Host
    norm_host = nil

    if (host.kind_of? String)

      if Rex::Socket.is_ipv4?(host)
        # If it's an IPv4 addr with a port on the end, strip the port
        if host =~ /((\d{1,3}\.){3}\d{1,3}):\d+/
          norm_host = $1
        else
          norm_host = host
        end
      elsif Rex::Socket.is_ipv6?(host)
        # If it's an IPv6 addr, drop the scope
        address, scope = host.split('%', 2)
        norm_host = address
      else
        norm_host = Rex::Socket.getaddress(host, true)
      end
    elsif host.kind_of? ::Mdm::Session
      norm_host = host.host
    elsif host.respond_to?(:session_host)
      # Then it's an Msf::Session object
      thost = host.session_host
      norm_host = thost
    end

    # If we got here and don't have a norm_host yet, it could be a
    # Msf::Session object with an empty or nil tunnel_host and tunnel_peer;
    # see if it has a socket and use its peerhost if so.
    if (
        norm_host.nil? and
        host.respond_to?(:sock) and
        host.sock.respond_to?(:peerhost) and
        host.sock.peerhost.to_s.length > 0
      )
      norm_host = session.sock.peerhost
    end
    # If We got here and still don't have a real host, there's nothing left
    # to try, just log it and return what we were given
    if not norm_host
      dlog("Host could not be normalized: #{host.inspect}")
      norm_host = host
    end

    norm_host
  end

  # A way to sneak the yield back into the db importer.
  # Used by the SAX parsers.
  def emit(sym,data,&block)
    yield(sym,data)
  end

protected

  #
  # This holds all of the shared parsing/handling used by the
  # Nessus NBE and NESSUS v1 methods
  #
  def handle_nessus(wspace, hobj, port, nasl, plugin_name, severity, data,task=nil)
    addr = hobj.address
    # The port section looks like:
    #   http (80/tcp)
    p = port.match(/^([^\(]+)\((\d+)\/([^\)]+)\)/)
    return if not p

    # Unnecessary as the caller should already have reported this host
    #report_host(:workspace => wspace, :host => addr, :state => Msf::HostState::Alive)
    name = p[1].strip
    port = p[2].to_i
    proto = p[3].downcase

    info = { :workspace => wspace, :host => hobj, :port => port, :proto => proto, :task => task }
    if name != "unknown" and name[-1,1] != "?"
      info[:name] = name
    end
    report_service(info)

    if nasl.nil? || nasl.empty? || nasl == 0 || nasl == "0"
      return
    end

    data.gsub!("\\n", "\n")

    refs = []

    if (data =~ /^CVE : (.*)$/)
      $1.gsub(/C(VE|AN)\-/, '').split(',').map { |r| r.strip }.each do |r|
        refs.push('CVE-' + r)
      end
    end

    if (data =~ /^BID : (.*)$/)
      $1.split(',').map { |r| r.strip }.each do |r|
        refs.push('BID-' + r)
      end
    end

    if (data =~ /^Other references : (.*)$/)
      $1.split(',').map { |r| r.strip }.each do |r|
        ref_id, ref_val = r.split(':')
        ref_val ? refs.push(ref_id + '-' + ref_val) : refs.push(ref_id)
      end
    end

    nss = 'NSS-' + nasl.to_s.strip
    refs << nss

    unless plugin_name.to_s.strip.empty?
      vuln_name = plugin_name
    else
      vuln_name = nss
    end

    vuln_info = {
      :workspace => wspace,
      :host => hobj,
      :port => port,
      :proto => proto,
      :name => vuln_name,
      :info => data,
      :refs => refs,
      :task => task,
    }
    report_vuln(vuln_info)
  end

  #
  # NESSUS v2 file format has a dramatically different layout
  # for ReportItem data
  #
  def handle_nessus_v2(wspace,hobj,port,proto,name,nasl,nasl_name,severity,description,cve,bid,xref,msf,task=nil)
    addr = hobj.address

    info = { :workspace => wspace, :host => hobj, :port => port, :proto => proto, :task => task }

    unless name =~ /^unknown$|\?$/
      info[:name] = name
    end

    if port.to_i != 0
      report_service(info)
    end

    if nasl.nil? || nasl.empty? || nasl == 0 || nasl == "0"
      return
    end

    refs = []

    cve.each do |r|
      r.to_s.gsub!(/C(VE|AN)\-/, '')
      refs.push('CVE-' + r.to_s)
    end if cve

    bid.each do |r|
      refs.push('BID-' + r.to_s)
    end if bid

    xref.each do |r|
      ref_id, ref_val = r.to_s.split(':')
      ref_val ? refs.push(ref_id + '-' + ref_val) : refs.push(ref_id)
    end if xref

    msfref = "MSF-" << msf if msf
    refs.push msfref if msfref

    nss = 'NSS-' + nasl
    if nasl_name.nil? || nasl_name.empty?
      vuln_name = nss
    else
      vuln_name = nasl_name
    end

    refs << nss.strip

    vuln = {
      :workspace => wspace,
      :host => hobj,
      :name => vuln_name,
      :info => description ? description : "",
      :refs => refs,
      :task => task,
    }

    if port.to_i != 0
      vuln[:port]  = port
      vuln[:proto] = proto
    end

    report_vuln(vuln)
  end

  #
  # IP360 v3 vuln
  #
  def handle_ip360_v3_svc(wspace,hobj,port,proto,hname,task=nil)
    addr = hobj.address
    report_host(:workspace => wspace, :host => hobj, :state => Msf::HostState::Alive, :task => task)

    info = { :workspace => wspace, :host => hobj, :port => port, :proto => proto, :task => task }
    if hname != "unknown" and hname[-1,1] != "?"
      info[:name] = hname
    end

    if port.to_i != 0
      report_service(info)
    end
  end  #handle_ip360_v3_svc

  #
  # IP360 v3 vuln
  #
  def handle_ip360_v3_vuln(wspace,hobj,port,proto,hname,vulnid,vulnname,cves,bids,task=nil)
    info = { :workspace => wspace, :host => hobj, :port => port, :proto => proto, :task => task }
    if hname != "unknown" and hname[-1,1] != "?"
      info[:name] = hname
    end

    if port.to_i != 0
      report_service(info)
    end

    refs = []

    cves.split(/,/).each do |cve|
      refs.push(cve.to_s)
    end if cves

    bids.split(/,/).each do |bid|
      refs.push('BID-' + bid.to_s)
    end if bids

    description = nil   # not working yet
    vuln = {
      :workspace => wspace,
      :host => hobj,
      :name => vulnname,
      :info => description ? description : "",
      :refs => refs,
      :task => task
    }

    if port.to_i != 0
      vuln[:port]  = port
      vuln[:proto] = proto
    end

    report_vuln(vuln)
  end  #handle_ip360_v3_vuln

  #
  # Qualys report parsing/handling
  #
  def handle_qualys(wspace, hobj, port, protocol, qid, severity, refs, name=nil, title=nil, task=nil)
    addr = hobj.address
    port = port.to_i if port

    info = { :workspace => wspace, :host => hobj, :port => port, :proto => protocol, :task => task }
    if name and name != 'unknown' and name != 'No registered hostname'
      info[:name] = name
    end

    if info[:host] && info[:port] && info[:proto]
      report_service(info)
    end

    fixed_refs = []
    if refs
      refs.each do |ref|
        case ref
        when /^MS[0-9]{2}-[0-9]{3}/
          fixed_refs << "MSB-#{ref}"
        else
          fixed_refs << ref
        end
      end
    end

    return if qid == 0
    title = 'QUALYS-' + qid if title.nil? or title.empty?
    if addr
      report_vuln(
        :workspace => wspace,
        :task => task,
        :host => hobj,
        :port => port,
        :proto => protocol,
        :name =>  title,
        :refs => fixed_refs
      )
    end
  end

  def process_nexpose_data_sxml_refs(vuln)
    refs = []
    vid = vuln.attributes['id'].to_s.downcase
    vry = vuln.attributes['resultCode'].to_s.upcase

    # Only process vuln-exploitable and vuln-version statuses
    return if vry !~ /^V[VE]$/

    refs = []
    vuln.elements.each('id') do |ref|
      rtyp = ref.attributes['type'].to_s.upcase
      rval = ref.text.to_s.strip
      case rtyp
      when 'CVE'
        refs << rval.gsub('CAN', 'CVE')
      when 'MS' # obsolete?
        refs << "MSB-MS-#{rval}"
      else
        refs << "#{rtyp}-#{rval}"
      end
    end

    refs << "NEXPOSE-#{vid}"
    refs
  end

end

end
