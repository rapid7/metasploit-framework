# -*- coding: binary -*-
module Msf
module RPC
class RPC_Db < RPC_Base

private

  include Metasploit::Credential::Creation

  def db
    self.framework.db.active
  end

  def find_workspace(wspace = nil)
    if wspace and wspace != ""
      return self.framework.db.find_workspace(wspace) || error(500, "Invalid workspace")
    end
    self.framework.db.workspace
  end

  def fix_cred_options(opts)
    new_opts = fix_options(opts)

    # Convert some of the raw data back to symbols
    if new_opts[:origin_type]
      new_opts[:origin_type] = new_opts[:origin_type].to_sym
    end

    if new_opts[:private_type]
      new_opts[:private_type] = new_opts[:private_type].to_sym
    end

    new_opts
  end

  def fix_options(opts)
    newopts = {}
    opts.each do |k,v|
      newopts[k.to_sym] = v
    end
    newopts
  end

  def opts_to_hosts(opts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = find_workspace(opts[:workspace])
    hosts  = []
    if opts[:host] or opts[:address]
      host = opts[:host] || opts[:address]
      hent = wspace.hosts.find_by_address(host)
      return hosts if hent == nil
      hosts << hent if hent.class == ::Mdm::Host
      hosts |= hent if hent.class == Array
    elsif opts[:addresses]
      return hosts if opts[:addresses].class != Array
      conditions = {}
      conditions[:address] = opts[:addresses]
      hent = wspace.hosts.where(conditions)
      hosts |= hent if hent.class == Array
    end
    return hosts
  }
  end

  def opts_to_services(hosts,opts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = find_workspace(opts[:workspace])
    services = []
    if opts[:host] or opts[:address] or opts[:addresses]
      return services if hosts.count < 1
      hosts.each do |h|
        if opts[:port] or opts[:proto]
          conditions = {}
          conditions[:port] = opts[:port] if opts[:port]
          conditions[:proto] = opts[:proto] if opts[:proto]
          sret = h.services.where(conditions)
          next if sret == nil
          services |= sret if sret.class == Array
          services << sret if sret.class == ::Mdm::Service
        else
          services |= h.services
        end
      end
    elsif opts[:port] or opts[:proto]
      conditions = {}
      conditions[:port] = opts[:port] if opts[:port]
      conditions[:proto] = opts[:proto] if opts[:proto]
      sret = wspace.services.where(conditions)
      services |= sret if sret.class == Array
      services << sret if sret.class == ::Mdm::Service
    end
    return services
  }
  end

  def db_check
    error(500, "Database Not Loaded") if not db
  end

  def init_db_opts_workspace(xopts)
    db_check
    opts = fix_options(xopts)
    opts[:workspace] = find_workspace(opts[:workspace])
    return opts, opts[:workspace]
  end

  def get_notes(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    notes = []

    host = self.framework.db.get_host(opts)
    return notes if not host

    if opts[:proto] && opts[:port]
      services = []
      nret = host.services.find_by_proto_and_port(opts[:proto], opts[:port])
      return ret if nret == nil
      services << nret if nret.class == ::Mdm::Service
      services |= nret if nret.class == Array

      services.each do |s|
        nret = nil
        if opts[:ntype]
          nret = s.notes.find_by_ntype(opts[:ntype])
        else
          nret = s.notes
        end
        next if nret == nil
        notes << nret if nret.class == ::Mdm::Note
        notes |= nret if nret.class == Array
      end
    else
      notes = host.notes
    end
    notes
  }
  end

public


  # Creates a cracked credential.
  #
  # @param [Hash] xopts Credential options. (See #create_credential Documentation)
  # @return [Metasploit::Credential::Core]
  # @see https://github.com/rapid7/metasploit-credential/blob/master/lib/metasploit/credential/creation.rb#L107 #create_credential Documentation.
  # @see #rpc_create_credential
  # @example Here's how you would use this from the client:
  #  opts = {
  #    username: username,
  #    password: password,
  #    core_id: core_id
  #  }
  #  rpc.call('db.create_cracked_credential', opts)
  def rpc_create_cracked_credential(xopts)
    opts = fix_cred_options(xopts)
    create_cracked_credential(opts)
  end


  # Creates a credential.
  #
  # @param [Hash] xopts Credential options. (See #create_credential Documentation)
  # @return [Hash] Credential data. It contains the following keys:
  #  * 'username' [String] Username saved.
  #  * 'private' [String] Password saved.
  #  * 'private_type' [String] Password type.
  #  * 'realm_value' [String] Realm.
  #  * 'realm_key' [String] Realm key.
  #  * 'host' [String] Host (Only avilable if there's a :last_attempted_at and :status)
  #  * 'sname' [String] Service name (only available if there's a :last_attempted_at and :status)
  #  * 'status' [Status] Login status (only available if there's a :last_attempted_at and :status)
  # @see https://github.com/rapid7/metasploit-credential/blob/master/lib/metasploit/credential/creation.rb#L107 #create_credential Documentation.
  # @example Here's how you would use this from the client:
  #  opts = {
  #   origin_type: :service,
  #   address: '192.168.1.100',
  #   port: 445,
  #   service_name: 'smb',
  #   protocol: 'tcp',
  #   module_fullname: 'auxiliary/scanner/smb/smb_login',
  #   workspace_id: myworkspace_id,
  #   private_data: 'password1',
  #   private_type: :password,
  #   username: 'Administrator'
  #  }
  #  rpc.call('db.create_cracked_credential', opts)
  def rpc_create_credential(xopts)
    opts = fix_cred_options(xopts)
    core = create_credential(opts)

    ret = {
        username: core.public.try(:username),
        private: core.private.try(:data),
        private_type: core.private.try(:type),
        realm_value: core.realm.try(:value),
        realm_key: core.realm.try(:key)
    }

    if opts[:last_attempted_at] && opts[:status]
      opts[:core] = core
      opts[:last_attempted_at] = opts[:last_attempted_at].to_datetime
      login = create_credential_login(opts)

      ret[:host]   = login.service.host.address,
      ret[:sname]  = login.service.name
      ret[:status] = login.status
    end
    ret
  end


  # Sets the status of a login credential to a failure.
  #
  # @param [Hash] xopts Credential data (See #invalidate_login Documentation)
  # @raise [Msf::RPC::Exception] If there's an option missing.
  # @return [void]
  # @see https://github.com/rapid7/metasploit-credential/blob/master/lib/metasploit/credential/creation.rb#L492 #invalidate_login Documentation
  # @see https://github.com/rapid7/metasploit-model/blob/master/lib/metasploit/model/login/status.rb Status symbols.
  # @example Here's how you would use this from the client:
  #  opts = {
  #    address: '192.168.1.100',
  #    port: 445,
  #    protocol: 'tcp',
  #    public: 'admin',
  #    private: 'password1',
  #    status: 'Incorrect'
  #  }
  #  rpc.call('db.invalidate_login', opts)
  def rpc_invalidate_login(xopts)
    opts = fix_cred_options(xopts)
    invalidate_login(opts)
  end


  # Returns login credentials from a specific workspace.
  #
  # @param [Hash] xopts Options:
  # @option xopts [String] :workspace Name of the workspace.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] Credentials with the following hash key:
  #  * 'creds' [Array<Hash>] An array of credentials. Each hash in the array will have the following:
  #    * 'user' [String] Username.
  #    * 'pass' [String] Password.
  #    * 'updated_at' [Integer] Last updated at.
  #    * 'type' [String] Password type.
  #    * 'host' [String] Host.
  #    * 'port' [Integer] Port.
  #    * 'proto' [String] Protocol.
  #    * 'sname' [String] Service name.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.creds', {})
  def rpc_creds(xopts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      ret = {}
      ret[:creds] = []
      opts, wspace = init_db_opts_workspace(xopts)
      limit = opts.delete(:limit) || 100
      offset = opts.delete(:offset) || 0
      query = Metasploit::Credential::Core.where(
        workspace_id: wspace
      ).offset(offset).limit(limit)
      query.each do |cred|
        host = ''
        port = 0
        proto = ''
        sname = ''
        unless cred.logins.empty?
          login = cred.logins.first
          host = login.service.host.address.to_s
          sname = login.service.name.to_s if login.service.name.present?
          port = login.service.port.to_i
          proto = login.service.proto.to_s
        end
        ret[:creds] << {
                :user => cred.public.username.to_s,
                :pass => cred.private.data.to_s,
                :updated_at => cred.private.updated_at.to_i,
                :type => cred.private.type.to_s,
                :host => host,
                :port => port,
                :proto => proto,
                :sname => sname}
      end
      ret
    }
  end


  # Returns information about hosts.
  #
  # @param [Hash] xopts Options:
  # @option xopts [String] :workspace Name of the workspace.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] Host information that starts with the following hash key:
  #  * 'hosts' [Array<Hash>] An array of hosts. Each hash in the array will have the following:
  #    * 'created_at' [Integer] Creation date.
  #    * 'address' [String] IP address.
  #    * 'mac' [String] MAC address.
  #    * 'name' [String] Computer name.
  #    * 'state' [String] Host's state.
  #    * 'os_name' [String] Name of the operating system.
  #    * 'os_flavor' [String] OS flavor.
  #    * 'os_sp' [String] Service pack.
  #    * 'os_lang' [String] OS language.
  #    * 'updated_at' [Integer] Last updated at.
  #    * 'purpose' [String] Host purpose (example: server)
  #    * 'info' [String] Additional information about the host.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.hosts', {})
  def rpc_hosts(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)

    conditions = {}
    conditions[:state] = [Msf::HostState::Alive, Msf::HostState::Unknown] if opts[:only_up]
    conditions[:address] = opts[:addresses] if opts[:addresses]

    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    ret = {}
    ret[:hosts] = []
    wspace.hosts.where(conditions).offset(offset).order(:address).limit(limit).each do |h|
      host = {}
      host[:created_at] = h.created_at.to_i
      host[:address] = h.address.to_s
      host[:mac] = h.mac.to_s
      host[:name] = h.name.to_s
      host[:state] = h.state.to_s
      host[:os_name] = h.os_name.to_s
      host[:os_flavor] = h.os_flavor.to_s
      host[:os_sp] = h.os_sp.to_s
      host[:os_lang] = h.os_lang.to_s
      host[:updated_at] = h.updated_at.to_i
      host[:purpose] = h.purpose.to_s
      host[:info] = h.info.to_s
      ret[:hosts]  << host
    end
    ret
  }
  end


  # Returns information about services.
  #
  # @param [Hash] xopts Options:
  # @option xopts [String] :workspace Name of workspace.
  # @option xopts [Integer] :limit Limit.
  # @option xopts [Integer] :offset Offset.
  # @option xopts [String] :proto Protocol.
  # @option xopts [String] :address Address.
  # @option xopts [String] :ports Port range.
  # @option xopts [String] :names Names (Use ',' as the separator).
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash with the following keys:
  #  * 'services' [Array<Hash>] In each hash of the array, you will get these keys:
  #    * 'host' [String] Host.
  #    * 'created_at' [Integer] Last created at.
  #    * 'updated_at' [Integer] Last updated at.
  #    * 'port' [Integer] Port.
  #    * 'proto' [String] Protocol.
  #    * 'state' [String] Service state.
  #    * 'name' [String] Service name.
  #    * 'info' [String] Additional information about the service.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.services', {})
  def rpc_services( xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    conditions = {}
    conditions[:state] = [Msf::ServiceState::Open] if opts[:only_up]
    conditions[:proto] = opts[:proto] if opts[:proto]
    conditions["hosts.address"] = opts[:addresses] if opts[:addresses]
    conditions[:port] = Rex::Socket.portspec_to_portlist(opts[:ports]) if opts[:ports]
    conditions[:name] = opts[:names].strip().split(",") if opts[:names]

    ret = {}
    ret[:services] = []

    wspace.services.includes(:host).where(conditions).offset(offset).limit(limit).each do |s|
      service = {}
      host = s.host
      service[:host] = host.address || "unknown"
      service[:created_at] = s[:created_at].to_i
      service[:updated_at] = s[:updated_at].to_i
      service[:port] = s[:port]
      service[:proto] = s[:proto].to_s
      service[:state] = s[:state].to_s
      service[:name] = s[:name].to_s
      service[:info] = s[:info].to_s
      ret[:services] << service
    end
    ret
  }
  end


  # Returns information about reported vulnerabilities.
  #
  # @param [Hash] xopts Options:
  # @option xopts [String] :workspace Name of workspace.
  # @option xopts [Integer] :limit Limit.
  # @option xopts [Integer] :offset Offset.
  # @option xopts [String] :proto Protocol.
  # @option xopts [String] :address Address.
  # @option xopts [String] :ports Port range.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash with the following key:
  #  * 'vulns' [Array<Hash>] In each hash of the array, you will get these keys:
  #    * 'port' [Integer] Port.
  #    * 'proto' [String] Protocol.
  #    * 'time' [Integer] Time reported.
  #    * 'host' [String] Vulnerable host.
  #    * 'name' [String] Exploit that was used.
  #    * 'refs' [String] Vulnerability references.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.vulns', {})
  def rpc_vulns(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    conditions = {}
    conditions["hosts.address"] = opts[:addresses] if opts[:addresses]
    conditions[:name] = opts[:names].strip().split(",") if opts[:names]
    conditions["services.port"] = Rex::Socket.portspec_to_portlist(opts[:ports]) if opts[:port]
    conditions["services.proto"] = opts[:proto] if opts[:proto]

    ret = {}
    ret[:vulns] = []
    wspace.vulns.includes(:service).where(conditions).offset(offset).limit(limit).each do |v|
      vuln = {}
      reflist = v.refs.map { |r| r.name }
      if v.service
        vuln[:port] = v.service.port
        vuln[:proto] = v.service.proto
      else
        vuln[:port] = nil
        vuln[:proto] = nil
      end
      vuln[:time] = v.created_at.to_i
      vuln[:host] = v.host.address || nil
      vuln[:name] = v.name
      vuln[:refs] = reflist.join(',')
      ret[:vulns] << vuln
    end
    ret
  }
  end


  # Returns information about workspaces.
  #
  # @raise [Msf::RPC::Exception] Database not loaded.
  # @return [Hash] A hash with the following key:
  #  * 'workspaces' [Array<Hash>] In each hash of the array, you will get these keys:
  #    * 'id' [Integer] Workspace ID.
  #    * 'name' [String] Workspace name.
  #    * 'created_at' [Integer] Last created at.
  #    * 'updated_at' [Integer] Last updated at.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.workspaces')
  def rpc_workspaces
    db_check

    res = {}
    res[:workspaces] = []
    self.framework.db.workspaces.each do |j|
      ws = {}
      ws[:id] = j.id
      ws[:name] = j.name
      ws[:created_at] = j.created_at.to_i
      ws[:updated_at] = j.updated_at.to_i
      res[:workspaces] << ws
    end
    res
  end


  # Returns the current workspace.
  #
  # @raise [Msf::RPC::Exception] Database not loaded. Try: rpc.call('console.create')
  # @return [Hash] A hash with the following keys:
  #  * 'workspace' [String] Workspace name.
  #  * 'workspace_id' [Integer] Workspace ID.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.current_workspace')
  def rpc_current_workspace
    db_check
    { "workspace" => self.framework.db.workspace.name, "workspace_id" => self.framework.db.workspace.id }
  end


  # Returns the current workspace.
  #
  # @param [String] wspace workspace name.
  # @raise [Msf::RPC::Exception] You might get one of the following errors:
  #  * 500 Database not loaded.
  #  * 500 Invalid workspace.
  # @return [Hash] A hash with the following key:
  #  * 'workspace' [Array<Hash>] In each hash of the array, you will get these keys:
  #    * 'name' [String] Workspace name.
  #    * 'id' [Integer] Workspace ID.
  #    * 'created_at' [Integer] Last created at.
  #    * 'updated_at' [Integer] Last updated at.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.get_workspace')
  def rpc_get_workspace(wspace)
    db_check
    wspace = find_workspace(wspace)
    ret = {}
    ret[:workspace] = []
    if wspace
      w = {}
      w[:name] = wspace.name
      w[:id] = wspace.id
      w[:created_at] = wspace.created_at.to_i
      w[:updated_at] = wspace.updated_at.to_i
      ret[:workspace] << w
    end
    ret
  end


  # Sets a workspace.
  #
  # @param [String] wspace Workspace name.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace
  #  * 404 Workspace not found.
  # @return [Hash] A hash indicating whether the action was successful or not. You will get:
  #  * 'result' [String] A message that says either 'success' or 'failed'
  # @example Here's how you would use this from the client:
  #  # This will set the current workspace to 'default'
  #  rpc.call('db.set_workspace', 'default')
  def rpc_set_workspace(wspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    db_check
    workspace = find_workspace(wspace)
    if workspace
      self.framework.db.workspace = workspace
      return { 'result' => "success" }
    end
    { 'result' => 'failed' }
  }
  end


  # Deletes a workspace.
  #
  # @param [String] wspace Workspace name.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 404 Workspace not found.
  # @return [Hash] A hash indicating the action was successful. It contains the following:
  #  * 'result' [String] A message that says 'success'.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.wspace', 'temp_workspace')
  def rpc_del_workspace(wspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    db_check
    # Delete workspace
    workspace = find_workspace(wspace)
    if workspace.nil?
      error(404, "Workspace not found: #{wspace}")
    elsif workspace.default?
      workspace.destroy
      workspace = self.framework.db.add_workspace(workspace.name)
    else
      # switch to the default workspace if we're about to delete the current one
      self.framework.db.workspace = self.framework.db.default_workspace if self.framework.db.workspace.name == workspace.name
      # now destroy the named workspace
      workspace.destroy
    end
    { 'result' => "success" }
  }
  end


  # Adds a new workspace.
  #
  # @param [String] wspace Workspace name.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash indicating whether the action was successful or not. You get:
  #  * 'result' [String] A message that says either 'success' or 'failed'.
  # @example Here's how you would use this from the client:
  #  * rpc.call('db.add_workspace', 'my_new_workspace')
  def rpc_add_workspace(wspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    db_check
    wspace = self.framework.db.add_workspace(wspace)
    return { 'result' => 'success' } if wspace
    { 'result' => 'failed' }
  }
  end


  # Returns information about a host.
  #
  # @param [Hash] xopts Options (:addr, :address, :host are the same thing, and you only need one):
  # @option xopts [String] :addr Host address.
  # @option xopts [String] :address Same as :addr.
  # @option xopts [String] :host Same as :address.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the following:
  #  * 'host' [Array<Hash>] Each hash in the array contains the following:
  #    * 'created_at' [Integer] Last created at.
  #    * 'address' [String] Address.
  #    * 'mac' [String] Mac address.
  #    * 'name' [String] Host name.
  #    * 'state' [String] Host state.
  #    * 'os_name' [String] OS name.
  #    * 'os_flavor' [String] OS flavor.
  #    * 'os_sp' [String] OS service pack.
  #    * 'os_lang' [String] OS language.
  #    * 'updated_at' [Integer] Last updated at.
  #    * 'purpose' [String] Purpose. Example: 'server'.
  #    * 'info' [String] Additional information.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.get_host', {:host => ip})
  def rpc_get_host(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)

    ret = {}
    ret[:host] = []
    opts = fix_options(xopts)
    h = self.framework.db.get_host(opts)
    if h
      host = {}
      host[:created_at] = h.created_at.to_i
      host[:address] = h.address.to_s
      host[:mac] = h.mac.to_s
      host[:name] = h.name.to_s
      host[:state] = h.state.to_s
      host[:os_name] = h.os_name.to_s
      host[:os_flavor] = h.os_flavor.to_s
      host[:os_sp] = h.os_sp.to_s
      host[:os_lang] = h.os_lang.to_s
      host[:updated_at] = h.updated_at.to_i
      host[:purpose] = h.purpose.to_s
      host[:info] = h.info.to_s
      ret[:host] << host
    end
    ret
  }
  end


  # Reports a new host to the database.
  #
  # @param [Hash] xopts Information to report about the host. See below:
  # @option xopts [String] :host IP address. You msut supply this.
  # @option xopts [String] :state One of the Msf::HostState constants. (See Most::HostState Documentation)
  # @option xopts [String] :os_name Something like "Windows", "Linux", or "Mac OS X".
  # @option xopts [String] :os_flavor Something like "Enterprise", "Pro", or "Home".
  # @option xopts [String] :os_sp Something like "SP2".
  # @option xopts [String] :os_lang Something like "English", "French", or "en-US".
  # @option xopts [String] :arch one of the ARCH_* constants. (see ARCH Documentation)
  # @option xopts [String] :mac Mac address.
  # @option xopts [String] :scope Interface identifier for link-local IPv6.
  # @option xopts [String] :virtual_host The name of the VM host software, eg "VMWare", "QEMU", "Xen", etc.
  # @see https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/host_state.rb Most::HostState Documentation.
  # @see https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/constants.rb#L66 ARCH Documentation.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash indicating whether the action was successful or not. It contains the following:
  #  * 'result' [String] A message that says either 'success' or 'failed'.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.report_host', {:host => ip})
  def rpc_report_host(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)

    res = self.framework.db.report_host(opts)
    return { :result => 'success' } if res
    { :result => 'failed' }
  }
  end


  # Reports a service to the database.
  #
  # @param [Hash] xopts Information to report about the service. See below:
  # @option xopts [String] :host Required. The host where this service is running.
  # @option xopts [String] :port Required. The port where this service listens.
  # @option xopts [String] :proto Required. The transport layer protocol (e.g. tcp, udp).
  # @option xopts [String] :name The application layer protocol (e.g. ssh, mssql, smb).
  # @option xopts [String] :sname An alias for the above
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash indicating whether the action was successful or not. It contains:
  #  * 'result' [String] A message that says either 'success' or 'failed'.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.report_service', {:host=>ip, :port=>8181, :proto=>'tcp', :name=>'http'})
  def rpc_report_service(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    res = self.framework.db.report_service(opts)
    return { :result => 'success' } if res
    { :result => 'failed' }
  }
  end


  # Returns information about a service.
  #
  # @param [Hash] xopts Filters for the search, see below:
  # @option xopts [String] :workspace Workspace name.
  # @option xopts [String] :proto Protocol.
  # @option xopts [Integer] :port Port.
  # @option xopts [String] :names Service names.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the following key:
  #  * 'service' [Array<Hash>] Each hash in the array contains the following:
  #    * 'host' [String] Host address.
  #    * 'created_at' [Integer] Creation date.
  #    * 'port' [Integer] Port.
  #    * 'proto' [String] Protocol.
  #    * 'state' [String] Service state.
  #    * 'name' [String] Service name.
  #    * 'info' [String] Additional information.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.get_service', {:workspace=>'default', :proto=>'tcp', :port=>443})
  def rpc_get_service(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)

    ret = {}
    ret[:service] = []

    host = self.framework.db.get_host(opts)

    services = []
    sret = nil

    if host && opts[:proto] && opts[:port]
      sret = host.services.find_by_proto_and_port(opts[:proto], opts[:port])
    elsif opts[:proto] && opts[:port]
      conditions = {}
      conditions[:state] = [Msf::ServiceState::Open] if opts[:up]
      conditions[:proto] = opts[:proto] if opts[:proto]
      conditions[:port] = opts[:port] if opts[:port]
      conditions[:name] = opts[:names] if opts[:names]
      sret = wspace.services.where(conditions).order("hosts.address, port")
    elsif host
      sret = host.services
    end
    return ret if sret == nil
    services << sret if sret.class == ::Mdm::Service
    services |= sret if sret.class == Array


    services.each do |s|
      service = {}
      host = s.host
      service[:host] = host.address || "unknown"
      service[:created_at] = s[:created_at].to_i
      service[:updated_at] = s[:updated_at].to_i
      service[:port] = s[:port]
      service[:proto] = s[:proto].to_s
      service[:state] = s[:state].to_s
      service[:name] = s[:name].to_s
      service[:info] = s[:info].to_s
      ret[:service] << service
    end
    ret
  }
  end

  # Returns a note.
  #
  # @param [Hash] xopts Options.
  # @option xopts [String] :addr Host address.
  # @option xopts [String] :address Same as :addr.
  # @option xopts [String] :host Same as :address.
  # @option xopts [String] :proto Protocol.
  # @option xopts [Integer] :port Port.
  # @option xopts [String] :ntype Note type.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the following:
  #  * 'note' [Array<Hash>] Each hash in the array contains the following:
  #    * 'host' [String] Host.
  #    * 'port' [Integer] Port.
  #    * 'proto' [String] Protocol.
  #    * 'created_at' [Integer] Last created at.
  #    * 'updated_at' [Integer] Last updated at.
  #    * 'ntype' [String] Note type.
  #    * 'data' [String] Note data.
  #    * 'critical' [String] A boolean indicating criticality.
  #    * 'seen' [String] A boolean indicating whether the note has been seen before.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.get_note', {:proto => 'tcp', :port => 80})
  def rpc_get_note(xopts)
    ret = {}
    ret[:note] = []

    notes = get_notes(xopts)

    notes.each do |n|
      note = {}
      host = n.host
      note[:host] = host.address || "unknown"
      if n.service
        note[:port] = n.service.port
        note[:proto] = n.service.proto
      end
      note[:created_at] = n[:created_at].to_i
      note[:updated_at] = n[:updated_at].to_i
      note[:ntype] = n[:ntype].to_s
      note[:data] = n[:data]
      note[:critical] = n[:critical].to_s
      note[:seen] = n[:seen].to_s
      ret[:note] << note
    end
    ret
  end


  # Returns information about a client connection.
  #
  # @param [Hash] xopts Options:
  # @option xopts [String] :workspace Workspace name.
  # @option xopts [String] :ua_string User agent string.
  # @option xopts [String] :host Host IP.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the client connection:
  #  * 'client' [Array<Hash>] Each hash of the array contains the following:
  #    * 'host' [String] Host IP.
  #    * 'created_at' [Integer] Created date.
  #    * 'updated_at' [Integer] Last updated at.
  #    * 'ua_string' [String] User-Agent string.
  #    * 'ua_name' [String] User-Agent name.
  #    * 'ua_ver' [String] User-Agent version.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.get_client', {:workspace=>'default', :ua_string=>user_agent, :host=>ip})
  def rpc_get_client(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    ret = {}
    ret[:client] = []
    c = self.framework.db.get_client(opts)
    if c
      client = {}
      host = c.host
      client[:host] = host.address
      client[:created_at] = c.created_at.to_i
      client[:updated_at] = c.updated_at.to_i
      client[:ua_string] = c.ua_string.to_s
      client[:ua_name] = c.ua_name.to_s
      client[:ua_ver] = c.ua_ver.to_s
      ret[:client] << client
    end
    ret
  }
  end


  # Reports a client connection.
  #
  # @param [Hash] xopts Information about the client.
  # @option xopts [String] :ua_string Required. User-Agent string.
  # @option xopts [String] :host Required. Host IP.
  # @option xopts [String] :ua_name One of the Msf::HttpClients constants. (See Msf::HttpClient Documentation.)
  # @option xopts [String] :ua_ver Detected version of the given client.
  # @option xopts [String] :campaign An id or Campaign object.
  # @see https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/constants.rb#L52 Msf::HttpClient Documentation.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash indicating whether the action was successful or not. It contains:
  #  * 'result' [String] A message that says either 'success' or 'failed'.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.report_client', {:workspace=>'default', :ua_string=>user_agent, :host=>ip})
  def rpc_report_client(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    res = self.framework.db.report_client(opts)
    return { :result => 'success' } if res
    { :result => 'failed' }
  }
  end


  # Reports a note.
  #
  # @param [Hash] xopts Information about the note.
  # @option xopts [String] :type Required. The type of note, e.g. smb_peer_os.
  # @option xopts [String] :workspace The workspace to associate with this note.
  # @option xopts [String] :host An IP address or a Host object to associate with this note.
  # @option xopts [String] :service A Service object to associate with this note.
  # @option xopts [String] :data Whatever it is you're making a note of.
  # @option xopts [Integer] :port Along with +:host+ and +:proto+, a service to associate with this note.
  # @option xopts [String] :proto Along with +:host+ and +:port+, a service to associate with this note.
  # @option xopts [Hash] A hash that contains the following information.
  #  * :unique [Boolean] Allow only a single Note per +:host+/+:type+ pair.
  #  * :unique_data [Boolean] Like +:uniqe+, but also compare +:data+.
  #  * :insert [Boolean] Always insert a new Note even if one with identical values exists.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash indicating whether the action was successful or not. It contains:
  #  * 'result' [String] A message that says either 'success' or 'failed'.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.report_note', {:type=>'http_data', :host=>'192.168.1.123', :data=>'data'})
  def rpc_report_note(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    if (opts[:host] or opts[:address]) and opts[:port] and opts[:proto]
      addr = opts[:host] || opts[:address]
      wspace = opts[:workspace] || self.framework.db.workspace
      host = wspace.hosts.find_by_address(addr)
      if host && host.services.count > 0
        service = host.services.find_by_proto_and_port(opts[:proto],opts[:port])
        if service
          opts[:service] = service
        end
      end
    end

    res = self.framework.db.report_note(opts)
    return { :result => 'success' } if res
    { :result => 'failed' }
  }
  end


  # Returns notes from the database.
  #
  # @param [Hash] xopts Filters for the search. See below:
  # @option xopts [String] :address Host address.
  # @option xopts [String] :names Names (separated by ',').
  # @option xopts [String] :ntype Note type.
  # @option xopts [String] :proto Protocol.
  # @option xopts [String] :ports Port change.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the following:
  #  * 'notes' [Array<Hash>] Each hash in the array contains the following:
  #    * 'time' [Integer] Creation date.
  #    * 'host' [String] Host address.
  #    * 'service' [String] Service name or port.
  #    * 'type' [String] Host type.
  #    * 'data' [String] Host data.
  # @example Here's how you would use this from the client:
  #  # This gives you all the notes.
  #  rpc.call('db.notes', {})
  def rpc_notes(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    conditions = {}
    conditions["hosts.address"] = opts[:addresses] if opts[:addresses]
    conditions[:name] = opts[:names].strip().split(",") if opts[:names]
    conditions[:ntype] = opts[:ntype] if opts[:ntype]
    conditions["services.port"] = Rex::Socket.portspec_to_portlist(opts[:ports]) if opts[:ports]
    conditions["services.proto"] = opts[:proto] if opts[:proto]

    ret = {}
    ret[:notes] = []
    wspace.notes.includes(:host, :service).where(conditions).offset(offset).limit(limit).each do |n|
      note = {}
      note[:time] = n.created_at.to_i
      note[:host] = ""
      note[:service] = ""
      note[:host] = n.host.address if n.host
      note[:service] = n.service.name || n.service.port  if n.service
      note[:type ] = n.ntype.to_s
      note[:data] = n.data.inspect
      ret[:notes] << note
    end
    ret
  }
  end


  # Returns an external vulnerability reference.
  #
  # @param [String] name Reference name.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [String] Reference.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.get_ref', ref_name)
  def rpc_get_ref(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    db_check
    self.framework.db.get_ref(name)
  }
  end


  # Deletes vulnerabilities.
  #
  # @param [Hash] xopts Filters that narrow down which vulnerabilities to delete. See below:
  # @option xopts [String] :workspace Workspace name.
  # @option xopts [String] :host Host address.
  # @option xopts [String] :address Same as :host.
  # @option xopts [Array] :addresses Same as :address.
  # @option xopts [Integer] :port Port.
  # @option xopts [String] :proto Protocol.
  # @option xopts [String] :name Name of the vulnerability.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the following:
  #  * 'result' [String] A message that says 'success'.
  #  * 'deleted' [Array<Hash>] Each hash in the array contains the following:
  #    * 'address' [String] Host address.
  #    * 'port' [Integer] Port.
  #    * 'proto' [String] Protocol.
  #    * 'name' [String] Vulnerability name.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.del_vuln', {:host=>ip, :port=>445, :proto=>'tcp'})
  def rpc_del_vuln(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    opts[:workspace] = opts[:workspace].name
    hosts  = []
    services = []
    vulns = []

    if opts[:host] or opts[:address] or opts[:addresses]
      hosts = opts_to_hosts(xopts)
    end

    if opts[:port] or opts[:proto]
      if opts[:host] or opts[:address] or opts[:addresses]
        services = opts_to_services(hosts,xopts)
      else
        services = opts_to_services([],xopts)
      end
    end

    if opts[:port] or opts[:proto]
      services.each do |s|
        vret = nil
        if opts[:name]
          vret = s.vulns.find_by_name(opts[:name])
        else
          vret = s.vulns
        end
        next if vret == nil
        vulns << vret if vret.class == ::Mdm::Vuln
        vulns |= vret if vret.class == Array
      end
    elsif opts[:address] or opts[:host] or opts[:addresses]
      hosts.each do |h|
        vret = nil
        if opts[:name]
          vret = h.vulns.find_by_name(opts[:name])
        else
          vret = h.vulns
        end
        next if vret == nil
        vulns << vret if vret.class == ::Mdm::Vuln
        vulns |= vret if vret.class == Array
      end
    else
      vret = nil
      if opts[:name]
        vret = wspace.vulns.find_by_name(opts[:name])
      else
        vret = wspace.vulns
      end
      vulns << vret if vret.class == ::Mdm::Vuln
      vulns |= vret if vret.class == Array
    end

    deleted = []
    vulns.each do |v|
      dent = {}
      dent[:address] = v.host.address.to_s if v.host
      dent[:port] = v.service.port if v.service
      dent[:proto] = v.service.proto if v.service
      dent[:name] = v.name
      deleted << dent
      v.destroy
    end

    return { :result => 'success', :deleted => deleted }
  }
  end


  # Deletes notes.
  #
  # @param [Hash] xopts Filters to narrow down which notes to delete.
  # @option xopts [String] :workspace Workspace name.
  # @option xopts [String] :host Host address.
  # @option xopts [String] :address Same as :host.
  # @option xopts [Array] :addresses Same as :address.
  # @option xopts [Integer] :port Port.
  # @option xopts [String] :proto Protocol.
  # @option xopts [String] :ntype Note type.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the following:
  #  * 'result' [String] A message that says 'success'.
  #  * 'deleted' [Array<Hash>] Each hash in the array contains the following:
  #    * 'address' [String] Host address.
  #    * 'port' [Integer] Port.
  #    * 'proto' [String] Protocol.
  #    * 'ntype' [String] Note type.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.del_note', {:workspace=>'default', :host=>ip, :port=>443, :proto=>'tcp'})
  def rpc_del_note(xopts)
    notes = get_notes(xopts)

    deleted = []
    notes.each do |n|
      dent = {}
      dent[:address] = n.host.address.to_s if n.host
      dent[:port] = n.service.port if n.service
      dent[:proto] = n.service.proto if n.service
      dent[:ntype] = n.ntype
      deleted << dent
      n.destroy
    end

    return { :result => 'success', :deleted => deleted }
  end


  # Deletes services.
  #
  # @param [Hash] xopts Filters to narrow down which services to delete.
  # @option xopts [String] :workspace Workspace name.
  # @option xopts [String] :host Host address.
  # @option xopts [String] :address Same as :host.
  # @option xopts [Array] :addresses Host addresses.
  # @option xopts [Integer] :port Port.
  # @option xopts [String] :proto Protocol.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the following:
  #  * 'result' [String] A message that says 'success' or 'failed'.
  #  * 'deleted' [Array<Hash>] If result says success, then you will get this key.
  #    Each hash in the array contains:
  #    * 'address' [String] Host address.
  #    * 'port' [Integer] Port.
  #    * 'proto' [String] Protocol.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.del_service', {:host=>ip})
  def rpc_del_service(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    hosts  = []
    services = []
    if opts[:host] or opts[:address]
      host = opts[:host] || opts[:address]
      hent = wspace.hosts.find_by_address(host)
      return { :result => 'failed' } if hent == nil or hent.class != ::Mdm::Host
      hosts << hent
    elsif opts[:addresses]
      return { :result => 'failed' } if opts[:addresses].class != Array
      conditions = { :address => opts[:addresses] }
      hent = wspace.hosts.where(conditions)
      return { :result => 'failed' } if hent == nil
      hosts |= hent if hent.class == Array
      hosts << hent if hent.class == ::Mdm::Host
    end
    if opts[:addresses] or opts[:address] or opts[:host]
      hosts.each do |h|
        sret = nil
        if opts[:port] or opts[:proto]
          conditions = {}
          conditions[:port] = opts[:port] if opts[:port]
          conditions[:proto] = opts[:proto] if opts[:proto]
          sret = h.services.where(conditions)
          next if sret == nil
          services << sret if sret.class == ::Mdm::Service
          services |= sret if sret.class == Array
        else
          services |= h.services
        end
      end
    elsif opts[:port] or opts[:proto]
      conditions = {}
      conditions[:port] = opts[:port] if opts[:port]
      conditions[:proto] = opts[:proto] if opts[:proto]
      sret = wspace.services.where(conditions)
      services << sret if sret and sret.class == ::Mdm::Service
      services |= sret if sret and sret.class == Array
    end

    deleted = []
    services.each do |s|
      dent = {}
      dent[:address] = s.host.address.to_s
      dent[:port] = s.port
      dent[:proto] = s.proto
      deleted << dent
      s.destroy
    end

    return { :result => 'success', :deleted => deleted }
  }
  end


  # Deletes hosts.
  #
  # @param [Hash] xopts Filters to narrow down which hosts to delete.
  # @option xopts [String] :workspace Workspace name.
  # @option xopts [String] :host Host address.
  # @option xopts [String] :address Same as :host.
  # @option xopts [Array] :addresses Host addresses.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the following:
  #  * 'result' [String] A message that says 'success'.
  #  * 'deleted' [Array<String>] All the deleted hosts.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.del_host', {:host=>ip})
  def rpc_del_host(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    db_check
    opts = fix_options(xopts)
    wspace = find_workspace(opts[:workspace])
    hosts  = []
    if opts[:host] or opts[:address]
      host = opts[:host] || opts[:address]
      hent = wspace.hosts.find_by_address(host)
      return { :result => 'failed' } if hent == nil or hent.class != ::Mdm::Host
      hosts << hent
    elsif opts[:addresses]
      return { :result => 'failed' } if opts[:addresses].class != Array
      conditions = { :address => opts[:addresses] }
      hent = wspace.hosts.where(conditions)
      return { :result => 'failed' } if hent == nil
      hosts |= hent if hent.class == Array
      hosts << hent if hent.class == ::Mdm::Host
    end
    deleted = []
    hosts.each do |h|
      deleted << h.address.to_s
      h.destroy
    end

    return { :result => 'success', :deleted => deleted }
  }
  end


  # Reports a vulnerability.
  #
  # @param [Hash] xopts Information about the vulnerability:
  # @option xopts [String] :workspace Workspace name.
  # @option xopts [String] :host The host where this vulnerability resides
  # @option xopts [String] :name The friendly name for this vulnerability (title).
  # @option xopts [String] :info A human readable description of the vuln, free-form text.
  # @option xopts [Array] :refs An array of Ref objects or string names of references.
  # @option xopts [Hash] :details A hash with :key pointed to a find criteria hash and the rest containing VulnDetail fields.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash indicating whether the action was successful or not. It contains:
  #  * 'result' [String] A message that says either 'success' or 'failed'.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.report_vuln', {:host=>ip, :name=>'file upload'})
  def rpc_report_vuln(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    db_check
    opts = fix_options(xopts)
    opts[:workspace] = find_workspace(opts[:workspace]) if opts[:workspace]
    res = self.framework.db.report_vuln(opts)
    return { :result => 'success' } if res
    { :result => 'failed' }
  }
  end


  # Returns framework events.
  #
  # @param [Hash] xopts Options:
  # @option xopts [String] :workspace Workspace name.
  # @option xopts [Integer] :limit Limit.
  # @option xopts [Integer] :offset Offset.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the following:
  #  * 'events' [Array<Hash>] Each hash in the array contains the following:
  #    * 'host' [String] Host address.
  #    * 'created_at' [Integer] Creation date.
  #    * 'updated_at' [Integer] Last updated at.
  #    * 'name' [String] Event name.
  #    * 'critical' [Boolean] Criticality.
  #    * 'username' [String] Username.
  #    * 'info' [String] Additional information.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.events', {})
  def rpc_events(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    ret = {}
    ret[:events] = []

    wspace.events.offset(offset).limit(limit).each do |e|
      event = {}
      event[:host] = e.host.address if e.host
      event[:created_at] = e.created_at.to_i
      event[:updated_at] = e.updated_at.to_i
      event[:name] = e.name
      event[:critical] = e.critical if e.critical
      event[:username] = e.username if e.username
      event[:info] = e.info
      ret[:events] << event
    end
    ret
  }
  end


  # Reports a framework event.
  #
  # @param [Hash] xopts Information about the event.
  # @option xopts [String] :workspace Workspace name.
  # @option xopts [String] :username Username.
  # @option xopts [String] :host Host address.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash indicating the action was successful. It contains:
  #  * 'result' [String] A message that says 'success'.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.report_event', {:username => username, :host=>ip})
  def rpc_report_event(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    res = self.framework.db.report_event(opts)
    { :result => 'success' } if res
  }
  end


  # Reports a looted item.
  #
  # @param [Hash] xopts Information about the looted item.
  # @option xopts [String] :workspace Workspace name.
  # @option xopts [String] :host Host address.
  # @option xopts [Integer] :port Port. Should match :service.
  # @option xopts [String] :proto Protocol. Should match :service.
  # @option xopts [String] :path Required. Path where the item was looted.
  # @option xopts [String] :type Loot type.
  # @option xopts [String] :ctype Content type.
  # @option xopts [String] :name Name.
  # @option xopts [String] :info Additional information.
  # @option xopts [String] :data Looted data.
  # @option xopts [Mdm::Service] :service Service where the data was found.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the following:
  #  * 'result' [String] A message that says 'success'.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.report_loot', {})
  def rpc_report_loot(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    if opts[:host] && opts[:port] && opts[:proto]
      opts[:service] = self.framework.db.find_or_create_service(opts)
    end

    res = self.framework.db.report_loot(opts)
    { :result => 'success' } if res
  }
  end


  # Returns all the looted items.
  #
  # @param [Hash] xopts Filters that narrow down the search:
  # @option xopts [Hash] :workspace Workspace name.
  # @option xopts [Integer] :limit Limit.
  # @option xopts [Integer] :offset Offset.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the following:
  #  * 'loots' [Array<Hash>] Each hash in the array contains the following:
  #    * 'host' [String] Host address.
  #    * 'service' [String] Service name or port.
  #    * 'ltype' [String] Loot type.
  #    * 'ctype' [String] Content type.
  #    * 'data' [String] Looted data.
  #    * 'created_at' [Integer] Creation date.
  #    * 'updated_at' [Integer] Last updated at.
  #    * 'name' [String] Name.
  #    * 'info' [String] Additional information.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.loots', {})
  def rpc_loots(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    ret = {}
    ret[:loots] = []
    wspace.loots.offset(offset).limit(limit).each do |l|
      loot = {}
      loot[:host] = l.host.address if l.host
      loot[:service] = l.service.name || l.service.port  if l.service
      loot[:ltype] = l.ltype
      loot[:ctype] = l.content_type
      loot[:data] = l.data
      loot[:created_at] = l.created_at.to_i
      loot[:updated_at] = l.updated_at.to_i
      loot[:name] = l.name
      loot[:info] = l.info
      ret[:loots] << loot
    end
    ret
  }
  end


  # Imports file to the database.
  #
  # @param [Hash] xopts A hash that contains:
  # @option xopts [String] :workspace Workspace name.
  # @option xopts [String] 'data' Data to import. The method will automatically detect the file type:
  #  * :acunetix_xml
  #  * :amap_log
  #  * :amap_mlog
  #  * :appscan_xml
  #  * :burp_session_xml
  #  * :ci_xml
  #  * :foundstone_xml
  #  * :fusionvm_xml
  #  * :gpp_xml
  #  * :ip360_aspl_xml
  #  * :ip360_xml_v3
  #  * :ip_list
  #  * :libpcap
  #  * :mbsa_xml
  #  * :msf_cred_dump_zip
  #  * :msf_pwdump
  #  * :msf_xml
  #  * :msf_zip
  #  * :nessus_nbe
  #  * :nessus_xml
  #  * :nessus_xml_v2
  #  * :netsparker_xml
  #  * :nexpose_rawxml
  #  * :nexpose_simplexml
  #  * :nikto_xml
  #  * :nmap_xml
  #  * :openvas_new_xml
  #  * :openvas_xml
  #  * :outpost24_xml
  #  * :qualys_asset_xml
  #  * :qualys_scan_xml
  #  * :retina_xml
  #  * :spiceworks_csv
  #  * :wapiti_xml
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that indicates the action was successful. It contains the following:
  #  * 'result' <String> A message that says 'success'.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.import_data', {'data'=>nexpose_scan_results})
  def rpc_import_data(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    self.framework.db.import(opts)
    return { :result => 'success' }
  }
  end


  # Returns vulnerabilities from services or from a host.
  #
  # @param [Hash] xopts Filters to narrow down which vulnerabilities to find.
  # @option xopts [String] :workspace Workspace name.
  # @option xopts [String] :proto Protocol.
  # @option xopts [Integer] :port Port.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the following:
  #  * 'vuln' [Array<Hash>] Each hash in the array contains the following:
  #    * 'host' [String] Host address.
  #    * 'port' [Integer] Port.
  #    * 'proto' [String] Protocol.
  #    * 'created_at' [Integer] Creation date.
  #    * 'updated_at' [Integer] Last updated at.
  #    * 'name' [String] Vulnerability name.
  #    * 'info' [String] Additional information.
  #    * 'refs' [Array<String>] Reference names.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.get_vuln', {:proto=>'tcp'})
  def rpc_get_vuln(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)

    ret = {}
    ret[:vuln] = []

    host = self.framework.db.get_host(opts)

    return ret if not host
    vulns = []

    if opts[:proto] && opts[:port]
      services = []
      sret = host.services.find_by_proto_and_port(opts[:proto], opts[:port])
      return ret if sret == nil
      services << sret if sret.class == ::Mdm::Service
      services |= sret if sret.class == Array

      services.each do |s|
        vulns |= s.vulns
      end
    else
      vulns = host.vulns
    end

    return ret if (not vulns)

    vulns.each do |v|
      vuln= {}
      host= v.host
      vuln[:host] = host.address || "unknown"
      if v.service
        vuln[:port] = v.service.port
        vuln[:proto] = v.service.proto
      end
      vuln[:created_at] = v[:created_at].to_i
      vuln[:updated_at] = v[:updated_at].to_i
      vuln[:name] = v[:name].to_s
      vuln[:info] = v[:info].to_s
      vuln[:refs] = []
      v.refs.each do |r|
        vuln[:refs] << r.name
      end
      ret[:vuln] << vuln
    end
    ret
  }
  end


  # Returns browser clients information.
  #
  # @param [Hash] xopts Filters that narrow down the search.
  # @option xopts [String] :ua_name User-Agent name.
  # @option xopts [String] :ua_ver Browser version.
  # @option xopts [Array] :addresses Addresses.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the following:
  #  * 'clients' [Array<Hash>] Each hash in the array that contains the following:
  #   * 'host' [String] Host address.
  #   * 'ua_string' [String] User-agent string.
  #   * 'ua_name' [String] Browser name.
  #   * 'ua_ver' [String] Browser version.
  #   * 'created_at' [Integer] Creation date.
  #   * 'updated_at' [Integer] Last updated at.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.clients', {})
  def rpc_clients(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    opts, wspace = init_db_opts_workspace(xopts)
    limit = opts.delete(:limit) || 100
    offset = opts.delete(:offset) || 0

    conditions = {}
    conditions[:ua_name] = opts[:ua_name] if opts[:ua_name]
    conditions[:ua_ver] = opts[:ua_ver] if opts[:ua_ver]
    conditions["hosts.address"] = opts[:addresses] if opts[:addresses]

    ret = {}
    ret[:clients] = []

    wspace.clients.includes(:host).where(conditions).offset(offset).limit(limit).each do |c|
      client = {}
      client[:host] = c.host.address.to_s if c.host
      client[:ua_string] = c.ua_string
      client[:ua_name] = c.ua_name
      client[:ua_ver] = c.ua_ver
      client[:created_at] = c.created_at.to_i
      client[:updated_at] = c.updated_at.to_i
      ret[:clients] << client
    end
    ret
  }
  end


  # Deletes browser information from a client.
  #
  # @param [Hash] xopts Filters that narrow down what to delete.
  # @option xopts [String] :workspace Workspace name.
  # @option xopts [String] :host Host address.
  # @option xopts [String] :address Same as :host.
  # @option xopts [Array] :addresses Same as :address.
  # @option xopts [String] :ua_name Browser name.
  # @option xopts [String] :ua_ver Browser version.
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  #  * 500 Invalid workspace.
  # @return [Hash] A hash that contains the following:
  #  * 'result' [String] A message that says 'success'.
  #  * 'deleted' [Array<Hash>] Each hash in the array contains the following:
  #    * 'address' [String] Host address.
  #    * 'ua_string' [String] User-Agent string.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.del_client', {})
  def rpc_del_client(xopts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    db_check
    opts = fix_options(xopts)
    wspace = find_workspace(opts[:workspace])
    hosts = []
    clients = []

    if opts[:host] or opts[:address] or opts[:addresses]
      hosts = opts_to_hosts(xopts)
    else
      hosts = wspace.hosts
    end

    hosts.each do |h|
      cret = nil
      if opts[:ua_name] or opts[:ua_ver]
        conditions = {}
        conditions[:ua_name] = opts[:ua_name] if opts[:ua_name]
        conditions[:ua_ver] = opts[:ua_ver] if opts[:ua_ver]
        cret = h.clients.where(conditions)
      else
        cret = h.clients
      end
      next if cret == nil
      clients << cret if cret.class == ::Mdm::Client
      clients |= cret if cret.class == Array
    end

    deleted = []
    clients.each do |c|
      dent = {}
      dent[:address] = c.host.address.to_s
      dent[:ua_string] = c.ua_string
      deleted << dent
      c.destroy
    end

    { :result => 'success', :deleted => deleted }
  }
  end


  # Sets the driver for the database or returns the current one.
  #
  # @param [Hash] xopts Options:
  # @option [String] :workspace Workspace name.
  # @option [String] :driver Driver name. For example: 'postgresql'. If this option is not set,
  #                  then the method returns the current one.
  # @return [Hash] A hash that contains:
  #  * 'result' [String] Indiciating whether we've successfully set the driver or not.
  #  * 'driver' [String] If the :driver option isn't set, then this returns the current one.
  # @example Here's how you would use this from the client:
  #  # Sets a driver
  #  rpc.call('db.driver', {:driver=>new_driver})
  #  # Returns the current driver
  #  rpc.call('db.driver', {})
  def rpc_driver(xopts)
    opts = fix_options(xopts)
    if opts[:driver]
      if self.framework.db.drivers.include?(opts[:driver])
        self.framework.db.driver = opts[:driver]
        return { :result => 'success' }
      else
        return { :result => 'failed' }

      end
    else
      return { :driver => self.framework.db.driver.to_s }
    end
    return { :result => 'failed' }
  end


  # Connects to the database.
  #
  # @param [Hash] xopts Options:
  # @option xopts [String] :driver Driver name. For example: 'postgresql'.
  # @return [Hash] A hash that indicates whether the action was successful or not.
  #  * 'result' [String] A message that says either 'success' or 'failed'.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.connect', {:driver=>'postgresql'})
  def rpc_connect(xopts)
    opts = fix_options(xopts)
    if not self.framework.db.driver and not opts[:driver]
      return { :result => 'failed' }
    end

    if opts[:driver]
      if self.framework.db.drivers.include?(opts[:driver])
        self.framework.db.driver = opts[:driver]
      else
        return { :result => 'failed' }
      end
    end

    driver = self.framework.db.driver

    case driver
    when 'postgresql'
      opts['adapter'] = 'postgresql'
    else
      return { :result => 'failed' }
    end

    if (not self.framework.db.connect(opts))
      return { :result => 'failed' }
    end
    return { :result => 'success' }

  end


  # Returns the database status.
  #
  # @raise [Msf::RPC::ServerException] You might get one of these errors:
  #  * 500 ActiveRecord::ConnectionNotEstablished. Try: rpc.call('console.create').
  #  * 500 Database not loaded. Try: rpc.call('console.create')
  # @return [Hash] A hash that contains the following keys:
  #  * 'driver' [String] Name of the database driver.
  #  * 'db' [String] Name of the database.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.status')
  def rpc_status
    if (not self.framework.db.driver)
      return {:driver => 'None' }
    end

    cdb = ""
    if framework.db.connection_established?
      ::ActiveRecord::Base.connection_pool.with_connection { |conn|
        if conn.respond_to? :current_database
          cdb = conn.current_database
        else
          cdb = conn.instance_variable_get(:@config)[:database]
        end
      }
      return {:driver => self.framework.db.driver.to_s , :db => cdb }
    else
      return {:driver => self.framework.db.driver.to_s}
    end
    {:driver => 'None' }
  end


  # Disconnects the database.
  #
  # @return [Hash] A hash that indicates whether the action was successful or not. It contains:
  #  * 'result' [String] A message that says either 'success' or 'failed'.
  # @example Here's how you would use this from the client:
  #  rpc.call('db.disconnect')
  def rpc_disconnect
    if (self.framework.db)
      self.framework.db.disconnect()
      return { :result => 'success' }
    else
      return { :result => 'failed' }
    end
  end


end
end
end
