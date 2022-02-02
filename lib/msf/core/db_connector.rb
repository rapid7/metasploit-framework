# -*- coding: binary -*-

module Msf

##
#
# This class is used when wanting to connect/disconnect framework
# from a particular database or http service
#
##
module DbConnector
  DbConfigGroup = 'framework/database'

  #
  # Connect to a database by using the default framework config, or the config file provided
  #
  def self.db_connect_from_config(framework, path = nil)
    begin
      conf = Msf::Config.load(path)
    rescue StandardError => e
      wlog("Failed to load configuration: #{e}")
      return {}
    end

    if conf.group?(DbConfigGroup)
      conf[DbConfigGroup].each_pair do |k, v|
        next unless k.downcase == 'default_db'

        ilog 'Default data service found. Attempting to connect...'
        db_name = v
        config = load_db_config(db_name, path)
        if config
          if framework.db.active && config[:url] !~ /http/
            ilog 'Existing local data connection found. Disconnecting first.'
            db_disconnect(framework)
          end

          return db_connect(framework, config).merge(data_service_name: db_name)
        else
          elog "Config entry for '#{db_name}' could not be found. Config file might be corrupt."
        end
      end
    end

    {}
  end

  # Connect to the required database
  #
  # @Example Connect to a remote http service
  #   db_connect(
  #     framework,
  #     {
  #       url: 'https://localhost:5443',
  #       cert: '/Users/user/.msf4/msf-ws-cert.pem',
  #       skip_verify: true,
  #       api_token: 'b1ca123e2f160a8a1fbf79baed180b8dc480de5b994f53eee42e57771e3f65e13bec737e4a4acbb2'
  #     }
  #   )
  def self.db_connect(framework, opts = {})
    unless framework.db.driver
      return { error: 'No database driver installed.'}
    end

    if !opts[:url] && !opts[:yaml_file]
      return { error: 'A URL or saved data service name is required.' }
    end

    if opts[:url] =~ /http/
      new_conn_type = 'http'
    else
      new_conn_type = framework.db.driver
    end

    # Currently only able to be connected to one DB at a time
    if framework.db.connection_established?
      # But the http connection still requires a local database to support AR, so we have to allow that
      # Don't allow more than one HTTP service, though
      if new_conn_type != 'http' || framework.db.get_services_metadata.count >= 2
        return {
          error: 'Connection already established. Only one connection is allowed at a time. Run db_disconnect first if you wish to connect to a different data service.'
        }
      end
    end

    if opts[:yaml_file]
      db_connect_yaml(framework, opts)
    elsif new_conn_type == 'http'
      db_connect_http(framework, as_connection_options(opts))
    elsif new_conn_type == 'postgresql'
      db_connect_postgresql(framework, as_connection_options(opts))
    else
      {
        error: "This database driver #{new_conn_type} is not currently supported"
      }
    end
  end

  #
  # Disconnect from the currently connected database. This will gracefully fallback
  # from a remote data service to a local postgres instance if configured correctly.
  #
  def self.db_disconnect(framework)
    result = { old_data_service_name: framework.db.name }
    unless framework.db.driver
      result[:error] = 'No database driver installed.'
      return result
    end

    if framework.db.active
      if framework.db.driver == 'http'
        begin
          framework.db.delete_current_data_service
          local_db_url = build_postgres_url
          local_name = data_service_search(url: local_db_url)
          result[:data_service_name] = local_name
        rescue StandardError => e
          result[:error] = e.message
        end
      else
        framework.db.disconnect
        result[:data_service_name] = nil
      end
    end

    result
  end

  #
  # Connect to a database via the supplied yaml file
  #
  def self.db_connect_yaml(framework, opts)
    file = opts[:yaml_file] || ::File.join(Msf::Config.get_config_root, 'database.yml')
    file = ::File.expand_path(file)
    unless ::File.exist?(file)
      return { error: 'File not found' }
    end
    begin
      db = YAML.load(::File.read(file))['production']
    rescue => _e
      return { error: 'File did not contain valid production database credentials' }
    end

    framework.db.connect(db)

    local_db_url = build_postgres_url
    local_name = data_service_search(url: local_db_url)
    return {
      result: 'Connected to the database specified in the YAML file',
      data_service_name: local_name
    }
  end

  #
  # Connect to an existing http database
  #
  def self.db_connect_http(framework, opts)
    # local database is required to use Mdm objects
    unless framework.db.active
      error = 'No local database connected, meaning some Metasploit features will not be available. A full list of '\
      'the affected features & database setup instructions can be found here: '\
      'https://github.com/rapid7/metasploit-framework/wiki/msfdb:-Database-Features-&-How-to-Set-up-a-Database-for-Metasploit'

      return {
        error: error
      }
    end

    uri = db_parse_db_uri_http(opts[:url])

    remote_data_service = Metasploit::Framework::DataService::RemoteHTTPDataService.new(uri.to_s, opts)
    begin
      framework.db.register_data_service(remote_data_service)
      framework.db.workspace = framework.db.default_workspace
      {
        result: "Connected to HTTP data service: #{remote_data_service.name}",
        data_service_name: data_service_search(url: opts[:url])
      }
    rescue => e
      {
        error: "Failed to connect to the HTTP data service: #{e.message}"
      }
    end
  end

  #
  # Connect to an existing Postgres database
  #
  def self.db_connect_postgresql(framework, cli_opts)
    info = db_parse_db_uri_postgresql(cli_opts[:url])
    opts = { 'adapter' => 'postgresql' }

    opts['username'] = info[:user] if (info[:user])
    opts['password'] = info[:pass] if (info[:pass])
    opts['database'] = info[:name]
    opts['host'] = info[:host] if (info[:host])
    opts['port'] = info[:port] if (info[:port])

    opts['pass'] ||= ''

    # Do a little legwork to find the real database socket
    if !opts['host']
      while(true)
        done = false
        dirs = %W{ /var/run/postgresql /tmp }
        dirs.each do |dir|
          if ::File.directory?(dir)
            d = ::Dir.new(dir)
            d.entries.grep(/^\.s\.PGSQL.(\d+)$/).each do |ent|
              opts['port'] = ent.split('.')[-1].to_i
              opts['host'] = dir
              done = true
              break
            end
          end
          break if done
        end
        break
      end
    end

    # Default to loopback
    unless opts['host']
      opts['host'] = '127.0.0.1'
    end

    if framework.db.connect(opts) && framework.db.connection_established?
      {
        result: "Connected to Postgres data service: #{info[:host]}/#{info[:name]}",
        data_service_name: data_service_search(url: opts[:url]) || framework.db.name
      }
    else
      {
        error: "Failed to connect to the Postgres data service: #{framework.db.error}"
      }
    end
  end

  def self.db_parse_db_uri_postgresql(path)
    res = {}
    if path
      auth, dest = path.split('@')
      (dest = auth and auth = nil) if not dest
      # remove optional scheme in database url
      auth = auth.sub(/^\w+:\/\//, '') if auth
      res[:user],res[:pass] = auth.split(':') if auth
      targ,name = dest.split('/')
      (name = targ and targ = nil) if not name
      res[:host],res[:port] = targ.split(':') if targ
    end
    res[:name] = name || 'metasploit3'
    res
  end

  def self.db_parse_db_uri_http(path)
    URI.parse(path)
  end

  def self.build_postgres_url
    conn_params = ApplicationRecord.connection_db_config.configuration_hash
    url = ''
    url += "#{conn_params[:username]}" if conn_params[:username]
    url += ":#{conn_params[:password]}" if conn_params[:password]
    url += "@#{conn_params[:host]}" if conn_params[:host]
    url += ":#{conn_params[:port]}" if conn_params[:port]
    url += "/#{conn_params[:database]}" if conn_params[:database]
    url
  end

  #
  # Search for a human readable data service name based on the search criteria
  # The search criteria can match against a service name or url
  #
  def self.data_service_search(name: nil, url: nil)
    conf = Msf::Config.load
    result = nil

    conf.each_pair do |key, value|
      conf_name = key.split('/').last
      has_name_match = !name.nil? && (conf_name == name)
      has_url_match = !url.nil? && (value.is_a?(Hash) && value['url'] == url)
      if has_name_match || has_url_match
        result = conf_name
      end
    end
    result
  end

  def self.load_db_config(db_name, path = nil)
    conf = Msf::Config.load(path)
    conf_options = conf["#{DbConfigGroup}/#{db_name}"]
    return unless conf_options

    conf_options.transform_keys(&:to_sym)
  end

  def self.as_connection_options(conf_options)
    opts = {}
    https_opts = {}
    if conf_options
      opts[:url] = conf_options[:url] if conf_options[:url]
      opts[:api_token] = conf_options[:api_token] if conf_options[:api_token]
      https_opts[:cert] = conf_options[:cert] if conf_options[:cert]
      https_opts[:skip_verify] = conf_options[:skip_verify] if conf_options[:skip_verify]
    else
      return
    end

    opts[:https_opts] = https_opts unless https_opts.empty?
    opts
  end
end
end
