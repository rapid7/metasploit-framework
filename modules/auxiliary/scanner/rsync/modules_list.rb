##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Rsync Unauthenticated List Command',
      'Description' => 'List all (listable) modules from a rsync daemon',
      'Author'      => ['ikkini', 'Nixawk'],
      'References'  =>
        [
          ['URL', 'http://rsync.samba.org/ftp/rsync/rsync.html']
        ],
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        Opt::RPORT(873),
        OptBool.new('AUTH_CHECK', [true, 'Check authentication or not', false])
      ], self.class)
  end

  def rsync(dir)
    connect

    version = sock.get_once # server_initialisation
    return if version.blank?

    sock.get(3) # server_motd
    sock.puts(version) # client_initialisation
    sock.puts(dir) # client_query
    data = sock.get(3) # module_list
    data.gsub!('@RSYNCD: EXIT', '')
    disconnect
    [version, data]
  end

  def auth?(dir)
    _version, data = rsync(dir)
    if data && data =~ /RSYNCD: OK/m
      vprint_status("#{dir} needs authentication: false")
      false
    else
      vprint_status("#{dir} needs authentication: true")
      true
    end
  end

  def module_list_format(ip, module_list)
    mods = {}
    rows = []

    return if module_list.blank?

    module_list = module_list.strip
    module_list = module_list.split("\n")

    module_list.each do |mod|
      name, desc = mod.split("\t")
      name = name.strip
      next unless name

      if datastore['AUTH_CHECK']
        is_auth = "#{auth?(name)}"
      else
        is_auth = 'Unknown'
      end

      rows << [name, desc, is_auth]
    end

    unless rows.blank?
      table = Msf::Ui::Console::Table.new(
        Msf::Ui::Console::Table::Style::Default,
        'Columns' =>
        [
          'Name',
          'Comment',
          'Authentication?'
        ],
        'Rows' => rows)
      vprint_line(table.to_s)
    end
    mods[ip] = rows
    return if mods.blank?
    path = store_loot(
      'rsync',
      'text/plain',
      ip,
      mods.to_json,
      'rsync')
    print_good('Saved file to: ' + path)
    mods
  end

  def run_host(ip)
    vprint_status("#{ip}:#{rport}")
    version, data = rsync('')
    return if data.blank?

    print_good("#{ip}:#{rport} - #{version.chomp} found")

    report_service(
      :host => ip,
      :port => rport,
      :proto => 'tcp',
      :name => 'rsync'
    )
    module_list_format(ip, data)
  end
end
