##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Registry
  include Msf::Post::DNS::ResolveHost

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Enumerate Computers',
        'Description' => %q{
          This module will enumerate computers included in the primary Active Directory domain.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Joshua Abraham <jabra[at]rapid7.com>'],
        'Platform' => [ 'win'],
        'SessionTypes' => %w[meterpreter powershell shell],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_net_resolve_host
            ]
          }
        }
      )
    )
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    domain = get_domain_name

    fail_with(Failure::Unknown, 'Could not retrieve domain name. Is the host part of a domain?') unless domain

    netbios_domain_name = domain.split('.').first.upcase

    hostname_list = get_domain_computers

    if hostname_list.empty?
      print_error('No computers found')
      return
    end

    list_computers(netbios_domain_name, hostname_list)
  end

  def gethost(hostname)
    ## get IP for host
    vprint_status("Looking up IP for #{hostname}")
    resolve_host(hostname)
  end

  def get_domain_computers
    computer_list = []
    devisor = "-------------------------------------------------------------------------------\r\n"
    raw_list = cmd_exec('net view').split(devisor)[1]

    return [] unless raw_list.include?('The command completed successfully')

    raw_list.sub!(/The command completed successfully\./, '')
    raw_list.gsub!(/\\\\/, '')
    raw_list.split(' ').each do |m|
      computer_list << m
    end

    computer_list
  end

  def list_computers(domain, hosts)
    tbl = Rex::Text::Table.new(
      'Header' => 'List of identified Hosts.',
      'Indent' => 1,
      'Columns' =>
        [
          'Domain',
          'Hostname',
          'IPs',
        ]
    )
    hosts.each do |hostname|
      hostip = gethost(hostname)
      tbl << [domain, hostname, hostip]
    end

    print_line("\n#{tbl}\n")

    report_note(
      host: session,
      type: 'domain.hosts',
      data: tbl.to_csv
    )
  end
end
