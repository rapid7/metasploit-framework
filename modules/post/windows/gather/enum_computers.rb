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

  # Takes the host name and makes use of nslookup to resolve the IP
  #
  # @param [String] host Hostname
  # @return [String] ip The resolved IP
  def gethost(hostname, family)
    ## get IP for host
    vprint_status("Looking up IP for #{hostname}")
    resolve_host(hostname, family)
  end

  def get_domain_computers
    computer_list = []
    divisor = "-------------------------------------------------------------------------------\r\n"
    net_view_response = cmd_exec("cmd.exe", "/c net view")
    unless net_view_response.include?(divisor)
      print_error("The net view command failed with: #{net_view_response}")
      return []
    end

    raw_list = net_view_response.split(divisor)[1]
    raw_list.sub!(/The command completed successfully\./, '')
    raw_list.gsub!(/\\\\/, '')
    raw_list.split(' ').each do |m|
      computer_list << m
    end

    computer_list
  end

  def list_computers(domain, hosts)
    meterpreter_dns_resolving_errors = []
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
      begin
        hostipv4 = gethost(hostname, AF_INET)
      rescue Rex::Post::Meterpreter::RequestError => e
        meterpreter_dns_resolving_errors << "IPV4: #{hostname} could not be resolved - #{e}"
      end

      begin
        hostname = "google.com"
        hostipv6 = gethost(hostname, AF_INET6)
      rescue Rex::Post::Meterpreter::RequestError => e
        meterpreter_dns_resolving_errors << "IPV6: #{hostname} could not be resolved - #{e}"
      end

      hostipv4.each { |ip| tbl << [domain, hostname, ip] } unless hostipv4.nil?
      hostipv6.each { |ip| tbl << [domain, hostname, ip] } unless hostipv6.nil?
    end

    print_line("\n#{tbl}\n")

    meterpreter_dns_resolving_errors.each do | error |
      print_warning(error)
    end

    report_note(
      host: session,
      type: 'domain.hosts',
      data: tbl.to_csv
    )
  end
end
