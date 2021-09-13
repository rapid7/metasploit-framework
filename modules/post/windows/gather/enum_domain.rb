##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => "Windows Gather Enumerate Domain",
        'Description' => %q{
          This module identifies the primary domain via the registry. The registry value used is:
          HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\DCName.
        },
        'License' => MSF_LICENSE,
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Author' => ['Joshua Abraham <jabra[at]rapid7.com>']
      )
    )
  end

  def gethost(hostorip)
    # check for valid ip and return if it is
    return hostorip if Rex::Socket.dotted_ip?(hostorip)

    ## get IP for host
    vprint_status("Looking up IP for #{hostorip}")
    result = client.net.resolve.resolve_host(hostorip)
    return result[:ip] if result[:ip]
    return nil if result[:ip].nil? || result[:ip].empty?
  end

  def run
    domain = get_domain("DomainControllerName")
    if !domain.nil? && domain =~ /\./
      dom_info = domain.split('.')
      dom_info[0].sub!(/\\\\/, '')
      report_note(
        host: session,
        type: 'windows.domain',
        data: { domain: dom_info[1] },
        update: :unique_data
      )
      print_good("FOUND Domain: #{dom_info[1]}")
      dc_ip = gethost(dom_info[0])
      if !dc_ip.nil?
        print_good("FOUND Domain Controller: #{dom_info[0]} (IP: #{dc_ip})")
        report_host({
          host: dc_ip,
          name: dom_info[0],
          info: "Domain controller for #{dom_info[1]}"
        })
      else
        print_good("FOUND Domain Controller: #{dom_info[0]}")
      end
    end
  end
end
