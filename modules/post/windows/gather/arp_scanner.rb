##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report

  OUI_LIST = Rex::Oui

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather ARP Scanner',
        'Description' => %q{
          This module will perform an ARP scan for a given IP range through a
          Meterpreter session.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
            ]
          }
        }
      )
    )
    register_options(
      [
        OptString.new('RHOSTS', [true, 'The target address range or CIDR identifier', nil]),
        OptInt.new('THREADS', [false, 'The number of concurrent threads', 10])
      ]
    )
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")
    arp_scan(datastore['RHOSTS'], datastore['THREADS'])
  end

  def arp_scan(cidr, threads)
    print_status("ARP Scanning #{cidr}")
    ws = client.railgun.ws2_32
    iphlp = client.railgun.iphlpapi
    a = []
    iplst = []
    found = ''
    ipadd = Rex::Socket::RangeWalker.new(cidr)
    numip = ipadd.num_ips
    while (iplst.length < numip)
      ipa = ipadd.next_ip
      if !ipa
        break
      end

      iplst << ipa
    end

    while !iplst.nil? && !iplst.empty?
      a = []
      1.upto(threads) do
        a << framework.threads.spawn("Module(#{refname})", false, iplst.shift) do |ip_text|
          next if ip_text.nil?

          h = ws.inet_addr(ip_text)
          ip = h['return']
          h = iphlp.SendARP(ip, 0, 6, 6)
          if h['return'] == client.railgun.const('NO_ERROR')
            mac_text = h['pMacAddr'].unpack('C*').map { |e| '%02x' % e }.join(':')
            company = OUI_LIST.lookup_oui_company_name(mac_text)
            print_good("\tIP: #{ip_text} MAC #{mac_text} (#{company})")
            report_host(host: ip_text, mac: mac_text)
            next if company.nil?

            report_note(host: ip_text, type: 'mac_oui', data: { :company => company })
          end
        end
      end
      a.map(&:join)
    end
    return found
  end
end
