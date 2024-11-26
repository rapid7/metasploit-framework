##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/java/serialization'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Java::Rmi::Client
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Java JMX Server Insecure Endpoint Code Execution Scanner',
      'Description' => 'Detect Java JMX endpoints',
      'Author'     => ['rocktheboat'],
      'License'     => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://docs.oracle.com/javase/8/docs/technotes/guides/jmx/JMX_1_4_specification.pdf'],
          ['URL', 'https://www.optiv.com/blog/exploiting-jmx-rmi'],
          ['CVE', '2015-2342']
        ],
      'Platform'       => 'java',
      'DisclosureDate' => 'May 22 2013'
    )

    register_options(
      [
        Opt::RPORT(1099)
      ])
  end

  def run_host(target_host)
    mbean_server = { "address" => rhost, "port" => rport }

    connect
    print_status("Sending RMI header...")
    unless is_rmi?
      print_status("#{rhost}:#{rport} Java JMX RMI not detected")
      disconnect
      return
    end

    mbean_server = discover_endpoint
    disconnect

    if mbean_server.nil?
      print_status("#{rhost}:#{rport} Java JMX MBean not detected")
      return
    end

    connect(true, { 'RHOST' => mbean_server[:address], 'RPORT' => mbean_server[:port] })

    unless is_rmi?
      print_status("#{rhost}:#{rport} Java JMX RMI not detected")
      disconnect
      return
    end

    jmx_endpoint = handshake(mbean_server)
    disconnect

    if jmx_endpoint == false
      print_status("#{mbean_server[:address]}:#{mbean_server[:port]} Java JMX MBean authentication required")
      return
    elsif jmx_endpoint.nil?
      print_status("#{mbean_server[:address]}:#{mbean_server[:port]} Java JMX MBean status unknown")
      return
    end

    print_good("Handshake with JMX MBean server on #{jmx_endpoint[:address]}:#{jmx_endpoint[:port]}")
    svc = report_service(:host => rhost, :port => rport, :name => "java-rmi", :info => "JMX MBean server accessible")
    report_vuln(
      :host         => rhost,
      :service      => svc,
      :name         => self.name,
      :info         => "Module #{self.fullname} confirmed RCE via JMX RMI service",
      :refs         => self.references
    )
  end

  def is_rmi?
    send_header
    ack = recv_protocol_ack
    if ack.nil?
      return false
    end

    true
  end

  def discover_endpoint
    rmi_classes_and_interfaces = [
      'javax.management.remote.rmi.RMIConnectionImpl',
      'javax.management.remote.rmi.RMIConnectionImpl_Stub',
      'javax.management.remote.rmi.RMIConnector',
      'javax.management.remote.rmi.RMIConnectorServer',
      'javax.management.remote.rmi.RMIIIOPServerImpl',
      'javax.management.remote.rmi.RMIJRMPServerImpl',
      'javax.management.remote.rmi.RMIServerImpl',
      'javax.management.remote.rmi.RMIServerImpl_Stub',
      'javax.management.remote.rmi.RMIConnection',
      'javax.management.remote.rmi.RMIServer'
    ]

    ref = send_registry_lookup(name: "jmxrmi")
    return nil if ref.nil?

    unless rmi_classes_and_interfaces.include? ref[:object]
      vprint_error("JMXRMI discovery returned unexpected object #{ref[:object]}")
      return nil
    end

    ref
  end

  def handshake(mbean)
    opts = {
      object_number: mbean[:object_number],
      uid_number: mbean[:uid].number,
      uid_time: mbean[:uid].time,
      uid_count: mbean[:uid].count
    }
    send_new_client(opts)
  rescue ::Rex::Proto::Rmi::Exception => e
    vprint_error("JMXRMI discovery raised an exception of type #{e.message}")
    if e.message == 'java.lang.SecurityException'
      return false
    end
    return nil
  end
end
