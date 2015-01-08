##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/java/serialization'

class Metasploit3 < Msf::Auxiliary

  include Msf::Rmi::Client
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Java RMI Server Insecure Endpoint Code Execution Scanner',
      'Description' => 'Detect Java RMI endpoints',
      'Author'     => ['mihi', 'hdm'],
      'License'     => MSF_LICENSE,
      'References'     =>
        [
          # RMI protocol specification
          [ 'URL', 'http://download.oracle.com/javase/1.3/docs/guide/rmi/spec/rmi-protocol.html'],
          # Placeholder reference for matching
          [ 'MSF', 'java_rmi_server']
        ],
      'DisclosureDate' => 'Oct 15 2011'
    )

    register_options(
      [
        Opt::RPORT(1099)
      ], self.class)
  end

  def run_host(target_host)
    vprint_status("#{peer} - Sending RMI Header...")
    connect
    begin
      send_header
    rescue ::RuntimeError
      print_error("#{peer} - Filed to negotiate RMI protocol")
      disconnect
      return
    end

    # Determine if the instance allows remote class loading
    vprint_status("#{peer} - Sending RMI Call...")
    jar = Rex::Text.rand_text_alpha(rand(8)+1) + '.jar'
    jar_url = "file:RMIClassLoaderSecurityTest/" + jar
    begin
      return_data = send_call(call_data: build_gc_call_data(jar_url))
    rescue ::RuntimeError
      print_error("#{peer} - Failed to send RMI Call, anyway JAVA RMI Endpoint detected")
      report_service(:host => rhost, :port => rport, :name => "java-rmi", :info => "")
      disconnect
      return
    end
    disconnect

    if loader_enabled?(return_data)
      print_good("#{rhost}:#{rport} Java RMI Endpoint Detected: Class Loader Enabled")
      svc = report_service(:host => rhost, :port => rport, :name => "java-rmi", :info => "Class Loader: Enabled")
      report_vuln(
        :host         => rhost,
        :service      => svc,
        :name         => self.name,
        :info         => "Module #{self.fullname} confirmed remote code execution via this RMI service",
        :refs         => self.references
      )
    else
      print_status("#{rhost}:#{rport} Java RMI Endpoint Detected: Class Loader Disabled")
      report_service(:host => rhost, :port => rport, :name => "java-rmi", :info => "Class Loader: Disabled")
    end

  end

  def loader_enabled?(stream)
    stream.contents.each do |content|
      if content.class == Rex::Java::Serialization::Model::NewObject &&
          content.class_desc.description.class == Rex::Java::Serialization::Model::NewClassDesc &&
          content.class_desc.description.class_name.contents == 'java.lang.ClassNotFoundException'

        if content.class_data[0].class == Rex::Java::Serialization::Model::NullReference &&
            content.class_data[1].contents.include?('RMI class loader disabled')
          return false
        else
          return true
        end

      end
    end

    false
  end

end
