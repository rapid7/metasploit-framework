##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/java/serialization'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Java::Rmi::Client

  def initialize
    super(
      'Name'        => 'Java RMI Registry Endpoint Information Gathering',
      'Description' => 'Information gathering from Java RMI Registry endpoints',
      'Author'     => ['juan vazquez'],
      'License'     => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://docs.oracle.com/javase/8/docs/platform/rmi/spec/rmiTOC.html']
        ],
      'DisclosureDate' => 'Mar 18 2015'
    )

    register_options(
      [
        Opt::RPORT(1099)
      ], self.class)
  end

  def run
    print_status("#{peer} - Sending RMI Header...")
    connect

    send_header
    ack = recv_protocol_ack
    if ack.nil?
      print_error("#{peer} - Filed to negotiate RMI protocol")
      disconnect
      return
    end

    print_status("#{peer} - Listing names in the Registry...")
    names = send_registry_list

    if names.nil?
      print_error("#{peer} - Failed to list names")
      return
    end

    if names.empty?
      print_error("#{peer} - Names not found in the Registry")
      return
    end

    print_good("#{peer} - #{names.length} names found in the Registry")

    names.each do |name|
      object = send_registry_lookup(name: name)
      next if object.nil?
      print_good("#{peer} - name: #{name} remote object: #{object}")
      #report_service(:host => rhost, :port => rport, :name => "java-rmi", :info => "#{name} / #{object}")
    end
  end
end
