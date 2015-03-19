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
      'Name'        => 'Java RMI Registry Interfaces Enumeration',
      'Description'    => %q{
        This module gathers information from an RMI endpoint running an RMI registry
        interface. It enumerates the names bound into a registry and lookups each
        remote reference.
      },
      'Description' => 'Information gathering from Java RMI Registry endpoints',
      'Author'      => ['juan vazquez'],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['URL', 'http://docs.oracle.com/javase/8/docs/platform/rmi/spec/rmiTOC.html']
        ]
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
      lookup_call = build_registry_lookup(name: name)
      send_call(call: lookup_call)
      return_value = recv_return
      if return_value.nil?
        print_error("#{peer} - Failed to lookup #{name}")
        next
      end

      remote_stub = parse_registry_lookup(return_value)
      if remote_stub.nil?
        print_error("#{peer} - Failed to lookup #{name}")
        next
      end

      location = parse_registry_lookup_endpoint(return_value)
      if location.nil?
        print_error("#{peer} - Failed to locate #{name} / #{remote_stub}")
      end

      print_good("#{peer} - Name #{name} (#{remote_stub}) found on #{location[:address]}:#{location[:port]}")
      report_service(:host => location[:address], :port => location[:port], :name => 'java-rmi', :info => "Name: #{name}, Stub: #{remote_stub}")
    end
  end
end
