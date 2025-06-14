##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::DCERPC

  include Msf::Auxiliary::Report

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Hidden DCERPC Service Discovery',
      'Description' => %q{
        This module will query the endpoint mapper and make a list
      of all ncacn_tcp RPC services. It will then connect to each of
      these services and use the management API to list all other
      RPC services accessible on this port. Any RPC service found attached
      to a TCP port, but not listed in the endpoint mapper, will be displayed
      and analyzed to see whether anonymous access is permitted.
      },
      'Author' => 'hdm',
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    deregister_options('RPORT')
  end

  # Obtain information about a single host
  def run_host(ip)
    epm = dcerpc_endpoint_list
    if !epm
      print_status("Could not contact the endpoint mapper on #{ip}")
      return
    end

    eports = {}

    epm.each do |ep|
      next if !(ep[:port] && ep[:prot] && (ep[:prot] == 'tcp'))

      eports[ep[:port]] ||= {}
      eports[ep[:port]][ep[:uuid] + '_' + ep[:vers]] = true
    end

    eports.each_pair do |eport, servs|
      rport = eport
      print_status("Looking for services on #{ip}:#{rport}...")

      ids = dcerpc_mgmt_inq_if_ids(rport)
      next if !ids

      ids.each do |id|
        next if servs.key?(id[0] + '_' + id[1])

        print_status("\tHIDDEN: UUID #{id[0]} v#{id[1]}")

        conn = nil
        bind = nil
        call = nil
        data = nil
        error = nil
        begin
          connect(true, { 'RPORT' => eport })
          conn = true

          handle = dcerpc_handle(id[0], id[1], 'ncacn_ip_tcp', [eport])
          dcerpc_bind(handle)
          bind = true

          dcerpc.call(0, NDR.long(0) * 128)
          call = true

          if !dcerpc.last_response.nil? && !dcerpc.last_response.stub_data.nil?
            data = dcerpc.last_response.stub_data
          end
        rescue ::Interrupt
          raise $ERROR_INFO
        rescue StandardError => e
          error = e.to_s
        end

        if error
          if error =~ /DCERPC FAULT/ && error !~ /nca_s_fault_access_denied/
            call = true
          else
            elog(e)
          end
        end

        status = "\t\t"
        status << 'CONN ' if conn
        status << 'BIND ' if bind
        status << 'CALL ' if call
        status << "DATA=#{data.unpack('H*')[0]} " if data
        status << "ERROR=#{error} " if error

        print_status(status)
        print_status('')

        report_note(
          host: ip,
          proto: 'tcp',
          port: datastore['RPORT'],
          type: "DCERPC HIDDEN: UUID #{id[0]} v#{id[1]}",
          data: { status: status }
        )
      end
    end
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue StandardError => e
    print_status("Error: #{e}")
  end
end
