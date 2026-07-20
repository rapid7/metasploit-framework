##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::DNS::Client
  include Msf::Exploit::Remote::DNS::Server

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Native DNS Server (Example)',
        'Description' => %q{
          This module provides a Rex based DNS service which can store static entries,
          resolve names over pivots, and serve DNS requests across routed session comms.
          DNS tunnels can operate across the Rex switchboard, and DNS other modules
          can use this as a template. Setting static records via hostfile allows for DNS
          spoofing attacks without direct traffic manipulation at the handlers. handlers
          for requests and responses provided here mimic the internal Rex functionality,
          but utilize methods within this module's namespace to output content processed
          in the Proc contexts via vprint_status.
        },
        'Author' => 'RageLtMan <rageltman[at]sempervictus>',
        'License' => MSF_LICENSE,
        'References' => [],
        'Actions' => [
          [ 'Service', { 'Description' => 'Run DNS service' } ]
        ],
        'PassiveActions' => [
          'Service'
        ],
        'DefaultAction' => 'Service',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  #
  # Wrapper for service execution and cleanup
  #
  def run
    start_service
    service.wait
  rescue Rex::BindFailed => e
    print_error "Failed to bind to port #{datastore['RPORT']}: #{e.message}"
  end

  #
  # Creates Proc to handle incoming requests
  #
  def on_dispatch_request(cli, data)
    return if data.strip.empty?

    req = Packet.encode_drb(data)
    peer = "#{cli.peerhost}:#{cli.peerport}"
    asked = req.question.map(&:qname).map(&:to_s).join(', ')
    vprint_status("Received request for #{asked} from #{peer}")
    answered = []

    # Find cached items, remove request from forwarded packet
    unless service.cache.nil?
      req.question.each do |ques|
        cached = service.cache.find(ques.qname, ques.qtype.to_s)
        next if cached.empty?

        req.instance_variable_set(:@answer, (req.answer + cached).uniq)
        answered << ques

        cached.each do |hit|
          if hit.respond_to?(:address)
            vprint_status("Cache hit for #{hit.name}:#{hit.address} #{hit.type}")
          else
            vprint_status("Cache hit for #{hit.name} #{hit.type}")
          end
        end
      end
    end

    # Forward remaining requests, cache responses
    if (answered.count < req.question.count) && service.fwd_res
      if !req.header.rd
        vprint_status("Recursion forbidden in query for #{req.question.first.name} from #{peer}")
      else
        forward = req.dup
        # forward.question = req.question - answered
        forward.instance_variable_set(:@question, req.question - answered)
        forwarded = service.fwd_res.send(Packet.validate(forward))
        unless service.cache.nil?
          forwarded.answer.each do |ans|
            rstring = ans.respond_to?(:address) ? "#{ans.name}:#{ans.address}" : ans.name
            vprint_status("Caching response #{rstring} #{ans.type}")
            service.cache.cache_record(ans)
          end
        end
        # Merge the answers and use the upstream response
        forward.instance_variable_set(:@answer, (req.answer + forwarded.answer).uniq)
        req = forwarded
      end
    end

    service.send_response(cli, Packet.validate(Packet.generate_response(req)).encode)
  end

  #
  # Creates Proc to handle outbound responses
  #
  def on_send_response(cli, data)
    res = Packet.encode_drb(data)
    peer = "#{cli.peerhost}:#{cli.peerport}"
    asked = res.question.map(&:qname).map(&:to_s).join(', ')
    vprint_status("Sending response for #{asked} to #{peer}")
    cli.write(data)
  end
end
