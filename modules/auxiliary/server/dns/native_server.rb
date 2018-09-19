##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/dns'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::DNS::Client
  include Msf::Exploit::Remote::DNS::Server

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Native DNS Server (Example)',
      'Description'    => %q{
        This module provides a Rex based DNS service which can store static entries,
        resolve names over pivots, and serve DNS requests across routed session comms.
        DNS tunnels can operate across the the Rex switchboard, and DNS other modules
        can use this as a template. Setting static records via hostfile allows for DNS
        spoofing attacks without direct traffic manipulation at the handlers. handlers
        for requests and responses provided here mimic the internal Rex functionality,
        but utilize methods within this module's namespace to output content processed
        in the Proc contexts via vprint_status.
      },
      'Author'         => 'RageLtMan <rageltman[at]sempervictus>',
      'License'        => MSF_LICENSE,
      'References'     => []
    ))
  end

  #
  # Wrapper for service execution and cleanup
  #
  def run
    begin
      start_service
      service.wait
    rescue Rex::BindFailed => e
      print_error "Failed to bind to port #{datastore['RPORT']}: #{e.message}"
    ensure
      stop_service(true)
    end
  end

  #
  # Creates Proc to handle incoming requests
  #
  def on_dispatch_request(cli,data)
    return if data.strip.empty?
    req = Packet.encode_drb(data)
    peer = "#{cli.peerhost}:#{cli.peerport}"
    asked = req.question.map(&:qname).map(&:to_s).join(', ')
    vprint_status("Received request for #{asked} from #{peer}")
    answered = []
    # Find cached items, remove request from forwarded packet
    req.question.each do |ques|
      cached = service.cache.find(ques.qname, ques.qtype.to_s)
      if cached.empty?
        next
      else
        req.instance_variable_set(:@answer, (req.answer + cached).uniq)
        answered << ques
        cached.map do |hit|
          if hit.respond_to?(:address)
            hit.name.to_s + ':' + hit.address.to_s + ' ' + hit.type.to_s
          else
            hit.name.to_s + ' ' + hit.type.to_s
          end
        end.each {|h| vprint_status("Cache hit for #{h}")}
      end
    end unless service.cache.nil?
    # Forward remaining requests, cache responses
    if answered.count < req.question.count and service.fwd_res
      if !req.header.rd
        vprint_status("Recursion forbidden in query for #{req.question.first.name} from #{peer}")
      else
        forward = req.dup
        # forward.question = req.question - answered
        forward.instance_variable_set(:@question, req.question - answered)
        forwarded = service.fwd_res.send(Packet.validate(forward))
        forwarded.answer.each do |ans|
          rstring = ans.respond_to?(:address) ? "#{ans.name}:#{ans.address}" : ans.name
          vprint_status("Caching response #{rstring} #{ans.type}")
          service.cache.cache_record(ans)
        end unless service.cache.nil?
        # Merge the answers and use the upstream response
        forward.instance_variable_set(:@question, (req.answer + forwarded.answer).uniq)
        req = forwarded
      end
    end
    service.send_response(cli, Packet.validate(Packet.generate_response(req)).encode)
  end

  #
  # Creates Proc to handle outbound responses
  #
  def on_send_response(cli,data)
    res = Packet.encode_drb(data)
    peer = "#{cli.peerhost}:#{cli.peerport}"
    asked = res.question.map(&:qname).map(&:to_s).join(', ')
    vprint_status("Sending response for #{asked} to #{peer}")
    cli.write(data)
  end


end
