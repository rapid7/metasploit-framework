##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/dns'

class Metasploit < Msf::Auxiliary

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
    ensure
      stop_service(true)
    end
  end

  #
  # Creates Proc to handle incoming requests
  #
  def on_dispatch_request(cli,data)
    req = Packet.encode_net(data)
    peer = "#{cli.peerhost}:#{cli.peerport}"
    asked = req.question.map(&:qName).join(', ')
    vprint_status("Received request for #{asked} from #{peer}")
    forward = req.dup
    # Find cached items, remove request from forwarded packet
    req.question.each do |ques|
      cached = service.cache.find(ques.qName, ques.qType.to_s)
      if cached.empty?
        next
      else
        req.answer = req.answer + cached
        forward.question.delete(ques)
        hits = cached.map do |hit|
          hit.name + ':' + hit.address.to_s + ' ' + hit.type
        end.each {|h| vprint_status("Cache hit for #{h}")}
      end
    end unless service.cache.nil?
    # Forward remaining requests, cache responses
    if forward.question.count > 0 and service.fwd_res
      if !forward.header.recursive?
        vprint_status("Recursion forbidden in query for #{forward.question.first.name} from #{peer}")
      else
        forwarded = service.fwd_res.send(Packet.validate(forward))
        forwarded.answer.each do |ans|
          vprint_status("Caching response #{ans.name}:#{ans.address} #{ans.type}")
          service.cache.cache_record(ans)
        end unless service.cache.nil?
        # Merge the answers and use the upstream response
        forwarded.answer = req.answer + forwarded.answer
        req = forwarded
      end
    end
    service.send_response(cli, Packet.validate(Packet.generate_response(req)).data)
  end

  #
  # Creates Proc to handle outbound responses
  #
  def on_send_response(cli,data)
    res = Packet.encode_net(data)
    peer = "#{cli.peerhost}:#{cli.peerport}"
    asked = res.question.map(&:qName).join(', ')
    vprint_status("Sending response for #{asked} to #{peer}")
    cli.write(data)
  end


end
