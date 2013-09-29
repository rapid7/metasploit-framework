##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'NetBIOS Information Discovery Prober',
            'Description' => 'Discover host information using sequential NetBIOS Probes',
            'Author'      => ['hdm', 'todb'],
            'License'     => MSF_LICENSE
        )
    )

    register_options(
    [
      Opt::CHOST,
      Opt::RPORT(137)
    ], self.class)
  end

  def rport
    datastore['RPORT'].to_i
  end

  # Fingerprint a single host
  def run_host(ip)

    @thost = ip

    @results = {}
    begin
      udp_sock = nil

      # Create an unbound UDP socket if no CHOST is specified, otherwise
      # create a UDP socket bound to CHOST (in order to avail of pivoting)
      udp_sock = Rex::Socket::Udp.create( {
        'LocalHost' => datastore['CHOST'] || nil,
        'PeerHost'  => ip, 'PeerPort' => rport,
        'Context' => {'Msf' => framework, 'MsfExploit' => self}
      })
      add_socket(udp_sock)

        begin
          data = create_netbios_status(ip)
          udp_sock.put(data)
        rescue ::Interrupt
          raise $!
        rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
          nil
        end

        while (r = udp_sock.recvfrom(65535, 0.1) and r[1])
          parse_reply(r)
        end

      while (r = udp_sock.recvfrom(65535, 3) and r[1])
        parse_reply(r)
      end

      # Second pass to find additional IPs per host name

      @results.keys.each do |ip|
        next if not @results[ip][:name]
        begin
          data = create_netbios_lookup(@results[ip][:name])
          udp_sock.put(data)
        rescue ::Interrupt
          raise $!
        rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
          nil
        end

        while (r = udp_sock.recvfrom(65535, 0.1) and r[1])
          parse_reply(r)
        end

      end

      while (r = udp_sock.recvfrom(65535, 3) and r[1])
        parse_reply(r)
      end

    rescue ::Interrupt
      raise $!
    rescue ::Errno::ENOBUFS
      print_status("Socket buffers are full, waiting for them to flush...")
      while (r = udp_sock.recvfrom(65535, 0.1) and r[1])
        parse_reply(r)
      end
      select(nil, nil, nil, 0.25)
    rescue ::Exception => e
      print_error("Unknown error: #{e.class} #{e}")
    end

    @results.keys.each do |ip|
      next unless inside_workspace_boundary?(ip)
      host = @results[ip]
      user = ""
      os   = "Windows"

      if(host[:user] and host[:mac] != "00:00:00:00:00:00")
        user = " User:#{host[:user]}"
      end

      if(host[:mac] == "00:00:00:00:00:00")
        os = "Unix"
      end

      names = ""
      if host[:names]
        names = " Names:(" + host[:names].map{|n| n[0]}.uniq.join(", ") + ")"
      end

      addrs = ""
      if(host[:addrs])
        addrs = "Addresses:(" + host[:addrs].map{|n| n[0]}.uniq.join(", ") + ")"
      end

      if(host[:mac] != "00:00:00:00:00:00")
        report_host(:host => ip, :mac => host[:mac])
      else
        report_host(:host => ip)
      end

      extra = ""

      virtual = nil
      case host[:mac]
      when /^00:13:07/i
        virtual = 'ParaVirtual'
      when /^(00:1C:14|00:50:56|00:05:69|00:0c:29)/i
        virtual = 'VMWare'
      when /^00:1C:42/
        virtual = "Parallels"
      when /^00:18:51/
        virtual = "SWsoft Virtuozzo"
      when /^00:21:F6/i
        virtual = 'Virtual Iron'
      when /^00:16:3e/
        virtual = 'Xen'
      when /^(54:52:00|DE:AD:BE)/
        virtual = 'QEMU (unofficial)'
      when /^00:24:0B/i
        virtual = 'Virtual Computer Inc'
      end

      if(virtual)
        extra = "Virtual Machine:#{virtual}"
        report_note(
          :host  => ip,
          :type  => 'host.virtual_machine',
          :data  => {:vendor => virtual, :method => 'netbios'}
        )
      end

      if(host[:addrs])
        aliases = []
        host[:addrs].map{|n| n[0]}.uniq.each do |addr|
          next if addr == ip
          aliases << addr
        end

        if not aliases.empty?
          report_note(
            :host  => ip,
            :proto => 'udp',
            :port  => 137,
            :type  => 'netbios.addresses',
            :data  => {:addresses => aliases}
          )
        end
      end

      print_status("#{ip} [#{host[:name]}] OS:#{os}#{user}#{names} #{addrs} Mac:#{host[:mac]} #{extra}")
    end
  end


  def parse_reply(pkt)
    # Ignore "empty" packets
    return if not pkt[1]

    addr = pkt[1]
    if(addr =~ /^::ffff:/)
      addr = addr.sub(/^::ffff:/, '')
    end

    data = pkt[0]

    head = data.slice!(0,12)

    xid, flags, quests, answers, auths, adds = head.unpack('n6')

    return if quests != 0
    return if answers == 0

    qname = data.slice!(0,34)
    rtype,rclass,rttl,rlen = data.slice!(0,10).unpack('nnNn')
    buff = data.slice!(0,rlen)

    names = []

    hname = nil
    uname = nil

    case rtype
    when 0x21
      rcnt = buff.slice!(0,1).unpack("C")[0]
      1.upto(rcnt) do
        tname = buff.slice!(0,15).gsub(/\x00.*/, '').strip
        ttype = buff.slice!(0,1).unpack("C")[0]
        tflag = buff.slice!(0,2).unpack('n')[0]
        names << [ tname, ttype, tflag ]
        hname = tname if ttype == 0x20
        uname = tname if ttype == 0x03
      end
      maddr = buff.slice!(0,6).unpack("C*").map{|c| "%.2x" % c }.join(":")

      @results[addr] = {
        :names => names,
        :mac   => maddr
      }

      if (!hname and @results[addr][:names].length > 0)
        @results[addr][:name] = @results[addr][:names][0][0]
      end

      @results[addr][:name] = hname if hname
      @results[addr][:user] = uname if uname

      inf = ''
      names.each do |name|
        inf << name[0]
        inf << ":<%.2x>" % name[1]
        if (name[2] & 0x8000 == 0)
          inf << ":U :"
        else
          inf << ":G :"
        end
      end
      inf << maddr

      if inside_workspace_boundary?(addr)
        report_service(
          :host  => addr,
          :mac   => (maddr and maddr != '00:00:00:00:00:00') ? maddr : nil,
          :host_name => (hname) ? hname.downcase : nil,
          :port  => pkt[2],
          :proto => 'udp',
          :name  => 'netbios',
          :info  => inf
        )
      end
    when 0x20
      1.upto(rlen / 6.0) do
        tflag = buff.slice!(0,2).unpack('n')[0]
        taddr = buff.slice!(0,4).unpack("C*").join(".")
        names << [ taddr, tflag ]
      end
      @results[addr][:addrs] = names
    end
  end

  def create_netbios_status(ip)
    data =
    [rand(0xffff)].pack('n')+
    "\x00\x00\x00\x01\x00\x00\x00\x00"+
    "\x00\x00\x20\x43\x4b\x41\x41\x41"+
    "\x41\x41\x41\x41\x41\x41\x41\x41"+
    "\x41\x41\x41\x41\x41\x41\x41\x41"+
    "\x41\x41\x41\x41\x41\x41\x41\x41"+
    "\x41\x41\x41\x00\x00\x21\x00\x01"

    return data
  end

  def create_netbios_lookup(name)
    name = [name].pack("A15") + "\x00"

    data =
    [rand(0xffff)].pack('n') +
    "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
    "\x20" +
    Rex::Proto::SMB::Utils.nbname_encode(name) +
    "\x00" +
    "\x00\x20\x00\x01"

    return data
  end
end
