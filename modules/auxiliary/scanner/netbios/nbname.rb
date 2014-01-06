##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'        => 'NetBIOS Information Discovery',
      'Description' => 'Discover host information through NetBIOS',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      Opt::RPORT(137)
    ], self.class)
  end

  def scanner_prescan(batch)
    print_status("Sending NetBIOS requests to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    @results = {}
  end

  def scan_host(ip)
    scanner_send(create_netbios_status(ip), ip, datastore['RPORT'])
  end

  def scanner_postscan(batch)

    cnt = 0

    # Perform a second pass based on responsive hosts
    @results.keys.each do |ip|
      next if not @results[ip][:name]
      scanner_send(create_netbios_lookup(@results[ip][:name]), ip, datastore['RPORT'])
      cnt += 1
    end

    # Wait for the final replies to trickle in
    scanner_recv(10) if cnt > 0

    @results.keys.each do |ip|

      host = @results[ip]
      user = ""
      os   = "Windows"

      if (host[:user] and host[:mac] != "00:00:00:00:00:00")
        user = " User:#{host[:user]}"
      end

      if (host[:mac] == "00:00:00:00:00:00")
        os = "Unix"
      end

      names = ""
      if (host[:names])
        names = " Names:(" + host[:names].map{|n| n[0]}.uniq.join(", ") + ")"
      end

      addrs = ""
      if (host[:addrs])
        addrs = "Addresses:(" + host[:addrs].map{|n| n[0]}.uniq.join(", ") + ")"
      end

      if (host[:mac] != "00:00:00:00:00:00")
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

      if (virtual)
        extra = "Virtual Machine:#{virtual}"
        report_note(
          :host  => ip,
          :type  => 'host.virtual_machine',
          :data  => {:vendor => virtual, :method => 'netbios'}
        )
      end

      if (host[:addrs])
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


  def scanner_process(data, shost, sport)

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

    @results[shost] ||= {}

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

      @results[shost][:names] = names
      @results[shost][:mac]   = maddr

      if (!hname and @results[shost][:names].length > 0)
        @results[shost][:name] = @results[shost][:names][0][0]
      end

      @results[shost][:name] = hname if hname
      @results[shost][:user] = uname if uname

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

      report_service(
        :host  => shost,
        :mac   => (maddr and maddr != '00:00:00:00:00:00') ? maddr : nil,
        :host_name => (hname) ? hname.downcase : nil,
        :port  => datastore['RPORT'],
        :proto => 'udp',
        :name  => 'netbios',
        :info  => inf
      )

    when 0x20
      1.upto(rlen / 6.0) do
        tflag = buff.slice!(0,2).unpack('n')[0]
        taddr = buff.slice!(0,4).unpack("C*").join(".")
        names << [ taddr, tflag ]
      end
      @results[shost][:addrs] = names
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
