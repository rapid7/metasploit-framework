# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Packet sniffer extension user interface.
#
###
class Console::CommandDispatcher::Sniffer

  Klass = Console::CommandDispatcher::Sniffer

  include Console::CommandDispatcher

  #
  # Initializes an instance of the sniffer command interaction.
  #
  def initialize(shell)
    super
  end

  #
  # List of supported commands.
  #
  def commands
    {
      "sniffer_interfaces" => "Enumerate all sniffable network interfaces",
      "sniffer_start" => "Start packet capture on a specific interface",
      "sniffer_stop"  => "Stop packet capture on a specific interface",
      "sniffer_stats" => "View statistics of an active capture",
      "sniffer_dump"  => "Retrieve captured packet data to PCAP file",
      "sniffer_release" => "Free captured packets on a specific interface instead of downloading them",
    }
  end


  def cmd_sniffer_interfaces(*args)

    ifaces = client.sniffer.interfaces()

    print_line()

    ifaces.each do |i|
      print_line(sprintf("%d - '%s' ( type:%d mtu:%d usable:%s dhcp:%s wifi:%s )",
        i['idx'], i['description'],
        i['type'], i['mtu'], i['usable'], i['dhcp'], i['wireless'])
      )
    end

    print_line()

    return true
  end

  def cmd_sniffer_start(*args)
    intf = args.shift.to_i
    if (intf == 0)
      print_error("Usage: sniffer_start [interface-id] [packet-buffer (1-200000)] [bpf filter (posix meterpreter only)]")
      return
    end
    maxp = (args.shift || 50000).to_i
    bpf  = args.join(" ")

    client.sniffer.capture_start(intf, maxp, bpf)
    print_status("Capture started on interface #{intf} (#{maxp} packet buffer)")
    return true
  end

  def cmd_sniffer_stop(*args)
    intf = args[0].to_i
    if (intf == 0)
      print_error("Usage: sniffer_stop [interface-id]")
      return
    end

    res = client.sniffer.capture_stop(intf)
    print_status("Capture stopped on interface #{intf}")
    print_status("There are #{res[:packets]} packets (#{res[:bytes]} bytes) remaining")
    print_status("Download or release them using 'sniffer_dump' or 'sniffer_release'")
    return true
  end

  def cmd_sniffer_stats(*args)
    intf = args[0].to_i
    if (intf == 0)
      print_error("Usage: sniffer_stats [interface-id]")
      return
    end

    stats = client.sniffer.capture_stats(intf)
    print_status("Capture statistics for interface #{intf}")
    stats.each_key do |k|
      print_line("\t#{k}: #{stats[k]}")
    end

    return true
  end

  def cmd_sniffer_release(*args)
    intf = args[0].to_i
    if (intf == 0)
      print_error("Usage: sniffer_release [interface-id]")
      return
    end

    res = client.sniffer.capture_release(intf)
    print_status("Flushed #{res[:packets]} packets (#{res[:bytes]} bytes) from interface #{intf}")

    return true
  end

  def cmd_sniffer_dump(*args)
    intf = args[0].to_i
    if (intf == 0 or not args[1])
      print_error("Usage: sniffer_dump [interface-id] [pcap-file]")
      return
    end

    path_cap = args[1]
    path_raw = args[1] + '.raw'

    fd = ::File.new(path_raw, 'wb+')

    print_status("Flushing packet capture buffer for interface #{intf}...")
    res = client.sniffer.capture_dump(intf)
    print_status("Flushed #{res[:packets]} packets (#{res[:bytes]} bytes)")

    bytes_all = res[:bytes] || 0
    bytes_got = 0
    bytes_pct = 0
    linktype = res[:linktype]
    while (bytes_all > 0)
      res = client.sniffer.capture_dump_read(intf,1024*512)

      bytes_got += res[:bytes]

      pct = ((bytes_got.to_f / bytes_all.to_f) * 100).to_i
      if(pct > bytes_pct)
        print_status("Downloaded #{"%.3d" % pct}% (#{bytes_got}/#{bytes_all})...")
        bytes_pct = pct
      end
      break if res[:bytes] == 0
      fd.write(res[:data])
    end

    fd.close

    print_status("Download completed, converting to PCAP...")

    fd = nil
    if(::File.exist?(path_cap))
      fd = ::File.new(path_cap, 'ab+')
    else
      fd = ::File.new(path_cap, 'wb+')
      fd.write([0xa1b2c3d4, 2, 4, 0, 0, 65536, linktype].pack('NnnNNNN'))
    end

    pkts = {}
    od = ::File.new(path_raw, 'rb')


    # TODO: reorder packets based on the ID (only an issue if the buffer wraps)
    while(true)
      buf = od.read(20)
      break if not buf

      idh,idl,thi,tlo,len = buf.unpack('N5')
      break if not len
      if(len > 10000)
        print_error("Corrupted packet data (length:#{len})")
        break
      end

      pkt_id = (idh << 32) +idl
      pkt_ts = Rex::Proto::SMB::Utils.time_smb_to_unix(thi,tlo)
      pkt    = od.read(len)

      fd.write([pkt_ts,0,len,len].pack('NNNN')+pkt)
    end
    od.close
    fd.close

    ::File.unlink(path_raw)
    print_status("PCAP file written to #{path_cap}")
  end

  #
  # Name for this dispatcher
  # sni
  def name
    "Sniffer"
  end

end

end
end
end
end
