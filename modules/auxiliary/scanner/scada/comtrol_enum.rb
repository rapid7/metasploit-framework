##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Comtrol device scanner and enumerator',
      'Description' => %q{
        This module allows enumeration of Comtrol devices by querying UDP/4606.  Reverse engineering of packet captures from PortVision DX as well
        as a head-start by the referenced Kemp blog allowed most of the tags returned to be associated to meaningful labels. If the first 4 bytes of the probe
        are replaced, the debug console (tcp/4607) gives an error message of 'bad cookie', which is why it is labeled as 'cookie'.  The scans can be configured
        to only target specific mac addresses by setting the scan_macs variable as outlined in the Kemp blog.  This scanner works slightly differently than
        PortVision DX in that it directly queries the IP on UDP/4606 instead of sending the packet to broadcast. Should work on Comtrol DeviceMaster, IO-Link Master,
        and RocketLinx models.
      },
      'References'  =>
        [
          [ 'URL', 'https://blog.kempj.co.uk/2020/01/devicemaster-protocol-part-1/' ],
          [ 'URL', 'https://comtrol.com/resources/product-resources-white-papers/additional-resources/portvision-dx' ],
        ],
      'Author'      => 'nowhey',
      'License'     => MSF_LICENSE
      ))

    register_options(
    [
      Opt::RPORT(4606)
    ])
  end

  def run_host(ip)
    begin
      mysock = connect_udp()
      cookie_and_id = "\xa9\x8d\xfd\x53" + "\xfa\x7b\xfc\x69\x00\x00"                                   # 1st sequence believed to cookie and 2nd believed to be identifier of scanner
      scan_label = "\xe5\x01"                                                                           # believed to be similar to a session identifier
      scan_type = "\x0c"                                                                                # a request for a tag 12 (inventory) of system
      scan_macs = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"        # these can have length(s) and mac(s) added, see referenced blog
      # fuzzing different aspects of this query revealed that the request can be up to 512 bytes before it is ignored
      probe = cookie_and_id + scan_label + scan_type + scan_macs
      tags = {
        # label controls how it is reported in print_good and report_note, type controls formatting of the values
        10 => { 'label' => "ip_mode", 'type' => 'text'},                                                # can be static or DHCP, int value
        16 => { 'label' => "serial", 'type' => 'text'},
        18 => { 'label' => "manufacturer", 'type' => 'text'},
        19 => { 'label' => "model", 'type' => 'text'},
        20 => { 'label' => "firmware", 'type' => 'text'},
        22 => { 'label' => "mac", 'type' => 'hex'},
        23 => { 'label' => "ip", 'type' => 'dec'},
        24 => { 'label' => "netmask", 'type' => 'dec'},
        25 => { 'label' => "gateway", 'type' => 'dec'},
        26 => { 'label' => "addr_mode", 'type' => 'dec'},                                               # (0=static, 1=dhcp), seems to repeat tag 10
        27 => { 'label' => "unk_1b", 'type' => 'hexn'},                                                 # tag 1b 1 byte in examples
        28 => { 'label' => "ip?", 'type' => 'dec'},                                                     # tag 1c unknown why it repeats ip info
        29 => { 'label' => "netmask?", 'type' => 'dec'},                                                # tag 1d unknown why it repeats netmask
        30 => { 'label' => "gateway?", 'type' => 'dec'},                                                # tag 1e unknown why it repeats gateway
        35 => { 'label' => "hostname", 'type' => 'text'},
        39 => { 'label' => "ipv6_mode", 'type' => 'dec'},                                               # tag 27 (0=disabled)
        40 => { 'label' => "ipv6_static_ip", 'type' => 'hex'},
        41 => { 'label' => "ipv6_static_prefix_length", 'type' => 'dec'},
        42 => { 'label' => "ipv6_static_prefix", 'type' => 'hex'},
        43 => { 'label' => "unk_2b", 'type' => 'hexn'},                                                 # tag 2b 4 bytes in example
        44 => { 'label' => "model_number", 'type' => 'int'},
        45 => { 'label' => "unk_2d", 'type' => 'hexn'},                                                 # tag 2d 1 byte in example
        46 => { 'label' => "unk_2e", 'type' => 'hexn'},                                                 # tag 2e 1 byte in example
        47 => { 'label' => "unk_2f", 'type' => 'hexn'},                                                 # tag 2f 1 byte in example
        48 => { 'label' => "unk_30", 'type' => 'hexn'},                                                 # tag 30 1 byte in example
        49 => { 'label' => "unk_31", 'type' => 'hexn'},                                                 # tag 31 4 bytes in example
        50 => { 'label' => "snmp_telnet_bitflag", 'type' => 'dec'},
        51 => { 'label' => "ipv6_dhcp_ip", 'type' => 'hex'},
        52 => { 'label' => "ipv6_dhcp_prefix_length", 'type' => 'dec'},
        53 => { 'label' => "ipv6_dhcp_prefix", 'type' => 'hex'},
        55 => { 'label' => "bootloader", 'type' => 'text'},
      }

      result = {}

      mysock.send(probe, 0)
      data, src, src_port = mysock.recvfrom(65535)

      return if(data.length == 0)
      mybytes = data.unpack("C*");
      i = cookie_and_id.length + scan_label.length + 2
      while(i < data.length) do
        tag = mybytes[i]
        label = tags[tag]['label']
        type = tags[tag]['type']
        if(label.nil?)
          i = i + 2 + mybytes[i+1]
          vprint_status("#{ip} returned unexpected tag: #{tag}")
          next
        end
        len = mybytes[i+1]

        arr = mybytes.slice(i+2, len)
        out = ''
        if(type == 'text')
          arr.each { |n| out = out + n.chr }
        elsif(type == 'hex')
          arr.each { |n| b = n.to_s(16); b = "0" + b if(n.to_s(16).length == 1); out = out + b + ":" }
        elsif(type == 'dec')
          arr.each { |n| out = out + n.to_s + "." }
        elsif(type =='int')
          arr.each { |n| out = out + n.to_s(16) }
          out = "0x" + out
          out = out.to_i(16).to_s
        elsif(type == 'hexn')
          arr.each { |n| b = n.to_s(16); b = "0" + b if(n.to_s(16).length == 1); out = out + b }
          out = "0x" + out
        end

        if(type == 'dec' or type == 'hex')
          out = out.chop
        end

        if((tag == 51 or tag == 53 or tag == 40 or tag == 42) and out == "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00")
          out = "unset"
        elsif(tag == 50)
          #from left to right (msb->lsb)
          # bit 0 = secure data
          # bit 1 = secure config
          # bit 2 = telnet/ssh
          # bit 3 = snmp
          val = arr[0]
          out = ''
          if(val >= 8 and val <= 15)
            out = "secure data"
            val = val - 8
          end
          if(val >= 4 and val <= 7)
            if(out.length > 0)
              out = out + ", "
            end
            out = out + "secure config"
            val = val - 4
          end
          if(val >= 2 and val <= 3)
            if(out.length > 0)
              out = out + ", "
            end
            out = out + "telnet/ssh"
            val = val - 2
          end
          if(val == 1)
            if(out.length > 0)
              out = out + ", "
            end
            out = out + "snmp"
            val = val - 1
          end
          out = out + " enabled"
        elsif(tag == 26)
          out = (out == 0) ? "static" : "dhcp"
        elsif(tag == 39 and out == "0")
          out = "disabled"
        end
        result[label] = out
        i = i + len + 2
      end
      vprint_status("#{ip} unknown tags:\n1b: #{result['unk_1b']}\n2b: #{result['unk_2b']}\n2d: #{result['unk_2d']}\n2e: #{result['unk_2e']}\n2f: #{result['unk_2f']}\n30: #{result['unk_30']}\n31: #{result['unk_31']}")
      print_good("#{ip} hostname:#{result['hostname']} mac:#{result['mac']} serial:#{result['serial']} model:#{result['model']} model_number:#{result['model_number']} firmware:#{result['firmware']} ipmode:#{result['addr_mode']} gateway:#{result['gateway']} netmask:#{result['netmask']}")
      vprint_status("#{ip} returned #{result.inspect}")
      report_service(:host => rhost, :port => rport, :name => "comtrol")
      report_note(
        :host => rhost,
        :port => rport,
        :type => 'comtrol.enum',
        :data => {:hostname => result['hostname'], :serial => result['serial'], :mac => result['mac'], :firmware => result['firmware'], :ipmode => result['addr_mode'], :netmask => result['netmask'], :gateway => result['gateway']}
      )
      mysock.close

    rescue Errno::ECONNREFUSED
      print_error("#{ip}, Connection refused.")
    rescue ::Interrupt
    raise $!
    rescue ::Exception => e
      print_error("#{ip}, Unknown error: #{e.class} #{e} #{e.backtrace}")
    end
  end
end

