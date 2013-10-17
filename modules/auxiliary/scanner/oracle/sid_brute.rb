##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::TNS
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute # Actually, doesn't use much here, but there's a couple handy functions.

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle TNS Listener SID Bruteforce',
      'Description'    => %q{
        This module queries the TNS listner for a valid Oracle database
        instance name (also known as a SID).
        Any response other than a "reject" will be considered a success.
        If a specific SID is provided, that SID will be attempted. Otherwise,
        SIDs read from the named file will be attempted in sequence instead.
      },
      'Author'         => [ 'todb' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptPath.new('SID_FILE', [ false, "File containing instance names, one per line", File.join(Msf::Config.install_root, "data", "wordlists", "sid.txt") ]),
        OptString.new('SID', [ false, 'A specific SID to attempt.' ]),
        Opt::RPORT(1521)
      ], self.class)

    deregister_options(
      "RHOST", "USERNAME", "PASSWORD", "USER_FILE", "PASS_FILE", "USERPASS_FILE",
      "BLANK_PASSWORDS", "USER_AS_PASS", "REMOVE_USER_FILE", "REMOVE_PASS_FILE",
      "REMOVE_USERPASS_FILE"
    )
  end

  def build_sid_request(sid,ip)
    connect_data = "(DESCRIPTION=(CONNECT_DATA=(SID=#{sid})(CID=(PROGRAM=)(HOST=__jdbc__)(USER=)))(ADDRESS=(PROTOCOL=tcp)(HOST=#{ip})(PORT=#{rport})))"
    pkt = tns_packet(connect_data)
  end

  def hostport
    [target_host,rport].join(":")
  end

  def check_sid(sid,ip)
    pkt = build_sid_request(sid,ip)
    sock.put(pkt)
    data = sock.get_once || ''
    parse_response(data)
  end

  def parse_response(data)
    return unless data
    len,sum,type,r,hsum,rest = data.unpack("nnCCnA*")
    type # 2 is "accept", 11 is resend. Usually you get 11, then 2. 4 is refuse.
  end

  def do_sid_check(sid,ip)
    begin
      connect
      response_code = check_sid(sid,ip)
      if response_code.nil?
        print_status "#{hostport} Oracle - No response given, something is wrong."
        return :abort
      elsif response_code != 4
        print_good "#{hostport} Oracle - '#{sid}' is valid"
        report_note(
          :host => ip,
          :proto => 'tcp',
          :port => rport,
          :sname => 'oracle',
          :type => "oracle.sid",
          :data => sid,
          :update => :unique_data
        )
        return :success
      else
        vprint_status "#{hostport} Oracle - Refused '#{sid}'"
        return :fail
      end
      disconnect
    rescue ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{hostport} Oracle - unable to connect to a TNS listener")
      return :abort
    end
  end

  # Based vaugely on each_user_pass in AuthBrute
  def each_sid(&block)
    @@oracle_sid_fail = []
    @@oracle_sid_success = []
    if datastore['SID'].nil? || datastore['SID'].empty?
      sids = extract_words(datastore['SID_FILE']).map {|s| s.to_s.strip.upcase}.uniq
    else
      sids = [datastore['SID'].to_s.strip.upcase]
    end
    print_status "Checking #{sids.size} SID#{sids.size != 1 && "s"} against #{hostport}"
    sids.each do |s|
      userpass_sleep_interval unless (@@oracle_sid_fail | @@oracle_sid_success).empty?
      next if @@oracle_sid_fail.include?(s) || @@oracle_sid_success.include?(s)
      ret = block.call(s)
      case ret
      when :abort
        break
      when :success
        @@oracle_sid_success << s
        break if datastore["STOP_ON_SUCCESS"]
      when :fail
        @@oracle_sid_fail << s
      end
    end
  end

  def run_host(ip)
    each_sid do |sid|
      vprint_status "#{hostport} Oracle - Checking '#{sid}'..."
      do_sid_check(sid,ip)
    end
  end
end
