##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'TFTP Brute Forcer',
      'Description' => 'This module uses a dictionary to brute force valid TFTP image names from a TFTP server.',
      'Author'      => 'antoine',
      'License'     => BSD_LICENSE
    )

    register_options(
      [
        Opt::RPORT(69),
        Opt::CHOST,
        OptPath.new('DICTIONARY', [ true, 'The list of filenames',
          File.join(Msf::Config.data_directory, "wordlists", "tftp.txt") ])
      ])
  end

  def run_host(ip)
    begin

      # Create an unbound UDP socket if no CHOST is specified, otherwise
      # create a UDP socket bound to CHOST (in order to avail of pivoting)
      udp_sock = Rex::Socket::Udp.create(
        {
          'LocalHost' => datastore['CHOST'] || nil,
          'Context'   =>
            {
              'Msf'        => framework,
              'MsfExploit' => self,
            }
        }
      )
      add_socket(udp_sock)

      fd = File.open(datastore['DICTIONARY'], 'rb')
      fd.read(fd.stat.size).split("\n").each do |filename|
        filename.strip!
        pkt = "\x00\x01" + filename + "\x00" + "netascii" + "\x00"
        udp_sock.sendto(pkt, ip, datastore['RPORT'])
        resp = udp_sock.get(3)
        if resp and resp.length >= 2 and resp[0, 2] == "\x00\x03"
          print_good("Found #{filename} on #{ip}")
          #Add Report
          report_note(
            :host	=> ip,
            :proto => 'udp',
            :sname	=> 'tftp',
            :port	=> datastore['RPORT'],
            :type	=> "Found #{filename}",
            :data	=> "Found #{filename}"
          )
        end
      end
      fd.close
    rescue
    ensure
      udp_sock.close
    end
  end
end
