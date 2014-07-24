##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Rsync Unauthenticated List Command',
      'Description' => 'List rsync available modules',
      'Author'      => 'avuko',
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        Opt::RPORT(873),
        OptInt.new('TIMEOUT', [true, 'Timeout for the Rsync probe', 30])
    ], self.class)
  end

  def to
    return 30 if datastore['TIMEOUT'].to_i.zero?
    datastore['TIMEOUT'].to_i
  end

  def run_host(ip)
    begin
      ::Timeout.timeout(to) do
        connect()
        version = sock.recv(1024)
        # making sure we match the version of the server
        sock.puts("#{version}" )
        sock.puts("\n")
        listing = sock.get()
        # not interested in EXIT message
        listing = listing.to_s.gsub('@RSYNCD: EXIT', '')
        disconnect()

        listing_santized = Rex::Text.to_hex_ascii(listing.to_s.strip)
        print_status("#{ip}:#{rport} #{version.rstrip.to_s} #{listing_santized}")
        report_service(:host => rhost, :port => rport, :name => "rsync", :info => listing_santized)
      end
    rescue ::Rex::ConnectionError
    rescue Timeout::Error
      print_error("#{target_host}:#{rport}, Server timed out after #{to} seconds. Skipping.")
    rescue ::Exception => e
      print_error("#{e} #{e.backtrace}")
    end
  end
end
