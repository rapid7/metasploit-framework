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
      'Description' => 'List all (listable) modules from a rsync daemon',
      'Author'      => 'ikkini',
      'References'  =>
        [
          ['URL', 'http://rsync.samba.org/ftp/rsync/rsync.html']
        ],
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        Opt::RPORT(873)
      ], self.class)
  end

  def run_host(ip)
    connect
    version = sock.get_once

    print_good("#{ip}:#{rport} - rsync #{version.strip} found")
    report_service(:host => ip, :port => rport, :proto => 'tcp', :name => 'rsync')
    report_note(
        :host => ip,
        :proto => 'tcp',
        :port => rport,
        :type => 'rsync_version',
        :data => version.strip
    )

    # making sure we match the version of the server
    sock.puts("#{version}")
    # the listing command
    sock.puts("\n")
    listing = sock.get(20)
    disconnect

    return if listing.blank?

    print_good("#{ip}:#{rport} - rsync listing found")
    listing.gsub!('@RSYNCD: EXIT', '') # not interested in EXIT message
    listing_sanitized = Rex::Text.to_hex_ascii(listing.strip)

    vprint_status("#{ip}:#{rport} - #{version.rstrip} #{listing_sanitized}")
    report_note(
        :host => ip,
        :proto => 'tcp',
        :port => rport,
        :type => 'rsync_listing',
        :data => listing_sanitized
    )
  end
end
