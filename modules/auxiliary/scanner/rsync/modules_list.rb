##
# This module requires Metasploit: http://metasploit.com/download
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

  def rsync_list
    sock.puts("#list\n")

    list = []
    # the module listing is the module name and comment separated by a tab, each module
    # on its own line, lines separated with a newline
    sock.get(20).split(/\n/).map(&:strip).map do |module_line|
      next if module_line =~ /^@RSYNCD: EXIT$/
      list << module_line.split(/\t/).map(&:strip)
    end
    list
  end

  def rsync_negotiate
    connect
    return unless greeting = sock.get_once

    greeting.strip!
    if /^@RSYNCD: (?<version>\d+(\.\d+)?)$/ =~ greeting
      # making sure we match the version of the server
      sock.puts("@RSYNCD: #{version}\n")
      version
    end
  end

  def run_host(ip)
    unless version = rsync_negotiate
      disconnect
      return
    end

    report_service(
      host: ip,
      port: rport,
      proto: 'tcp',
      name: 'rsync',
      info: "rsync protocol version #{version}"
    )

    listing = rsync_list
    if listing.empty?
      print_status("#{ip}:#{port} - rsync #{version}: no modules found")
    else
      # build a table to store the module listing in
      listing_table = Msf::Ui::Console::Table.new(
        Msf::Ui::Console::Table::Style::Default,
        'Header' => "rsync modules",
        'Columns' =>
          [
            "Name",
            "Comment"
          ],
        'Rows' => listing
      )

      print_good("#{ip}:#{rport} - rsync #{version}: #{listing_table.rows.size} modules found")
      vprint_line(listing_table.to_s)

      report_note(
        host: ip,
        proto: 'tcp',
        port: rport,
        type: 'rsync_modules',
        :data   => { :modules => listing_table.rows },
        :update => :unique_data
      )
    end
  end
end
