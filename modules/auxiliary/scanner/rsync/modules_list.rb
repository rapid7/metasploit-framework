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

  def read_timeout
    10
  end

  def rsync_list
    sock.puts("#list\n")

    list = []
    # the module listing is the module name and comment separated by a tab, each module
    # on its own line, lines separated with a newline
    sock.get(read_timeout).split(/\n/).map(&:strip).map do |module_line|
      next if module_line =~ /^@RSYNCD: EXIT$/
      list << module_line.split(/\t/).map(&:strip)
    end

    list
  end

  def rsync_negotiate
    return unless greeting = sock.get(read_timeout)

    greeting.strip!
    control_lines = []
    motd_lines = []
    greeting.split(/\n/).map do |greeting_line|
      if greeting_line =~ /^@RSYNCD:/
        control_lines << greeting_line
      else
        motd_lines << greeting_line
      end
    end

    control_lines.map do |control_line|
      if /^@RSYNCD: (?<version>\d+(\.\d+)?)$/ =~ control_line
        motd = motd_lines.empty? ? nil : motd_lines.join("\n")
        sock.puts("@RSYNCD: #{version}\n")
      end
      return version, motd
    end

    nil
  end

  def run_host(ip)
    connect
    version, motd = rsync_negotiate
    unless version
      disconnect
      return
    end

    info = "rsync protocol version #{version}"
    info += ", MOTD '#{motd}'" if motd
    report_service(
      host: ip,
      port: rport,
      proto: 'tcp',
      name: 'rsync',
      info: info
    )
    vprint_good("#{ip}:#{rport} - rsync MOTD: #{motd}") if motd

    listing = rsync_list
    if listing.empty?
      print_status("#{ip}:#{rport} - rsync #{version}: no modules found")
    else
      # build a table to store the module listing in
      listing_table = Msf::Ui::Console::Table.new(
        Msf::Ui::Console::Table::Style::Default,
        'Header' => "rsync modules for #{ip}:#{rport}",
        'Columns' =>
          [
            "Name",
            "Comment"
          ],
        'Rows' => listing
      )

      print_good("#{ip}:#{rport} - rsync #{version}: #{listing.size} modules found: " \
                 "#{listing.map(&:first).join(', ')}")
      vprint_line(listing_table.to_s)

      report_note(
        host: ip,
        proto: 'tcp',
        port: rport,
        type: 'rsync_modules',
        data: { modules: listing },
        update: :unique_data
      )
    end
  end
end
