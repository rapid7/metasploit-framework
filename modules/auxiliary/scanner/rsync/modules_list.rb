##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  RSYNC_HEADER = '@RSYNCD:'

  def initialize
    super(
      'Name'        => 'List Rsync Modules',
      'Description' => %q(
        An rsync module is essentially a directory share.  These modules can
        optionally be protected by a password.  This module connects to and
        negotiates with an rsync server, lists the available modules and,
        optionally, determines if the module requires a password to access.
      ),
      'Author'      => [
        'ikkini', # original metasploit module
        'Jon Hart <jon_hart[at]rapid7.com>' # improved metasploit module
      ],
      'References'  =>
        [
          ['URL', 'http://rsync.samba.org/ftp/rsync/rsync.html']
        ],
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        OptBool.new('TEST_AUTHENTICATION',
                    [ true, 'Test if the rsync module requires authentication', true ]),
        Opt::RPORT(873)
      ], self.class)
  end

  def read_timeout
    10
  end

  def rsync_requires_auth?(rmodule)
    sock.puts("#{rmodule}\n")
    res = sock.get_once
    if res && (res =~ /^#{RSYNC_HEADER} AUTHREQD/)
      true
    else
      false
    end
  end

  def rsync_list
    sock.puts("#list\n")

    list = []
    # the module listing is the module name and comment separated by a tab, each module
    # on its own line, lines separated with a newline
    sock.get(read_timeout).split(/\n/).map(&:strip).map do |module_line|
      next if module_line =~ /^#{RSYNC_HEADER} EXIT$/
      name, comment = module_line.split(/\t/).map(&:strip)
      list << [ name, comment ]
    end

    list
  end

  # Attempts to negotiate the rsync protocol with the endpoint.
  def rsync_negotiate(get_motd)
    # rsync is promiscuous and will send the negotitation and motd
    # upon connecting.  abort if we get nothing
    return unless (greeting = sock.get_once)

    # parse the greeting control and data lines.  With some systems, the data
    # lines at this point will be the motd.
    greeting_control_lines, greeting_data_lines = rsync_parse_lines(greeting)

    # locate the rsync negotiation and complete it by just echo'ing
    # back the same rsync version that it sent us
    version = nil
    greeting_control_lines.map do |greeting_control_line|
      if /^#{RSYNC_HEADER} (?<version>\d+(\.\d+)?)$/ =~ greeting_control_line
        version = Regexp.last_match('version')
        sock.puts("#{RSYNC_HEADER} #{version}\n")
      end
    end

    unless version
      vprint_error("#{ip}:#{rport} - no rsync negotation found")
      return
    end

    motd_lines = greeting_data_lines
    if get_motd
      _, post_neg_data_lines = rsync_parse_lines(sock.get_once)
      motd_lines |= post_neg_data_lines
    end
    [ version, motd_lines.empty? ? nil : motd_lines.join("\n") ]
  end

  # parses the control and data lines from the provided response data
  def rsync_parse_lines(response_data)
    control_lines = []
    data_lines = []

    if response_data
      response_data.strip!
      response_data.split(/\n/).map do |line|
        if line =~ /^#{RSYNC_HEADER}/
          control_lines << line
        else
          data_lines << line
        end
      end
    end

    [ control_lines, data_lines ]
  end

  def run_host(ip)
    connect
    version, motd = rsync_negotiate(true)
    unless version
      vprint_error("#{ip}:#{rport} - does not appear to be rsync")
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
    disconnect
    if listing.empty?
      print_status("#{ip}:#{rport} - rsync #{version}: no modules found")
    else
      print_good("#{ip}:#{rport} - rsync #{version}: #{listing.size} modules found: " \
                 "#{listing.map(&:first).join(', ')}")

      table_columns = %w(Name Comment)
      if datastore['TEST_AUTHENTICATION']
        table_columns << 'Authentication?'
        listing.each do |name_comment|
          connect
          rsync_negotiate(false)
          name_comment << rsync_requires_auth?(name_comment.first)
          disconnect
        end
      end

      # build a table to store the module listing in
      listing_table = Msf::Ui::Console::Table.new(
        Msf::Ui::Console::Table::Style::Default,
        'Header' => "rsync modules for #{ip}:#{rport}",
        'Columns' => table_columns,
        'Rows' => listing
      )
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
