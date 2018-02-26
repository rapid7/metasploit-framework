##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  RSYNC_HEADER = '@RSYNCD:'
  HANDLED_EXCEPTIONS = [
    Rex::AddressInUse, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused,
    ::Errno::ETIMEDOUT, ::Timeout::Error, ::EOFError
  ]

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
        'Jon Hart <jon_hart[at]rapid7.com>', # improved metasploit module
        'Nixawk' # improved metasploit module
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
      ]
    )

    register_advanced_options(
      [
        OptBool.new('SHOW_MOTD',
                    [ true, 'Show the rsync motd, if found', false ]),
        OptBool.new('SHOW_VERSION',
                    [ true, 'Show the rsync version', false ]),
        OptInt.new('READ_TIMEOUT', [ true, 'Seconds to wait while reading rsync responses', 2 ])
      ]
    )
  end

  def read_timeout
    datastore['READ_TIMEOUT']
  end

  def get_rsync_auth_status(rmodule)
    sock.puts("#{rmodule}\n")
    res = sock.get_once(-1, read_timeout)
    if res
      res.strip!
      if res =~ /^#{RSYNC_HEADER} AUTHREQD \S+$/
        'required'
      elsif res =~ /^#{RSYNC_HEADER} OK$/
        'not required'
      else
        vprint_error("unexpected response when connecting to #{rmodule}: #{res}")
        "unexpected response '#{res}'"
      end
    else
      vprint_error("no response when connecting to #{rmodule}")
      'no response'
    end
  end

  def rsync_list
    sock.puts("#list\n")

    modules_metadata = []
    # the module listing is the module name and comment separated by a tab, each module
    # on its own line, lines separated with a newline
    sock.get(read_timeout).split(/\n/).map(&:strip).map do |module_line|
      break if module_line =~ /^#{RSYNC_HEADER} EXIT$/
      name, comment = module_line.split(/\t/).map(&:strip)
      next unless name
      modules_metadata << { name: name, comment: comment }
    end

    modules_metadata
  end

  # Attempts to negotiate the rsync protocol with the endpoint.
  def rsync_negotiate
    # rsync is promiscuous and will send the negotitation and motd
    # upon connecting.  abort if we get nothing
    return unless (greeting = sock.get_once(-1, read_timeout))

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
      vprint_error("no rsync negotiation found")
      return
    end

    _, post_neg_data_lines = rsync_parse_lines(sock.get_once(-1, read_timeout))
    motd_lines = greeting_data_lines + post_neg_data_lines
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
    begin
      connect
      version, motd = rsync_negotiate
      unless version
        vprint_error("does not appear to be rsync")
        disconnect
        return
      end
    rescue *HANDLED_EXCEPTIONS => e
      vprint_error("error while connecting and negotiating: #{e}")
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
    print_status("rsync version: #{version}") if datastore['SHOW_VERSION']
    print_status("rsync MOTD: #{motd}") if motd && datastore['SHOW_MOTD']

    modules_metadata = {}
    begin
      modules_metadata = rsync_list
    rescue *HANDLED_EXCEPTIONS => e
      vprint_error("Error while listing modules: #{e}")
      return
    ensure
      disconnect
    end

    if modules_metadata.empty?
      print_status("no rsync modules found")
    else
      modules = modules_metadata.map { |m| m[:name] }
      print_good("#{modules.size} rsync modules found: #{modules.join(', ')}")

      table_columns = %w(Name Comment)
      if datastore['TEST_AUTHENTICATION']
        table_columns << 'Authentication'
        modules_metadata.each do |module_metadata|
          begin
            connect
            rsync_negotiate
            module_metadata[:authentication] = get_rsync_auth_status(module_metadata[:name])
          rescue *HANDLED_EXCEPTIONS => e
            vprint_error("error while testing authentication on #{module_metadata[:name]}: #{e}")
            break
          ensure
            disconnect
          end
        end
      end

      # build a table to store the module listing in
      listing_table = Msf::Ui::Console::Table.new(
        Msf::Ui::Console::Table::Style::Default,
        'Header' => "rsync modules for #{peer}",
        'Columns' => table_columns,
        'Rows' => modules_metadata.map(&:values)
      )
      vprint_line(listing_table.to_s)

      report_note(
        host: ip,
        proto: 'tcp',
        port: rport,
        type: 'rsync_modules',
        data: { modules: modules_metadata }
      )
    end
  end

  def setup
    fail_with(Failure::BadConfig, 'READ_TIMEOUT must be > 0') if read_timeout <= 0
  end
end
