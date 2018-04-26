##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ManualRanking

  #
  # This module does basically nothing
  # NOTE: Because of this it's missing a disclosure date that makes msftidy angry.
  #

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Generic Payload Handler',
        'Description'    => %q(
          This module is a stub that provides all of the
          features of the Metasploit payload system to exploits
          that have been launched outside of the framework.
        ),
        'License'        => MSF_LICENSE,
        'Author'         =>  [ 'hdm', 'bcook-r7' ],
        'References'     =>  [ ],
        'Payload'        =>
          {
            'Space'       => 10000000,
            'BadChars'    => '',
            'DisableNops' => true
          },
        'Platform'       => %w[android apple_ios bsd java js linux osx nodejs php python ruby solaris unix win mainframe multi],
        'Arch'           => ARCH_ALL,
        'Targets'        => [ [ 'Wildcard Target', {} ] ],
        'DefaultTarget'  => 0,
      )
    )

    register_advanced_options(
      [
        OptBool.new(
          "ExitOnSession",
          [ true, "Return from the exploit after a session has been created", true ]
        ),
        OptInt.new(
          "ListenerTimeout",
          [ false, "The maximum number of seconds to wait for new sessions", 0 ]
        )
      ]
    )
  end

  def exploit
    if datastore['DisablePayloadHandler']
      print_error "DisablePayloadHandler is enabled, so there is nothing to do. Exiting!"
      return
    end

    stime = Time.now.to_f
    timeout = datastore['ListenerTimeout'].to_i
    loop do
      break if session_created? && datastore['ExitOnSession']
      break if timeout > 0 && (stime + timeout < Time.now.to_f)
      Rex::ThreadSafe.sleep(1)
    end
  end
end
