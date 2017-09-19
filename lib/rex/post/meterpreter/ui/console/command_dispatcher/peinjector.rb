# -*- coding: binary -*-
require 'rex/post/meterpreter'
require 'pry'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Peinjector extension - inject a given shellcode into an executable file
#
###
class Console::CommandDispatcher::Peinjector

  Klass = Console::CommandDispatcher::Peinjector

  include Console::CommandDispatcher

  #
  # Name for this dispatcher
  #
  def name
    'Peinjector'
  end

  #
  # List of supported commands.
  #
  def commands
    {
      'injectpe'  => 'Inject a shellcode into a given executable'
    }
  end


  @@injectpe_opts = Rex::Parser::Arguments.new(
    '-s' => [true, 'Specify the raw shellcode'],
    '-h' => [false, 'Help banner']
  )

  def injectpe_usage
    print_line('Usage: injectpe -s <raw shellcode> -e <remote file location>')
    print_line
    print_line('Inject a shellcode on the target executable.')
    print_line(@@injectpe_opts.usage)
  end

  #
  # Inject a given shellcode into a remote executable
  #
  def cmd_injectpe(*args)
    if args.length == 0 || args.include?('-h')
	    injectpe_usage
      return false
    end

    opts = {
      shellcode: args.shift
    	}

    @@injectpe_opts.parse(args) { |opt, idx, val|
      case opt
      when '-s'
        opts[:shellcode] = val
      end
    exj}

    result = client.peinjector.inject_shellcode(opts)
    print_good("Command execution completed:\n#{result}")
  end

end

end
end
end
end

