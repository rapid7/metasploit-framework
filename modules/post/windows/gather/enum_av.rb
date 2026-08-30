##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Installed AntiVirus Enumeration',
        'Description' => %q{
          This module will enumerate the AV products detected by WMIC
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'rageltman <rageltman[at]sempervictus>' ],
        'Platform' => %w[win],
        'SessionTypes' => [ 'meterpreter', 'shell' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  # Run Method for when run command is issued
  def run
    if command_exists?('wmic') == false
      print_error("The 'wmic' command doesn't exist on this host!") # wmic is technically marked as deprecated so this command could very well be removed in future releases.
      return
    end
    avs = {}
    cmd = 'wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get * /value'
    resp = cmd_exec(cmd, nil, 6000).to_s
    fail_with(Failure::Unknown, resp) if resp[0..5].upcase == 'ERROR:'
    resp.split("\r\r\n\r\r\n").map do |ent|
      next if ent.strip.empty?

      print_status("Found AV product:\n#{ent}\n")
      av_note = ent.lines.map(&:strip).map.select { |e| e.length > 1 }.map { |e| e.split('=', 2) }.to_h
      avn = av_note.delete('displayName')
      avs[avn] = av_note
    end
    report_note(host: target_host, type: 'windows.antivirus', data: avs, update: :unique_data)
  end
end
