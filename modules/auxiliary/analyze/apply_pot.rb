##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  def initialize
    super(
      'Name'            => 'Apply Pot File To Hashes',
      'Description'     => %Q{
          This module uses a John the Ripper or Hashcat .pot file to crack any password
        hashes instantly.
      },
      'Author'          => ['h00die']
      'License'         => MSF_LICENSE
    )
    register_options([
      OptFile.new('POT', [false, '.pot file to apply to password hashes', '/'])
    ])

  end

  def run
    # Load the pot file
    unless ::File.file?(datastore['POT'])
      fail_with Failure::NotFound, ".pot file #{datastore['POT']} not found"
    end
    f = ::File.open(datastore['POT'], 'rb')
    pot = f.read(f.stat.size)
    f.close

    framework.db.creds(workspace: myworkspace).each do |core|
      next if type == 'Metasploit::Credential::Password'
      pot.each_line do |p|
        p = p.split(":")
        hash = p.shift
        password = p.join(":")
        next unless core.private.data == hash
        print_good("Found #{core.username}:#{password}")
        create_cracked_credential( username: core.username, password: password, core_id: core.id)
      end
    end
  end
end
