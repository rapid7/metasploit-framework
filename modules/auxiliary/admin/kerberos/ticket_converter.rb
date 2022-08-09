##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos ticket converter',
        'Description' => %q{
          This module converts tickets to the ccache format from the kirbi format and vice versa.
        },
        'Author' => [
          'Dean Welch', # Metasploit Module
          'Zer1t0' # Impacket Implementation https://github.com/Zer1t0
        ],
        'References' => [
          ['URL', 'https://github.com/SecureAuthCorp/impacket/blob/3c6713e309cae871d685fa443d3e21b7026a2155/examples/ticketConverter.py'],
          ['URL', 'https://tools.ietf.org/html/rfc4120'],
          ['URL', 'http://web.mit.edu/KERBEROS/krb5-devel/doc/formats/ccache_file_format.html'],
          ['URL', 'https://github.com/gentilkiwi/kekeo'],
          ['URL', 'https://github.com/rvazarkar/KrbCredExport'],
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options(
      [
        OptPath.new('InputFile', [ true, 'The file path to ticket in kirbi (KRB-CRED) or ccache format.' ]),
        OptString.new('OutputPath', [ true, 'The output path to save the converted ticket.' ]),
      ]
    )
  end

  def run
    input = File.open(datastore['InputFile'], 'rb', &:read)
    if input[0..1] == "\x05\x04"
      print_status('Converting from ccache to kirbi')
      output = ccache_to_kirbi(input)
    elsif input[0] == "\x76"
      print_status('Converting from kirbi to ccache')
      output = kirbi_to_ccache(input)
    else
      fail_with(Msf::Module::Failure::BadConfig, 'Unknown file format')
    end
    path = File.expand_path(datastore['OutputPath'])
    File.write(path, output.encode, mode: 'wb')
    print_status("File written to #{path}")
  end

  def ccache_to_kirbi(input)
    ccache = Rex::Proto::Kerberos::CredentialCache::Krb5Ccache.read(input)
    Msf::Exploit::Remote::Kerberos::TicketConverter.ccache_to_kirbi(ccache)
  end

  def kirbi_to_ccache(input)
    krb_cred = Rex::Proto::Kerberos::Model::KrbCred.decode(input)
    Msf::Exploit::Remote::Kerberos::TicketConverter.kirbi_to_ccache(krb_cred)
  end
end
