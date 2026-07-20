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
          'Zer1t0', # Impacket Implementation https://github.com/Zer1t0
          'Dean Welch', # Metasploit Module
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
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options(
      [
        OptPath.new('InputPath', [ true, 'The file path to ticket in kirbi (KRB-CRED) or ccache format.' ]),
        OptString.new('OutputPath', [ true, 'The output path to save the converted ticket.' ]),
      ]
    )
    register_advanced_options(
      [
        OptEnum.new('KerberosTicketTrace', [false, 'Kerberos ticket trace mode for converted ticket output', 'off', %w[off metadata ticket full]])
      ]
    )
  end

  def run
    input_path = datastore['InputPath']
    output_path = File.expand_path(datastore['OutputPath'])
    unless File.file?(input_path.to_s) && File.readable?(input_path.to_s)
      fail_with(Msf::Module::Failure::BadConfig, "Input ticket file does not exist or is not readable: #{input_path}")
    end

    header = File.binread(input_path, 2)
    if ccache?(header)
      print_status('Converting from ccache to kirbi')
      ccache = Rex::Proto::Kerberos::CredentialCache::Krb5Ccache.read(File.binread(input_path))
      output = Msf::Exploit::Remote::Kerberos::TicketConverter.ccache_to_kirbi(ccache)
      trace_converted_ticket(ccache, source: "ccache File:#{input_path}")
    elsif kirbi?(header)
      print_status('Converting from kirbi to ccache')
      output = kirbi_to_ccache(File.binread(input_path))
      trace_converted_ticket(output, source: "Kirbi File:#{input_path}")
    else
      fail_with(Msf::Module::Failure::BadConfig, 'Unknown file format')
    end
    File.binwrite(output_path, output.encode)
    print_status("File written to #{output_path}")
  end

  def ccache_to_kirbi(input)
    ccache = Rex::Proto::Kerberos::CredentialCache::Krb5Ccache.read(input)
    Msf::Exploit::Remote::Kerberos::TicketConverter.ccache_to_kirbi(ccache)
  end

  def kirbi_to_ccache(input)
    krb_cred = Rex::Proto::Kerberos::Model::KrbCred.decode(input)
    Msf::Exploit::Remote::Kerberos::TicketConverter.kirbi_to_ccache(krb_cred)
  end

  private

  def kirbi?(header)
    header[0] == "\x76"
  end

  def ccache?(header)
    header[0..1] == "\x05\x04"
  end

  def trace_converted_ticket(ccache, source:)
    trace_mode = datastore['KerberosTicketTrace'].to_s.downcase
    return if trace_mode.empty? || trace_mode == 'off'

    unless Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter::TRACE_MODES.include?(trace_mode)
      trace_mode = Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter::TRACE_MODE_FULL
    end

    presenter = Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter.new(ccache)
    print_line presenter.present_trace(source: source, trace_mode: trace_mode)
  end
end
