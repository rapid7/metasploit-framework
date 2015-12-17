##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  def initialize(info = {})
    super(update_info(info,
                      'Name'         => 'Enumerate Active Directory Trusts From Current Domain',
                      'Description'  => %q(
                        This module will enumerate AD trusts from the current domain, including decoding
                        of the remote SIDs. This could be particularly useful when creating golden tickets
                        with a SID history, or just to immediately map the available trusts.
                                            ),
                      'License'      => MSF_LICENSE,
                      'Platform'     => ['win'],
                      'SessionTypes' => ['meterpreter'],
                      'Author'       => ['Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>']
                     ))

    register_options([
      OptInt.new('MAX_SEARCH', [true, 'Maximum number of trusts.', '100'])
    ], self.class)
  end

  def run
    ldap_fields = ['flatname', 'cn', 'securityIdentifier', 'trustAttributes', 'trustDirection', 'trustType', 'distinguishedName']
    ldap_names = ['Name', 'Domain', 'SID', 'Attributes', 'Direction', 'Trust Type', 'DN']
    search_filter = '(objectClass=trustedDomain)'
    max_search = datastore['MAX_SEARCH']

    begin
      trust_results = query(search_filter, max_search, ldap_fields)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      print_error(e.message)
      return
    end

    if trust_results.nil? || trust_results[:results].empty?
      print_error('No trusts found')
      return
    end

    num = trust_results[:results].size

    # Draw the results table with the
    results_table = Rex::Ui::Text::Table.new(
      'Header'     => "#{num} Domain Trust(s)", 
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => ldap_names
    )

    trust_results[:results].each do |result|
      row = []

      # Go through each of the fields translating each one if necessary
      result.each_with_index do |field, index|
        if field.nil?
          field_value = ''
          next
        end

        if index == 3 # trustAttributes
          field_value = translate_trust_attributes(field[:value])
        elsif index == 4 # trustDirection
          field_value = translate_trust_direction(field[:value])
        elsif index == 5 # trustType
          field_value = translate_trust_type(field[:value])
        elsif index == 2 # SID
          field_value = sid_hex_to_string(field[:value])
        else # Just add the raw data
          field_value = field[:value].to_s
        end

        row << field_value
      end

      # Add the row to the results table
      results_table << row
    end

    # Draw the whole table
    print_line results_table.to_s
  end

  # Translate the trustAttributes parameter
  # https://msdn.microsoft.com/en-us/library/cc223779.aspx
  def translate_trust_attributes(val_original)
    val = val_original.to_i
    result = []
    result << 'Non Transitive' if val & 0x00000001
    result << 'Uplevel Only' if val & 0x00000002
    result << 'Quarantined' if val & 0x00000004
    result << 'Transitive' if val & 0x00000008
    result << 'Cross Organisation' if val & 0x00000010
    result << 'Within Forest' if val & 0x00000020
    result << 'Treat As External' if val & 0x00000040
    result << 'Uses RC4 Encryption' if val & 0x00000080
    result << 'No TGT Delegation' if val & 0x00000200
    result << 'PIM Trust' if val & 0x00000400
    return '' unless result.nil?
    result.join(',')
  end

  # Translate the trustDirection parameter
  # https://msdn.microsoft.com/en-us/library/cc223768.aspx
  def translate_trust_direction(val)
    result = ''
    result = 'Disabled' if val == 0x00000000
    result = 'Inbound' if val == 0x00000001
    result = 'Outbound' if val == 0x00000002
    result = 'Bidirectional' if val == 0x00000003
    result
  end

  # Translate the trustType parameter
  # https://msdn.microsoft.com/en-us/library/cc223771.aspx
  def translate_trust_type(val)
    result = ''
    result = 'Downlevel (No AD)' if val == 0x00000001
    result = 'Uplevel (AD)' if val == 0x00000002
    result = 'MIT (Not Windows)' if val == 0x00000003
    result = 'DCE (Historic)' if val == 0x00000004
    result
  end

  # Convert the SID from Hex to printable string.
  # https://msdn.microsoft.com/en-us/library/cc223778.aspx
  #  Byte [1]: SID structure revision (always 1, but it could change in the future).
  #  Byte [2]: The number of sub-authorities in the SID. (i.e. the number of blocks from byte 10 onwards)
  #  Bytes [3-9]: Identifier Authority - convert to hex as the second number group.
  #  The rest: A variable length list of unsigned 32bit integers, the number of which is defined in byte 2.
  #  i.e. S-[1]-[3-9]-[10+] < the number of '10+' groups is defined by [2]
  def sid_hex_to_string(data)
    sid = []
    sid << data[0].to_s
    rid = ''
    (6).downto(1) do |i|
      rid += byte2hex(data[i, 1][0])
    end
    sid << rid.to_i.to_s
    sid += data.unpack("bbbbbbbbV*")[8..-1]
    "S-" + sid.join('-')
 end

  def byte2hex(b)
    ret = '%x' % (b.to_i & 0xff)
    ret = '0' + ret if ret.length < 2
    ret
  end
end
