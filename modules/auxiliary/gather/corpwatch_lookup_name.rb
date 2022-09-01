##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'CorpWatch Company Name Information Search',
      'Description'    => %q{
          This module interfaces with the CorpWatch API to get publicly available
        info for a given company name.  Please note that by using CorpWatch API, you
        acknowledge the limitations of the data CorpWatch provides, and should always
        verify the information with the official SEC filings before taking any action.
      },
      'Author'         => [ 'Brandon Perry <bperry.volatile[at]gmail.com>' ],
      'References'     =>
        [
          [ 'URL', 'http://api.corpwatch.org/' ]
        ]
    ))

    deregister_http_client_options

    register_options(
      [
        OptString.new('COMPANY_NAME', [ true, "Search for companies with this name", ""]),
        OptInt.new('YEAR', [ false, "Year to look up", Time.now.year-1]),
        OptString.new('LIMIT', [ true, "Limit the number of results returned", "5"]),
        OptString.new('CORPWATCH_APIKEY', [ false, "Use this API key when getting the data", ""]),
      ])
  end

  def rhost_corpwatch
    'api.corpwatch.org'
  end

  def rport_corpwatch
    80
  end

  def run

    uri = "/"
    uri << (datastore['YEAR'].to_s + "/") if datastore['YEAR'].to_s != ""
    uri << "companies.xml"

    res = send_request_cgi(
    {
      'rhost'    => rhost_corpwatch,
      'rport'    => rport_corpwatch,
      'uri'      => uri,
      'method'   => 'GET',
      'vars_get' =>
      {
        'company_name' => datastore['COMPANY_NAME'],
        'limit'        => datastore['LIMIT'],
        'key'          => datastore['CORPWATCH_APIKEY']
      }
    }, 25)

    if not res
      print_error("Server down, bad response")
      return
    end

    begin
      doc = REXML::Document.new(res.body)
    rescue
      print_error("Body not well formed XML")
      return
    end

    root = doc.root

    if not root
      print_error("document root nil")
      return
    end

    elements = root.get_elements("result")

    if not elements
      print_error("Document root has no results")
      return
    end

    results = elements[0]

    if not results
      print_error("No results returned, try another search")
      return
    end

    elements = results.get_elements("companies")

    if elements.blank?
      print_error("No companies returned")
      return
    end

    results = elements[0]

    return if not results.elements || results.elements.length == 0

    results.elements.each { |e|
      cwid = grab_text(e, "cw_id")
      company_name = grab_text(e, "company_name")
      address = grab_text(e, "raw_address")
      sector = grab_text(e, "sector_name")
      industry = grab_text(e, "industry_name")

      print_status("Company Information\n---------------------------------")
      print_status("CorpWatch (cw) ID): " + cwid)
      print_status("Company Name: " + company_name)
      print_status("Address: " + address)
      print_status("Sector: " + sector)
      print_status("Industry: " + industry)
    }
  end

  def grab_text(e, name)
    (e.get_elements(name) && e.get_elements(name)[0] &&
    e.get_elements(name)[0].get_text ) ?
    e.get_elements(name)[0].get_text.to_s  : ""
  end
end
