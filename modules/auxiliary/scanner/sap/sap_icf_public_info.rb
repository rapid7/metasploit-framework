##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
# Framework web site for more information on licensing and terms of use.
##

##
# This module is based on, inspired by, or is a port of a plugin available in
# the Onapsis Bizploit Opensource ERP Penetration Testing framework -
# http://www.onapsis.com/research-free-solutions.php.
# Mariano Nunez (the author of the Bizploit framework) helped me in my efforts
# in producing the Metasploit modules and was happy to share his knowledge and
# experience - a very cool guy. I'd also like to thank Chris John Riley,
# Ian de Villiers and Joris van de Vis who have Beta tested the modules and
# provided excellent feedback. Some people just seem to enjoy hacking SAP :)
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'SAP ICF /sap/public/info Service Sensitive Information Gathering',
      'Description' => %q{
        This module uses the /sap/public/info service within SAP Internet Communication
        Framework (ICF) to obtain the operating system version, SAP version, IP address
        and other information.
      },
      'Author' =>
        [
          'Agnivesh Sathasivam', # original sap_soap_rfc_system_info module
          'nmonkee', # original sap_soap_rfc_system_info module
          'ChrisJohnRiley' # repurposed for /sap/public/info (non-RFC)
        ],
      'License' => MSF_LICENSE
      )
    register_options(
      [
        Opt::RPORT(8000),
        OptString.new('TARGETURI', [true, 'Path to SAP Application Server', '/'])
      ], self.class)
  end

  def extract_field(data, elem)
    if data =~ /<#{elem}>([^<]+)<\/#{elem}>/i
      return $1
    end
    nil
  end

  def report_note_sap(type, data, value)
    # create note
    report_note(
      :host => rhost,
      :port => rport,
      :proto => 'tcp',
      :sname => 'sap',
      :type => type,
      :data => data + value
    ) if data
    # update saptbl for output
    @saptbl << [ data, value ]
  end

  def run_host(ip)

    print_status("[SAP] #{ip}:#{rport} - Sending request to SAP Application Server")
    uri = normalize_uri(target_uri.path, '/sap/public/info')
    begin
      res = send_request_cgi({ 'uri' => uri })
      if res and res.code != 200
        print_error("[SAP] #{ip}:#{rport} - Server did not respond as expected")
        return
      elsif not res
        print_error("[SAP] #{ip}:#{rport} - Server did not respond")
        return
      end
    rescue ::Rex::ConnectionError
      print_error("[SAP] #{ip}:#{rport} - Unable to connect")
      return
    end

    print_status("[SAP] #{ip}:#{rport} - Response received")

    # create table for output
    @saptbl = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header' => "[SAP] ICF SAP PUBLIC INFO",
      'Prefix' => "\n",
      'Postfix' => "\n",
      'Indent' => 1,
      'Columns' => [ "Key", "Value" ]
    )

    response = res.body

    # extract data from response body
    rfcproto = extract_field(response, 'rfcproto')
    rfcchartyp = extract_field(response, 'rfcchartyp')
    rfcinttyp = extract_field(response, 'rfcinttyp')
    rfcflotyp = extract_field(response, 'rfcflotyp')
    rfcdest = extract_field(response, 'rfcdest')
    rfchost = extract_field(response, 'rfchost')
    rfcsysid = extract_field(response, 'rfcsysid')
    rfcdbhost = extract_field(response, 'rfcdbhost')
    rfcdbsys = extract_field(response, 'rfcdbsys')
    rfcsaprl = extract_field(response, 'rfcsaprl')
    rfcmach = extract_field(response, 'rfcmach')
    rfcopsys = extract_field(response, 'rfcopsys')
    rfctzone = extract_field(response, 'rfctzone')
    rfcdayst = extract_field(response, 'rfcdayst')
    rfcipaddr = extract_field(response, 'rfcipaddr')
    rfckernrl = extract_field(response, 'rfckernrl')
    rfcipv6addr = extract_field(response, 'rfcipv6addr')

    # report notes / create saptbl output
    report_note_sap('sap.version.release','Release Status of SAP System: ',rfcsaprl) if rfcsaprl
    report_note_sap('sap.version.rfc_log','RFC Log Version: ',rfcproto) if rfcproto
    report_note_sap('sap.version.kernel','Kernel Release: ',rfckernrl) if rfckernrl
    report_note_sap('system.os','Operating System: ',rfcopsys) if rfcopsys
    report_note_sap('sap.db.hostname','Database Host: ',rfcdbhost) if rfcdbhost
    report_note_sap('sap.db_system','Central Database System: ',rfcdbsys) if rfcdbsys
    report_note_sap('system.hostname','Hostname: ',rfchost) if rfchost
    report_note_sap('system.ip.v4','IPv4 Address: ',rfcipaddr) if rfcipaddr
    report_note_sap('system.ip.v6','IPv6 Address: ',rfcipv6addr) if rfcipv6addr
    report_note_sap('sap.instance','System ID: ',rfcsysid) if rfcsysid
    report_note_sap('sap.rfc.destination','RFC Destination: ',rfcdest) if rfcdest
    report_note_sap('system.timezone','Timezone (diff from UTC in seconds): ',rfctzone.gsub(/\s+/, "")) if rfctzone
    report_note_sap('system.charset','Character Set: ',rfcchartyp) if rfcchartyp
    report_note_sap('sap.daylight_saving_time','Daylight Saving Time: ',rfcdayst) if rfcdayst
    report_note_sap('sap.machine_id','Machine ID: ',rfcmach.gsub(/\s+/,"")) if rfcmach

    if rfcinttyp == 'LIT'
      report_note_sap('system.endianness','Integer Format: ', 'Little Endian')
    elsif rfcinttyp
      report_note_sap('system.endianness','Integer Format: ', 'Big Endian')
    end

    if rfcflotyp == 'IE3'
      report_note_sap('system.float_type','Float Type Format: ', 'IEEE')
    elsif rfcflotyp
      report_note_sap('system.float_type','Float Type Format: ', 'IBM/370')
    end

    # output table
    print(@saptbl.to_s)

  end
end
