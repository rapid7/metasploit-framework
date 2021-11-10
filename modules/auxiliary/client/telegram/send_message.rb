##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'faraday'

class MetasploitModule < Msf::Auxiliary
  def initialize
    super(
    'Name' => 'Telegram Message Client',
    'Description' => %q{
        This module can be used to send a document and/or message to
        multiple chats on telegram. Please refer to the module
        documentation for info on how to retrieve the bot token and corresponding chat
        ID values.
        },
    'Author' => [
      'Ege Balcı <egebalci[at]pm.me>', # Aka @egeblc of https://pentest.blog
      'Gaurav Purswani' # @pingport80
    ],
    'License' => MSF_LICENSE,
    )

    register_options(
      [
        OptString.new('BOT_TOKEN', [true, 'Telegram BOT token', '']),
        OptString.new('MESSAGE', [false, 'The message to be sent']),
        OptInt.new('CHAT_ID', [false, 'Chat ID for the BOT', '']),
        OptPath.new('DOCUMENT', [false, 'The path to the document(binary, video etc)']),
        OptPath.new('IDFILE', [false, 'File containing chat IDs, one per line']),
        OptEnum.new('FORMATTING', [false, 'Message formating option (Markdown|MarkdownV2|HTML)', 'Markdown', [ 'Markdown', 'MarkdownV2', 'HTML']])
      ], self.class
    )
  end

  def formatting
    datastore['FORMATTING']
  end

  def message
    datastore['MESSAGE']
  end

  def document
    datastore['DOCUMENT']
  end

  def bot_token
    datastore['BOT_TOKEN']
  end

  def id_file
    datastore['IDFILE']
  end

  def send_document(conn, chat_id)
    unless ::File.file?(document) && ::File.readable?(document)
      fail_with(Failure::BadConfig, 'The document to be sent does not exist or is not a readable file!')
    end
    raw_params = { 'chat_id' => chat_id, 'document' => Faraday::UploadIO.new(document, 'application/octet-stream') }
    params = {}
    raw_params.each_with_object({}) do |(key, value), _tmp_params|
      params[key] = value
    end
    response = conn.post("/bot#{bot_token}/sendDocument", params)
    if response.status == 200
      print_good("Document sent successfully to #{chat_id}")
    elsif response.status == 403
      print_bad("Error while sending document! Make sure you have access to message chat_id : #{chat_id}")
    else
      print_bad("Error while sending the document to #{chat_id} API Status : #{response.status}")
    end
  end

  def send_message(conn, chat_id)
    params = { 'chat_id' => chat_id, 'text' => message, 'parse_mode' => formatting }
    response = conn.post("/bot#{bot_token}/sendMessage", params)
    if response.status == 200
      print_good("Message sent successfully to #{chat_id}")
    elsif response.status == 403
      print_bad("Error while sending document! Make sure you have access to message chat_id : #{chat_id}")
    else
      print_bad("Error while sending the message to chat_id #{chat_id} API Status : #{response.status}")
    end
  end

  def run
    unless document || message
      fail_with(Failure::BadConfig, 'You must supply a message and/or document')
    end
    url = 'https://api.telegram.org'
    conn = Faraday.new(url: url) do |faraday|
      faraday.request :multipart
      faraday.request :url_encoded
      faraday.adapter Faraday.default_adapter
    end

    if id_file
      print_warning("Opening `#{id_file}` to fetch chat IDs...")
      unless ::File.file?(id_file) && ::File.readable?(id_file)
        fail_with(Failure::BadConfig, 'The ID file is not an existing readable file!')
      end
      File.readlines(id_file).each do |chat_id|
        send_document(conn, chat_id) if document
        send_message(conn, chat_id) if message
      end
      return
    end
    send_document(conn, datastore['CHAT_ID']) if document
    send_message(conn, datastore['CHAT_ID']) if message
  end

end
