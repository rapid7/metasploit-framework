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
        This module can be used to send a specified document and message
        to multiple users with an optional message and can be used for
        ethical phishing campaigns. Please refer to the module documentation
        for info on how to retrieve the bot token and corresponding chat ID
        values.
        },
    'Author' =>
      [
        'Ege Balcı <egebalci[at]pm.me>', # Aka @egeblc of https://pentest.blog
        'Gaurav Purswani' # @pingport80
      ],
    'License' => MSF_LICENSE,
    )

    register_options(
      [
        OptString.new('BOT_TOKEN', [true, 'Telegram BOT token', '']),
        OptString.new('MESSAGE', [false, 'Optional message sent with the document']),
        OptInt.new('CHAT_ID', [false, 'Chat ID for the BOT', '']),
        OptPath.new('DOCUMENT', [false, 'The path to the document(binary, video etc)']),
        OptPath.new('IDFILE', [false, 'File containing chat IDs, one per line'])
      ], self.class
    )
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
    return unless document

    raw_params = { 'chat_id' => chat_id, 'document' => Faraday::UploadIO.new(document, 'application/octet-stream') }
    parms = {}
    raw_params.each_with_object({}) do |(key, value), _params|
      parms[key] = value
    end
    print_warning("Sending to #{chat_id.strip}")
    response = conn.post("/bot#{bot_token}/sendDocument", parms)
    if response.status == 200
      print_good('Document sent successfully!')
    elsif response.status == 403
      print_bad("Error while sending document! Make sure the user with chat_id : #{chat_id} is active on bot.")
    else
      print_bad('Error while sending the document!')
    end
  end

  def send_message(conn, chat_id)
    return if message == ''

    parms = { 'chat_id' => chat_id, 'text' => message }
    response = conn.post("/bot#{bot_token}/sendMessage", parms)
    if response.status == 200
      print_good('Message sent successfully')
    elsif response.status == 403
      print_bad("Error while sending messsage. Make sure the user with chat_id : #{chat_id} is active on bot")
    else
      print_bad('Error while sending the message.')
    end
  end

  def run
    url = 'https://api.telegram.org'
    conn = Faraday.new(url: url) do |faraday|
      faraday.request :multipart
      faraday.request :url_encoded
      faraday.adapter Faraday.default_adapter
    end

    if id_file
      File.readlines(id_file).each do |chat_id|
        send_document(conn, chat_id)
        send_message(conn, chat_id)
      end
      return
    end
    send_document(conn, datastore['CHAT_ID'])
    send_message(conn, datastore['CHAT_ID'])
  end

end
