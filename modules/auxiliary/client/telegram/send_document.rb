##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'faraday'
require 'uri'

class MetasploitModule < Msf::Auxiliary
  def initialize
    super(
    'Name' => 'Module for sending documents to mass with telegram bot',
    'Description' => %q{
       This module.
        },
    'Author' => 'Gaurav Purswani', # @pingport80
    'License' => MSF_LICENSE,
    )

    register_options(
      [
        OptString.new('BOT_TOKEN', [true, 'Telegram BOT token', '']),
        OptString.new('MESSAGE', [false, 'Optional message sent with the document', '']),
        OptInt.new('CHAT_ID', [true, 'Chat ID for the BOT', '']),
        OptPath.new('DOCUMENT', [true, 'The path to the document(binary, video etc)'	]),
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
    url = 'https://api.telegram.org'
    conn = Faraday.new(url: url) do |faraday|
      faraday.request :multipart
      faraday.request :url_encoded
      faraday.adapter Faraday.default_adapter
    end
    raw_params = { 'chat_id' => chat_id, 'document' => Faraday::UploadIO.new(document, 'application/octet-stream') }
    parms = {}
    raw_params.each_with_object({}) do |(key, value), _params|
      parms[key] = value
    end
    response = conn.post("/bot#{bot_token}/sendDocument", parms)
    if response.status == 200
      print_good('Document sent successfully!')
    else
      print_bad('Error while sending')
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
      end
    else
      send_document(conn, datastore['CHAT_ID'])
    end

    if message
      parms = { 'chat_id' => datastore['CHAT_ID'], 'text' => message }
      conn.post("/bot#{bot_token}/sendMessage", parms)
    end
  end

end
