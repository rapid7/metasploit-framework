##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'

class MetasploitModule < Msf::Auxiliary
  def initialize
    super(
    'Name' => 'Telegram Message Client',
    'Description' => %q(
            This module will send a Telegram message to given chat ID with the
            given bot token. Please refer to the module documentation for info
            on how to retrieve the bot token and corresponding chat ID values.
        ),
    'Author' => 'Ege Balcı <egebalci[at]pm.me>', # Aka @egeblc of https://pentest.blog
    'License' => MSF_LICENSE,
    )

    register_options(
      [
        OptString.new('BOT_TOKEN', [true, 'Telegram BOT token', '']),
        OptInt.new('CHAT_ID', [true, 'Chat ID for the BOT', '']),
        OptString.new('MSG', [true, 'Message content', 'New session opened!']),
        OptEnum.new('FORMATTING', [true, 'Message formating option (Markdown|MarkdownV2|HTML)', 'Markdown', [ 'Markdown', 'MarkdownV2', 'HTML']]),
      ], self.class
    )
  end

  def message
    datastore['MSG']
  end

  def formatting
    datastore['FORMATTING']
  end

  def bot_token
    datastore['BOT_TOKEN']
  end

  def run
    uri = URI("https://api.telegram.org/bot#{bot_token}/sendMessage")
    params = { chat_id: datastore['CHAT_ID'], parse_mode: formatting, text: message }
    uri.query = URI.encode_www_form(params)
    res = Net::HTTP.get_response(uri)

    if res.is_a?(Net::HTTPSuccess)
      print_good('Message sent!')
    else
      print_error('Unable to send the message!')
      print_error("API Status: #{res.code}")
    end
  end
end
