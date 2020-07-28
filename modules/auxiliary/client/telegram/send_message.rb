##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'

class MetasploitModule < Msf::Auxiliary
    def initialize
        super(
        'Name' => 'Telegram Message Client',
        'Description' => %q{
            This module will send a Telegram message to given chat ID with the 
            given bot token. To get the value for BOT_TOKEN, got to https://t.me/botfather 
            and send the message '/newbot' to him, then follow the prompts and respond with 
            the bot name and its user name. You should then get a congratulations message 
            with the bot's API key, which you will need for this module.

            To get the CHAT_ID value, send a message to the bot username that you created 
            earlier. Then browse to https://api.telegram.org/bot<BOT_TOKEN VALUE>/getUpdates
            and look for a line like "chat":"id":1344308063. That ID is what you will 
            want to use the value of CHAT_ID; in this case it would be 1344308063.
        },
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
        params = { :chat_id => datastore['CHAT_ID'], :parse_mode => formatting, :text => message }
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
