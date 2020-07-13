# Content: Metasploit Module to send telegram message
# Author: Ege Balcı| @egeblc | https://pentest.blog
# Date: 07/2020

require 'uri'

class MetasploitModule < Msf::Auxiliary
    def initialize
        super(
        'Name' => 'Telegram Message Client',
        'Description' => 'This Module will send a telegram message to given chat ID with given bot token',
        'Author' => 'Ege Balcı <egebalci@pm.me>',
        'License' => MSF_LICENSE,
        )

        register_options(
            [
                OptString.new('BOT_TOKEN', [true, 'Telegram BOT token', '']),
                OptInt.new('CHAT_ID', [true, 'Chat ID for the BOT', '']),
                OptString.new('MSG', [true, 'Message content', 'New session opened !']),
                OptString.new('FORMATTING', [false, 'Set message formating option (Markdown|MarkdownV2|HTML)', 'Markdown']),
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
        unless formatting == 'Markdown' || formatting == 'MarkdownV2' || formatting == 'HTML'
            raise 'Invalid formatting selected'
        end

        uri = URI("https://api.telegram.org/bot#{bot_token}/sendMessage")
        params = { :chat_id => datastore['CHAT_ID'], :parse_mode => formatting, :text => message }
        uri.query = URI.encode_www_form(params)
        res = Net::HTTP.get_response(uri)

        if res.is_a?(Net::HTTPSuccess)
            print_good('Message sent')
        else
            print_error('Unable to send the message')
            print_error("API Status: #{res.code}")
        end
    end
end
