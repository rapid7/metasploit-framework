# $Id: imap.rb,v 1.1 2006/10/05 01:36:52 koheik Exp $

require "net/imap"
$:.unshift(File.dirname(__FILE__) + '/../lib')
require "net/ntlm"

Net::IMAP::debug = true

$host = "localhost"
$port = 143
$ssl = false
$user = nil
$passwd = nil

module Net
  class IMAP
    class NtlmAuthenticator
      def process(data)
        case @state
        when 1
          @state = 2
          t1 = Net::NTLM::Message::Type1.new()
          return t1.serialize
        when 2
          @state = 3
          t2 = Net::NTLM::Message.parse(data)
          t3 = t2.response({:user => @user, :password => @password}, {:ntlmv2 => (@ntlm_type == "ntlmv2")})
          return t3.serialize
        end
      end

      private

      def initialize(user, password, ntlm_type = "ntlmv2")
        @user = user
        @password = password
        @ntlm_type = @ntlm_type
        @state = 1
      end
    end
    add_authenticator "NTLM", NtlmAuthenticator

    class ResponseParser
      def continue_req
        match(T_PLUS)
        if lookahead.symbol == T_CRLF # means empty message
          return ContinuationRequest.new(ResponseText.new(nil, ""), @str)
        end
        match(T_SPACE)
        return ContinuationRequest.new(resp_text, @str)
      end
    end
  end
end

unless $user and $passwd
  print "User name: "
  ($user = $stdin.readline).chomp!
  print "Password: "
  ($passwd = $stdin.readline).chomp!
end

imap = Net::IMAP.new($host, $port, $ssl)
imap.authenticate("NTLM", $user, $passwd)
imap.examine("Inbox")
# imap.search(["RECENT"]).each do |message_id|
# envelope = imap.fetch(message_id, "ENVELOPE")[0].attr["ENVELOPE"]
# from = envelope.from.nil? ? "" : envelope.from[0].name
# subject = envelope.subject
# puts "#{message_id} #{from}: \t#{subject}"
# end
imap.logout
# imap.disconnect
