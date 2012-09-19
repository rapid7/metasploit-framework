# encoding: utf-8
module Net
  class SMTP
    # This is a backport of r30294 from ruby trunk because of a bug in net/smtp.
    # http://svn.ruby-lang.org/cgi-bin/viewvc.cgi?view=rev&amp;revision=30294
    #
    # Fixed in what will be Ruby 1.9.3 - tlsconnect also does not exist in some early versions of ruby
    remove_method :tlsconnect if defined?(Net::SMTP.new.tlsconnect)

    def tlsconnect(s)
      verified = false
      s = OpenSSL::SSL::SSLSocket.new s, @ssl_context
      logging "TLS connection started"
      s.sync_close = true
      s.connect
      if @ssl_context.verify_mode != OpenSSL::SSL::VERIFY_NONE
        s.post_connection_check(@address)
      end
      verified = true
      s
    ensure
      s.close unless verified
    end
  end
end
