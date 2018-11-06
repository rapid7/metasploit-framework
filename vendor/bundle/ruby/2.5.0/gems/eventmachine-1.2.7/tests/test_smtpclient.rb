require 'em_test_helper'

class TestSmtpClient < Test::Unit::TestCase

  Localhost = "127.0.0.1"
  Localport = 9801

  def setup
  end

  def teardown
  end

  def test_a
    # No real tests until we have a server implementation to test against.
    # This is what the call looks like, though:
    err = nil
    EM.run {
      d = EM::Protocols::SmtpClient.send :domain=>"example.com",
      :host=>Localhost,
      :port=>Localport, # optional, defaults 25
      :starttls=>true,
      :from=>"sender@example.com",
      :to=> ["to_1@example.com", "to_2@example.com"],
      :header=> {"Subject" => "This is a subject line"},
      :body=> "This is the body of the email",
      :verbose=>true
      d.errback {|e|
        err = e
        EM.stop
      }
    }
    assert(err)
  end

  def test_content
    err = nil
    EM.run {
      d = EM::Protocols::SmtpClient.send :domain=>"example.com",
      :host=>Localhost,
      :port=>Localport, # optional, defaults 25
      :starttls=>true,
      :from=>"sender@example.com",
      :to=> ["to_1@example.com", "to_2@example.com"],
      :content => ["Subject: xxx\r\n\r\ndata\r\n.\r\n"],
      :verbose=>true
      d.errback {|e|
        err = e
        EM.stop
      }
    }
    assert(err)
  end


  EM::Protocols::SmtpClient.__send__(:public, :escape_leading_dots)

  def test_escaping
    smtp = EM::Protocols::SmtpClient.new :domain => "example.com"

    expectations = {
      "Hello\r\n" => "Hello\r\n",
      "\r\n.whatever\r\n" => "\r\n..whatever\r\n",
      "\r\n.\r\n" => "\r\n..\r\n",
      "\r\n.\r\n." => "\r\n..\r\n..",
      ".\r\n.\r\n" => "..\r\n..\r\n",
      "..\r\n" => "...\r\n"
    }

    expectations.each do |input, output|
      assert_equal output, smtp.escape_leading_dots(input)
    end
  end

end
