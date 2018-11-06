require 'em_test_helper'

class TestStomp < Test::Unit::TestCase
  CONTENT_LENGTH_REGEX = /^content-length: (\d+)$/

  def bytesize(str)
    str = str.to_s
    size = str.bytesize if str.respond_to?(:bytesize) # bytesize added in 1.9
    size || str.size
  end

  class TStomp
    include EM::P::Stomp

    def last_sent_content_length
      @sent && Integer(@sent[CONTENT_LENGTH_REGEX, 1])
    end

    def send_data(string)
      @sent = string
    end
  end

  def test_content_length_in_bytes
    connection = TStomp.new

    queue = "queue"
    failure_message = "header content-length is not the byte size of last sent body"

    body = "test"
    connection.send queue, body
    assert_equal bytesize(body), connection.last_sent_content_length, failure_message

    body = "test\u221A"
    connection.send queue, body
    assert_equal bytesize(body), connection.last_sent_content_length, failure_message
  end
end
