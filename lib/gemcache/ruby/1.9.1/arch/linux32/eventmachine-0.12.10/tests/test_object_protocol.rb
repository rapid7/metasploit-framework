$:.unshift "../lib"
require 'eventmachine'
require 'test/unit'

class TestObjectProtocol < Test::Unit::TestCase
  Host = "127.0.0.1"
  Port = 9550

  module Server
    include EM::P::ObjectProtocol
    def post_init
      send_object :hello=>'world'
    end
    def receive_object obj
      $server = obj
      EM.stop
    end
  end

  module Client
    include EM::P::ObjectProtocol
    def receive_object obj
      $client = obj
      send_object 'you_said'=>obj
    end
  end

  def test_send_receive
    EM.run{
      EM.start_server Host, Port, Server
      EM.connect Host, Port, Client
    }

    assert($client == {:hello=>'world'})
    assert($server == {'you_said'=>{:hello=>'world'}})
  end
end