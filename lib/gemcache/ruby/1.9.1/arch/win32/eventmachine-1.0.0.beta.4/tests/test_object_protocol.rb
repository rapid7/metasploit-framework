require 'em_test_helper'

class TestObjectProtocol < Test::Unit::TestCase
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

  def setup
    @port = next_port
  end

  def test_send_receive
    EM.run{
      EM.start_server "127.0.0.1", @port, Server
      EM.connect "127.0.0.1", @port, Client
    }

    assert($client == {:hello=>'world'})
    assert($server == {'you_said'=>{:hello=>'world'}})
  end
end
