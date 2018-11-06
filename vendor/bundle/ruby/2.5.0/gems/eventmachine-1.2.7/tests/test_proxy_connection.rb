require 'em_test_helper'

class TestProxyConnection < Test::Unit::TestCase

  if EM.respond_to?(:start_proxy)
    module ProxyConnection
      def initialize(client, request)
        @client, @request = client, request
      end

      def post_init
        EM::enable_proxy(self, @client)
      end

      def connection_completed
        EM.next_tick {
          send_data @request
        }
      end

      def proxy_target_unbound
        $unbound_early = true
        EM.stop
      end

      def unbind
        $proxied_bytes = self.get_proxied_bytes
        @client.close_connection_after_writing
      end
    end

    module PartialProxyConnection
      def initialize(client, request, length)
        @client, @request, @length = client, request, length
      end

      def post_init
        EM::enable_proxy(self, @client, 0, @length)
      end

      def receive_data(data)
        $unproxied_data = data
        @client.send_data(data)
      end

      def connection_completed
        EM.next_tick {
          send_data @request
        }
      end

      def proxy_target_unbound
        $unbound_early = true
        EM.stop
      end

      def proxy_completed
        $proxy_completed = true
      end

      def unbind
        @client.close_connection_after_writing
      end
    end

    module Client
      def connection_completed
        send_data "EM rocks!"
      end

      def receive_data(data)
        $client_data = data
      end

      def unbind
        EM.stop
      end
    end

    module Client2
      include Client
      def unbind; end
    end

    module Server
      def receive_data(data)
        send_data "I know!" if data == "EM rocks!"
        close_connection_after_writing
      end
    end

    module ProxyServer
      def initialize port
        @port = port
      end

      def receive_data(data)
        @proxy = EM.connect("127.0.0.1", @port, ProxyConnection, self, data)
      end
    end

    module PartialProxyServer
      def initialize port
        @port = port
      end

      def receive_data(data)
        EM.connect("127.0.0.1", @port, PartialProxyConnection, self, data, 1)
      end
    end

    module EarlyClosingProxy
      def initialize port
        @port = port
      end

      def receive_data(data)
        EM.connect("127.0.0.1", @port, ProxyConnection, self, data)
        close_connection
      end
    end

    def setup
      @port = next_port
      @proxy_port = next_port
    end

    def test_proxy_connection
      EM.run {
        EM.start_server("127.0.0.1", @port, Server)
        EM.start_server("127.0.0.1", @proxy_port, ProxyServer, @port)
        EM.connect("127.0.0.1", @proxy_port, Client)
      }

      assert_equal("I know!", $client_data)
    end

    def test_proxied_bytes
      EM.run {
        EM.start_server("127.0.0.1", @port, Server)
        EM.start_server("127.0.0.1", @proxy_port, ProxyServer, @port)
        EM.connect("127.0.0.1", @proxy_port, Client)
      }

      assert_equal("I know!", $client_data)
      assert_equal("I know!".bytesize, $proxied_bytes)
    end

    def test_partial_proxy_connection
      EM.run {
        EM.start_server("127.0.0.1", @port, Server)
        EM.start_server("127.0.0.1", @proxy_port, PartialProxyServer, @port)
        EM.connect("127.0.0.1", @proxy_port, Client)
      }

      assert_equal("I know!", $client_data)
      assert_equal(" know!", $unproxied_data)
      assert($proxy_completed)
    end

    def test_early_close
      $client_data = nil
      EM.run {
        EM.start_server("127.0.0.1", @port, Server)
        EM.start_server("127.0.0.1", @proxy_port, EarlyClosingProxy, @port)
        EM.connect("127.0.0.1", @proxy_port, Client2)
      }

      assert($unbound_early)
    end
  else
    warn "EM.start_proxy not implemented, skipping tests in #{__FILE__}"

    # Because some rubies will complain if a TestCase class has no tests
    def test_em_start_proxy_not_implemented
      assert !EM.respond_to?(:start_proxy)
    end
  end

end
