$:.unshift(File.dirname(__FILE__))

require 'spec_helper'
require 'mqtt'
require 'fake_server'

describe "a client talking to a server" do

  before(:each) do
    @error_log = StringIO.new
    @server = MQTT::FakeServer.new
    @server.just_one_connection = true
    @server.respond_to_pings = true
    @server.logger = Logger.new(@error_log)
    @server.logger.level = Logger::WARN
    @server.start

    @client = MQTT::Client.new(@server.address, @server.port)
  end

  after(:each) do
    @client.disconnect
    @server.stop
  end

  context "connecting and publishing a packet" do
    def connect_and_publish(options = {})
      @client.connect

      retain = options.fetch(:retain) { false }
      qos = options.fetch(:qos) { 0 }

      @client.publish('test', 'foobar', retain, qos)
      @client.disconnect
      @server.thread.join(1)
    end

    it "the server should have received a packet" do
      connect_and_publish
      expect(@server.last_publish).not_to be_nil
    end

    it "the server should have received the correct topic" do
      connect_and_publish
      expect(@server.last_publish.topic).to eq('test')
    end

    it "the server should have received the correct payload" do
      connect_and_publish
      expect(@server.last_publish.payload).to eq('foobar')
    end

    it "the server should not report any errors" do
      connect_and_publish
      expect(@error_log.string).to be_empty
    end

    context "with qos > 0" do
      it "the server should have received a packet without timeout" do
        connect_and_publish(:qos => 1)
        expect(@server.last_publish).not_to be_nil
      end
    end
  end

  context "connecting, subscribing to a topic and getting a message" do
    def connect_and_subscribe
      @client.connect
      @client.subscribe('test')
      @topic, @message = @client.get
      @client.disconnect
    end

    it "the client should have received the right topic name" do
      connect_and_subscribe
      expect(@topic).to eq('test')
    end

    it "the client should have received the right message" do
      connect_and_subscribe
      expect(@message).to eq('hello test')
    end

    it "the server should not report any errors" do
      connect_and_subscribe
      expect(@error_log.string).to be_empty
    end
  end

  context "connecting, subscribing to a topic and getting a packet" do
    def connect_and_subscribe
      @client.connect
      @client.subscribe('test', 'foobar')
      @packet = @client.get_packet
      @client.disconnect
    end

    it "the client should have received a packet" do
      connect_and_subscribe
      expect(@packet).not_to be_nil
    end

    it "the client should have received the correct topic" do
      connect_and_subscribe
      expect(@packet.topic).to eq('test')
    end

    it "the client should have received the correct payload" do
      connect_and_subscribe
      expect(@packet.payload).to eq('hello test')
    end

    it "the client should have received a retained packet" do
      connect_and_subscribe
      expect(@packet.retain).to be_truthy
    end

    it "the server should not report any errors" do
      connect_and_subscribe
      expect(@error_log.string).to be_empty
    end
  end

  context "sends pings when idle" do
    def connect_and_ping(keep_alive)
      @client.keep_alive = keep_alive
      @client.connect
      @server.thread.join(2)
      @client.disconnect
    end

    context "when keep-alive=1" do
      it "the server should have received at least one ping" do
        connect_and_ping(1)
        expect(@server.pings_received).to be >= 1
      end

      it "the server should not report any errors" do
        connect_and_ping(1)
        expect(@error_log.string).to be_empty
      end
    end

    context "when keep-alive=0" do
      it "the server should not receive any pings" do
        connect_and_ping(0)
        expect(@server.pings_received).to eq(0)
      end

      it "the server should not report any errors" do
        connect_and_ping(0)
        expect(@error_log.string).to be_empty
      end
    end
  end

  context "detects server not sending ping responses" do
    def connect_and_timeout(keep_alive)
      @server.respond_to_pings = false
      @client.keep_alive = keep_alive
      @client.connect
      sleep(keep_alive * 3)
    end

    context "when keep-alive=1" do
      it "the server should have received at least one ping" do
        expect {
          connect_and_timeout(1)
        }.to raise_error(
          MQTT::ProtocolException,
          'No Ping Response received for 2 seconds'
        )
      end
    end
  end

end
