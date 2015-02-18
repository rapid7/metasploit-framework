# -*- coding:binary -*-
require 'spec_helper'
require 'rex/proto/smb/server'

describe Rex::Proto::SMB::Server do

  class << self

    # Set a standard excuse that indicates that the method
    # under test needs to be first examined to figure out
    # what's sane and what's not.
    def excuse_lazy(test_method=nil)
      ret = "need to determine pass/fail criteria"
      test_method ? ret << " for #{test_method.inspect}" : ret
    end

    # Complain about not having a "real" connection (can be mocked)
    def excuse_needs_connection
      "need to actually set up an SMB server to test"
    end

  end

  let(:unc) { '\\\\127.0.0.1\\share\\test.dll' }
  let(:file_name) { 'test.dll' }
  let(:contents) { 'test' }
  let(:share) { 'share' }
  let(:listen_port) { '445' }
  let(:listen_host) { "127.0.0.1" }
  subject(:server) do
    Rex::Proto::SMB::Server.new(listen_port, listen_host)
  end
  subject(:this_cli) do
    Rex::Proto::SMB::SimpleClient.new("127.0.0.1")
  end

  it "should respond to initialize" do
    server.should be
  end

  it "should have a set of default instance variables" do
    server.instance_variable_get(:@listen_host).should == listen_host 
    server.instance_variable_get(:@listen_port).should == listen_port 
    server.instance_variable_get(:@context).should == {}
  end

  it "should produce a connection" do
    this_cli.should be_a_kind_of Rex::Proto::SMB::SimpleClient
  end

  it "should attempt to connect to a server" do
    expect { this_cli.connect(1) }
  end

  it "should send a request and receive a response", :pending => excuse_needs_connection do

  end

  it "should send a request", :pending => excuse_needs_connection do

  end

  it "should get a response", :pending => excuse_needs_connection do

  end

  it "should end a connection with a stop" do
    server.stop.should be_nil
  end

  it "should test if a connection is valid" do
    server.conn?.should be_false
  end

  it "should respond to its various accessors" do
    server.should respond_to :listen_port
    server.should respond_to :listen_host
    server.should respond_to :process_id
    server.should respond_to :name
    server.should respond_to :ip
    server.should respond_to :port
    server.should respond_to :data
    server.should respond_to :context
    # These are supposed to be protected
    server.should respond_to :hi
    server.should respond_to :lo
  end

end
