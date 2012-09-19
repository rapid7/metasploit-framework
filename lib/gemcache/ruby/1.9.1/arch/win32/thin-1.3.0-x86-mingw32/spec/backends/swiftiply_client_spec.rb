require File.dirname(__FILE__) + '/../spec_helper'

describe Backends::SwiftiplyClient do
  before do
    @backend = Backends::SwiftiplyClient.new('0.0.0.0', 3333)
    @backend.server = mock('server', :null_object => true)
  end
  
  it "should connect" do
    EventMachine.run do
      @backend.connect
      EventMachine.stop
    end
  end
  
  it "should disconnect" do
    EventMachine.run do
      @backend.connect
      @backend.disconnect
      EventMachine.stop
    end
  end
end

describe SwiftiplyConnection do
  before do
    @connection = SwiftiplyConnection.new(nil)
    @connection.backend = Backends::SwiftiplyClient.new('0.0.0.0', 3333)
    @connection.backend.server = mock('server', :null_object => true)
  end
  
  it do
    @connection.should be_persistent
  end
  
  it "should send handshake on connection_completed" do
    @connection.should_receive(:send_data).with('swiftclient000000000d0500')
    @connection.connection_completed
  end
  
  it "should reconnect on unbind" do
    @connection.backend.stub!(:running?).and_return(true)
    @connection.stub!(:rand).and_return(0) # Make sure we don't wait
    
    @connection.should_receive(:reconnect).with('0.0.0.0', 3333)
    
    EventMachine.run do
      @connection.unbind
      EventMachine.add_timer(0) { EventMachine.stop }      
    end
  end
  
  it "should not reconnect when not running" do
    @connection.backend.stub!(:running?).and_return(false)
    EventMachine.should_not_receive(:add_timer)
    @connection.unbind
  end
  
  it "should have a host_ip" do
    @connection.send(:host_ip).should == [0, 0, 0, 0]
  end
  
  it "should generate swiftiply_handshake based on key" do
    @connection.send(:swiftiply_handshake, 'key').should == 'swiftclient000000000d0503key'
  end
end