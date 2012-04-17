require File.dirname(__FILE__) + '/../spec_helper'
require 'ostruct'
include Controllers

describe Controller, 'start' do
  before do
    @controller = Controller.new(:address              => '0.0.0.0',
                                 :port                 => 3000,
                                 :pid                  => 'thin.pid',
                                 :log                  => 'thin.log',
                                 :timeout              => 60,
                                 :max_conns            => 2000,
                                 :max_persistent_conns => 1000,
                                 :adapter              => 'rails')
    
    @server = OpenStruct.new
    @adapter = OpenStruct.new
    
    Server.should_receive(:new).with('0.0.0.0', 3000, @controller.options).and_return(@server)
    @server.should_receive(:config)
    Rack::Adapter::Rails.stub!(:new).and_return(@adapter)
  end
  
  it "should configure server" do
    @controller.start
    
    @server.app.should == @adapter
    @server.pid_file.should == 'thin.pid'
    @server.log_file.should == 'thin.log'
    @server.maximum_connections.should == 2000
    @server.maximum_persistent_connections.should == 1000
  end
  
  it "should start as daemon" do
    @controller.options[:daemonize] = true
    @controller.options[:user] = true
    @controller.options[:group] = true
    
    @server.should_receive(:daemonize)
    @server.should_receive(:change_privilege)

    @controller.start
  end
  
  it "should configure Rails adapter" do
    Rack::Adapter::Rails.should_receive(:new).with(@controller.options.merge(:root => nil))
    
    @controller.start
  end
  
  it "should mount app under :prefix" do
    @controller.options[:prefix] = '/app'
    @controller.start
    
    @server.app.class.should == Rack::URLMap
  end

  it "should mount Stats adapter under :stats" do
    @controller.options[:stats] = '/stats'
    @controller.start
    
    @server.app.class.should == Stats::Adapter
  end
  
  it "should load app from Rack config" do
    @controller.options[:rackup] = File.dirname(__FILE__) + '/../../example/config.ru'
    @controller.start
    
    @server.app.class.should == Proc
  end

  it "should load app from ruby file" do
    @controller.options[:rackup] = File.dirname(__FILE__) + '/../../example/myapp.rb'
    @controller.start
    
    @server.app.should == Myapp
  end

  it "should throwup if rackup is not a .ru or .rb file" do
    proc do
      @controller.options[:rackup] = File.dirname(__FILE__) + '/../../example/myapp.foo'
      @controller.start
    end.should raise_error(RuntimeError, /please/)
  end
  
  it "should set server as threaded" do
    @controller.options[:threaded] = true
    @controller.start
    
    @server.threaded.should be_true
  end
  
  it "should set RACK_ENV" do
    @controller.options[:rackup] = File.dirname(__FILE__) + '/../../example/config.ru'
    @controller.options[:environment] = "lolcat"
    @controller.start
    
    ENV['RACK_ENV'].should == "lolcat"
  end
    
end

describe Controller do
  before do
    @controller = Controller.new(:pid => 'thin.pid', :timeout => 10)
    @controller.stub!(:wait_for_file)
  end
  
  it "should stop" do
    Server.should_receive(:kill).with('thin.pid', 10)
    @controller.stop
  end
  
  it "should restart" do
    Server.should_receive(:restart).with('thin.pid')
    @controller.restart
  end
  
  it "should write configuration file" do
    silence_stream(STDOUT) do
      Controller.new(:config => 'test.yml', :port => 5000, :address => '127.0.0.1').config
    end

    File.read('test.yml').should include('port: 5000', 'address: 127.0.0.1')
    File.read('test.yml').should_not include('config: ')

    File.delete('test.yml')
  end
end