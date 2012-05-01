require File.dirname(__FILE__) + '/../spec_helper'
include Controllers

describe Service do
  before(:all) do
    silence_stream(STDERR) do
      Service::INITD_PATH          = 'tmp/sandbox' + Service::INITD_PATH
      Service::DEFAULT_CONFIG_PATH = 'tmp/sandbox' + Service::DEFAULT_CONFIG_PATH
    end
  end
  
  before do
    Thin.stub!(:linux?).and_return(true)
    FileUtils.mkdir_p 'tmp/sandbox'
        
    @service = Service.new(:all => 'spec/configs')
  end
  
  it "should call command for each config file" do
    Command.should_receive(:run).with(:start, :config => 'spec/configs/cluster.yml', :daemonize => true)
    Command.should_receive(:run).with(:start, :config => 'spec/configs/single.yml', :daemonize => true)
    
    @service.start
  end
  
  it "should create /etc/init.d/thin file when calling install" do
    @service.install
    
    File.exist?(Service::INITD_PATH).should be_true
    File.read(Service::INITD_PATH).should include('CONFIG_PATH=tmp/sandbox/etc/thin',
                                                  'SCRIPT_NAME=tmp/sandbox/etc/init.d/thin',
                                                  'DAEMON=' + Command.script)
  end
  
  it "should create /etc/thin dir when calling install" do
    @service.install
    
    File.directory?(Service::DEFAULT_CONFIG_PATH).should be_true
  end
  
  it "should include specified path in /etc/init.d/thin script" do
    @service.install('tmp/sandbox/usr/thin')
    
    File.read(Service::INITD_PATH).should include('CONFIG_PATH=tmp/sandbox/usr/thin')
  end
  
  after do
    FileUtils.rm_rf 'tmp/sandbox'
  end
end