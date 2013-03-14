require File.dirname(__FILE__) + '/../spec_helper'

describe Server, 'app builder' do
  it "should build app from constructor" do
    app = proc {}
    server = Server.new('0.0.0.0', 3000, app)
    
    server.app.should == app
  end
  
  it "should build app from builder block" do
    server = Server.new '0.0.0.0', 3000 do
      run(proc { |env| :works })
    end
    
    server.app.call({}).should == :works
  end
  
  it "should use middlewares in builder block" do
    server = Server.new '0.0.0.0', 3000 do
      use Rack::ShowExceptions
      run(proc { |env| :works })
    end
    
    server.app.class.should == Rack::ShowExceptions
    server.app.call({}).should == :works
  end
  
  it "should work with Rack url mapper" do
    server = Server.new '0.0.0.0', 3000 do
      map '/test' do
        run(proc { |env| [200, {}, 'Found /test'] })
      end
    end
    
    default_env = { 'SCRIPT_NAME' => '' }
    
    server.app.call(default_env.update('PATH_INFO' => '/'))[0].should == 404
    
    status, headers, body = server.app.call(default_env.update('PATH_INFO' => '/test'))
    status.should == 200
    body.should == 'Found /test'
  end
end
