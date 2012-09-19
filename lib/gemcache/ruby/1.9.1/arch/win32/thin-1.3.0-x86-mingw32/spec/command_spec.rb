require File.dirname(__FILE__) + '/spec_helper'

describe Command do
  before do
    Command.script = 'thin'
    @command = Command.new(:start, :port => 3000, :daemonize => true, :log => 'hi.log',
                           :require => %w(rubygems thin), :no_epoll => true)
  end
  
  it 'should shellify command' do
    out = @command.shellify
    out.should include('--port=3000', '--daemonize', '--log="hi.log"', 'thin start --')
    out.should_not include('--pid')
  end
  
  it 'should shellify Array argument to multiple parameters' do
    out = @command.shellify
    out.should include('--require="rubygems"', '--require="thin"')
  end

  it 'should convert _ to - in option name' do
    out = @command.shellify
    out.should include('--no-epoll')
  end
end