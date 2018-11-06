require File.expand_path('../helper', __FILE__)

begin
require 'coffee-script'
require 'execjs'

begin
  ExecJS.compile '1'
rescue Exception
  raise LoadError, 'unable to execute JavaScript'
end

class CoffeeTest < Minitest::Test
  def coffee_app(options = {}, &block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      set(options)
      get('/', &block)
    end
    get '/'
  end

  it 'renders inline Coffee strings' do
    coffee_app { coffee "alert 'Aye!'\n" }
    assert ok?
    assert body.include?("alert('Aye!');")
  end

  it 'defaults content type to javascript' do
    coffee_app { coffee "alert 'Aye!'\n" }
    assert ok?
    assert_equal "application/javascript;charset=utf-8", response['Content-Type']
  end

  it 'defaults allows setting content type per route' do
    coffee_app do
      content_type :html
      coffee "alert 'Aye!'\n"
    end
    assert ok?
    assert_equal "text/html;charset=utf-8", response['Content-Type']
  end

  it 'defaults allows setting content type globally' do
    coffee_app(:coffee => { :content_type => 'html' }) do
      coffee "alert 'Aye!'\n"
    end
    assert ok?
    assert_equal "text/html;charset=utf-8", response['Content-Type']
  end

  it 'renders .coffee files in views path' do
    coffee_app { coffee :hello }
    assert ok?
    assert_include body, "alert(\"Aye!\");"
  end

  it 'ignores the layout option' do
    coffee_app { coffee :hello, :layout => :layout2 }
    assert ok?
    assert_include body, "alert(\"Aye!\");"
  end

  it "raises error if template not found" do
    mock_app {
      get('/') { coffee :no_such_template }
    }
    assert_raises(Errno::ENOENT) { get('/') }
  end

  it "passes coffee options to the coffee engine" do
    coffee_app { coffee "alert 'Aye!'\n", :no_wrap => true }
    assert ok?
    assert_body "alert('Aye!');"
  end

  it "passes default coffee options to the coffee engine" do
    mock_app do
      set :coffee, :no_wrap => true # default coffee style is :nested
      get('/') { coffee "alert 'Aye!'\n" }
    end
    get '/'
    assert ok?
    assert_body "alert('Aye!');"
  end
end

rescue LoadError
  warn "#{$!.to_s}: skipping coffee tests"
rescue
  if $!.class.name == 'ExecJS::RuntimeUnavailable'
    warn "#{$!.to_s}: skipping coffee tests"
  else
    raise
  end
end
