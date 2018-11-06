require File.expand_path('../helper', __FILE__)

begin
require 'creole'

class CreoleTest < Minitest::Test
  def creole_app(&block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      get('/', &block)
    end
    get '/'
  end

  it 'renders inline creole strings' do
    creole_app { creole '= Hiya' }
    assert ok?
    assert_body "<h1>Hiya</h1>"
  end

  it 'renders .creole files in views path' do
    creole_app { creole :hello }
    assert ok?
    assert_body "<h1>Hello From Creole</h1>"
  end

  it "raises error if template not found" do
    mock_app { get('/') { creole :no_such_template } }
    assert_raises(Errno::ENOENT) { get('/') }
  end

  it "renders with inline layouts" do
    mock_app do
      layout { 'THIS. IS. #{yield.upcase}!' }
      get('/') { creole 'Sparta', :layout_engine => :str }
    end
    get '/'
    assert ok?
    assert_like 'THIS. IS. <P>SPARTA</P>!', body
  end

  it "renders with file layouts" do
    creole_app do
      creole 'Hello World', :layout => :layout2, :layout_engine => :erb
    end
    assert ok?
    assert_body "ERB Layout!\n<p>Hello World</p>"
  end

  it "can be used in a nested fashion for partials and whatnot" do
    mock_app do
      template(:inner) { "hi" }
      template(:outer) { "<outer><%= creole :inner %></outer>" }
      get('/') { erb :outer }
    end

    get '/'
    assert ok?
    assert_like '<outer><p>hi</p></outer>', body
  end
end

rescue LoadError
  warn "#{$!.to_s}: skipping creole tests"
end
