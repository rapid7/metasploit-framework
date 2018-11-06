require File.expand_path('../helper', __FILE__)

begin
require 'redcloth'

class TextileTest < Minitest::Test
  def textile_app(&block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      get('/', &block)
    end
    get '/'
  end

  it 'renders inline textile strings' do
    textile_app { textile('h1. Hiya') }
    assert ok?
    assert_equal "<h1>Hiya</h1>", body
  end

  it 'renders .textile files in views path' do
    textile_app { textile(:hello) }
    assert ok?
    assert_equal "<h1>Hello From Textile</h1>", body
  end

  it "raises error if template not found" do
    mock_app { get('/') { textile(:no_such_template) } }
    assert_raises(Errno::ENOENT) { get('/') }
  end

  it "renders with inline layouts" do
    mock_app do
      layout { 'THIS. IS. #{yield.upcase}!' }
      get('/') { textile('Sparta', :layout_engine => :str) }
    end
    get '/'
    assert ok?
    assert_like 'THIS. IS. <P>SPARTA</P>!', body
  end

  it "renders with file layouts" do
    textile_app {
      textile('Hello World', :layout => :layout2, :layout_engine => :erb)
    }
    assert ok?
    assert_body "ERB Layout!\n<p>Hello World</p>"
  end

  it "can be used in a nested fashion for partials and whatnot" do
    mock_app do
      template(:inner) { "hi" }
      template(:outer) { "<outer><%= textile :inner %></outer>" }
      get('/') { erb :outer }
    end

    get '/'
    assert ok?
    assert_like '<outer><p>hi</p></outer>', body
  end
end

rescue LoadError
  warn "#{$!.to_s}: skipping textile tests"
end
