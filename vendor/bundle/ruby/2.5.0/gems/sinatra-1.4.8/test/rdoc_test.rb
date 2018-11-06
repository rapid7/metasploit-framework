require File.expand_path('../helper', __FILE__)

begin
require 'rdoc'
require 'rdoc/markup/to_html'

class RdocTest < Minitest::Test
  def rdoc_app(&block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      get('/', &block)
    end
    get '/'
  end

  it 'renders inline rdoc strings' do
    rdoc_app { rdoc '= Hiya' }
    assert ok?
    assert_body(/<h1[^>]*>Hiya(<span><a href=\"#label-Hiya\">&para;<\/a> <a href=\"#(documentation|top)\">&uarr;<\/a><\/span>)?<\/h1>/)
  end

  it 'renders .rdoc files in views path' do
    rdoc_app { rdoc :hello }
    assert ok?
    assert_body(/<h1[^>]*>Hello From RDoc(<span><a href=\"#label-Hello\+From\+RDoc\">&para;<\/a> <a href=\"#(documentation|top)\">&uarr;<\/a><\/span>)?<\/h1>/)
  end

  it "raises error if template not found" do
    mock_app { get('/') { rdoc :no_such_template } }
    assert_raises(Errno::ENOENT) { get('/') }
  end

  it "renders with inline layouts" do
    mock_app do
      layout { 'THIS. IS. #{yield.upcase}!' }
      get('/') { rdoc 'Sparta', :layout_engine => :str }
    end
    get '/'
    assert ok?
    assert_like 'THIS. IS. <P>SPARTA</P>!', body
  end

  it "renders with file layouts" do
    rdoc_app {
      rdoc 'Hello World', :layout => :layout2, :layout_engine => :erb
    }
    assert ok?
    assert_body "ERB Layout!\n<p>Hello World</p>"
  end

  it "can be used in a nested fashion for partials and whatnot" do
    mock_app do
      template(:inner) { "hi" }
      template(:outer) { "<outer><%= rdoc :inner %></outer>" }
      get('/') { erb :outer }
    end

    get '/'
    assert ok?
    assert_like '<outer><p>hi</p></outer>', body
  end
end

rescue LoadError
  warn "#{$!.to_s}: skipping rdoc tests"
end
