require File.expand_path('../helper', __FILE__)

begin
require 'haml'

class HAMLTest < Minitest::Test
  def haml_app(&block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      get('/', &block)
    end
    get '/'
  end

  it 'renders inline HAML strings' do
    haml_app { haml '%h1 Hiya' }
    assert ok?
    assert_equal "<h1>Hiya</h1>\n", body
  end

  it 'renders .haml files in views path' do
    haml_app { haml :hello }
    assert ok?
    assert_equal "<h1>Hello From Haml</h1>\n", body
  end

  it "renders with inline layouts" do
    mock_app do
      layout { %q(%h1= 'THIS. IS. ' + yield.upcase) }
      get('/') { haml '%em Sparta' }
    end
    get '/'
    assert ok?
    assert_equal "<h1>THIS. IS. <EM>SPARTA</EM></h1>\n", body
  end

  it "renders with file layouts" do
    haml_app { haml 'Hello World', :layout => :layout2 }
    assert ok?
    assert_equal "<h1>HAML Layout!</h1>\n<p>Hello World</p>\n", body
  end

  it "raises error if template not found" do
    mock_app { get('/') { haml :no_such_template } }
    assert_raises(Errno::ENOENT) { get('/') }
  end

  it "passes HAML options to the Haml engine" do
    mock_app {
      get('/') { haml "!!!\n%h1 Hello World", :format => :html5 }
    }
    get '/'
    assert ok?
    assert_equal "<!DOCTYPE html>\n<h1>Hello World</h1>\n", body
  end

  it "passes default HAML options to the Haml engine" do
    mock_app do
      set :haml, {:format => :html5}
      get('/') { haml "!!!\n%h1 Hello World" }
    end
    get '/'
    assert ok?
    assert_equal "<!DOCTYPE html>\n<h1>Hello World</h1>\n", body
  end

  it "merges the default HAML options with the overrides and passes them to the Haml engine" do
    mock_app do
      set :haml, {:format => :html5, :attr_wrapper => '"'} # default HAML attr are <tag attr='single-quoted'>
      get('/') { haml "!!!\n%h1{:class => :header} Hello World" }
      get('/html4') {
        haml "!!!\n%h1{:class => 'header'} Hello World", :format => :html4
      }
    end
    get '/'
    assert ok?
    assert_equal "<!DOCTYPE html>\n<h1 class=\"header\">Hello World</h1>\n", body
    get '/html4'
    assert ok?
    assert_match(/^<!DOCTYPE html PUBLIC (.*) HTML 4.01/, body)
  end

  it "is possible to pass locals" do
    haml_app { haml "= foo", :locals => { :foo => 'bar' }}
    assert_equal "bar\n", body
  end

  it "can render truly nested layouts by accepting a layout and a block with the contents" do
    mock_app do
      template(:main_outer_layout) { "%h1 Title\n= yield" }
      template(:an_inner_layout) { "%h2 Subtitle\n= yield" }
      template(:a_page) { "%p Contents." }
      get('/') do
        haml :main_outer_layout, :layout => false do
          haml :an_inner_layout do
            haml :a_page
          end
        end
      end
    end
    get '/'
    assert ok?
    assert_body "<h1>Title</h1>\n<h2>Subtitle</h2>\n<p>Contents.</p>\n"
  end
end

rescue LoadError
  warn "#{$!.to_s}: skipping haml tests"
end
