require File.expand_path('../helper', __FILE__)

class ERBTest < Minitest::Test
  def engine
    Tilt::ERBTemplate
  end

  def setup
    Tilt.prefer engine, :erb
    super
  end

  def erb_app(&block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      get('/', &block)
    end
    get '/'
  end

  it 'uses the correct engine' do
    assert_equal engine, Tilt[:erb]
  end

  it 'renders inline ERB strings' do
    erb_app { erb '<%= 1 + 1 %>' }
    assert ok?
    assert_equal '2', body
  end

  it 'renders .erb files in views path' do
    erb_app { erb :hello }
    assert ok?
    assert_equal "Hello World\n", body
  end

  it 'takes a :locals option' do
    erb_app do
      locals = {:foo => 'Bar'}
      erb '<%= foo %>', :locals => locals
    end
    assert ok?
    assert_equal 'Bar', body
  end

  it "renders with inline layouts" do
    mock_app do
      layout { 'THIS. IS. <%= yield.upcase %>!' }
      get('/') { erb 'Sparta' }
    end
    get '/'
    assert ok?
    assert_equal 'THIS. IS. SPARTA!', body
  end

  it "renders with file layouts" do
    erb_app { erb 'Hello World', :layout => :layout2 }
    assert ok?
    assert_body "ERB Layout!\nHello World"
  end

  it "renders erb with blocks" do
    mock_app do
      def container
        @_out_buf << "THIS."
        yield
        @_out_buf << "SPARTA!"
      end
      def is; "IS." end
      get('/') { erb '<% container do %> <%= is %> <% end %>' }
    end
    get '/'
    assert ok?
    assert_equal 'THIS. IS. SPARTA!', body
  end

  it "can be used in a nested fashion for partials and whatnot" do
    mock_app do
      template(:inner) { "<inner><%= 'hi' %></inner>" }
      template(:outer) { "<outer><%= erb :inner %></outer>" }
      get('/') { erb :outer }
    end

    get '/'
    assert ok?
    assert_equal '<outer><inner>hi</inner></outer>', body
  end

  it "can render truly nested layouts by accepting a layout and a block with the contents" do
    mock_app do
      template(:main_outer_layout) { "<h1>Title</h1>\n<%= yield %>" }
      template(:an_inner_layout) { "<h2>Subtitle</h2>\n<%= yield %>" }
      template(:a_page) { "<p>Contents.</p>\n" }
      get('/') do
        erb :main_outer_layout, :layout => false do
          erb :an_inner_layout do
            erb :a_page
          end
        end
      end
    end
    get '/'
    assert ok?
    assert_body "<h1>Title</h1>\n<h2>Subtitle</h2>\n<p>Contents.</p>\n"
  end
end


begin
  require 'erubis'
  class ErubisTest < ERBTest
    def engine; Tilt::ErubisTemplate end
  end
rescue LoadError
  warn "#{$!.to_s}: skipping erubis tests"
end
