require File.expand_path('../helper', __FILE__)

begin
require 'wlang'

class WLangTest < Minitest::Test
  def engine
    Tilt::WLangTemplate
  end

  def wlang_app(&block)
    mock_app {
      set :views, File.dirname(__FILE__) + '/views'
      get '/', &block
    }
    get '/'
  end

  it 'uses the correct engine' do
    assert_equal engine, Tilt[:wlang]
  end

  it 'renders .wlang files in views path' do
    wlang_app { wlang :hello }
    assert ok?
    assert_equal "Hello from wlang!\n", body
  end

  it 'renders in the app instance scope' do
    mock_app do
      helpers do
        def who; "world"; end
      end
      get('/') { wlang 'Hello +{who}!' }
    end
    get '/'
    assert ok?
    assert_equal 'Hello world!', body
  end

  it 'takes a :locals option' do
    wlang_app do
      locals = {:foo => 'Bar'}
      wlang 'Hello ${foo}!', :locals => locals
    end
    assert ok?
    assert_equal 'Hello Bar!', body
  end

  it "renders with inline layouts" do
    mock_app do
      layout { 'THIS. IS. +{yield.upcase}!' }
      get('/') { wlang 'Sparta' }
    end
    get '/'
    assert ok?
    assert_equal 'THIS. IS. SPARTA!', body
  end

  it "renders with file layouts" do
    wlang_app { wlang 'Hello World', :layout => :layout2 }
    assert ok?
    assert_body "WLang Layout!\nHello World"
  end

  it "can rendered truly nested layouts by accepting a layout and a block with the contents" do
    mock_app do
      template(:main_outer_layout) { "<h1>Title</h1>\n>{ yield }" }
      template(:an_inner_layout) { "<h2>Subtitle</h2>\n>{ yield }" }
      template(:a_page) { "<p>Contents.</p>\n" }
      get('/') do
        wlang :main_outer_layout, :layout => false do
          wlang :an_inner_layout do
            wlang :a_page
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
  warn "#{$!.to_s}: skipping wlang tests"
end
