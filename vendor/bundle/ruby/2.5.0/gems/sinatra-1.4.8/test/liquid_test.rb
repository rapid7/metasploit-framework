require File.expand_path('../helper', __FILE__)

begin
require 'liquid'

class LiquidTest < Minitest::Test
  def liquid_app(&block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      get('/', &block)
    end
    get '/'
  end

  it 'renders inline liquid strings' do
    liquid_app { liquid '<h1>Hiya</h1>' }
    assert ok?
    assert_equal "<h1>Hiya</h1>", body
  end

  it 'renders .liquid files in views path' do
    liquid_app { liquid :hello }
    assert ok?
    assert_equal "<h1>Hello From Liquid</h1>\n", body
  end

  it "renders with inline layouts" do
    mock_app do
      layout { "<h1>THIS. IS. {{ yield }}</h1>" }
      get('/') { liquid '<EM>SPARTA</EM>' }
    end
    get '/'
    assert ok?
    assert_equal "<h1>THIS. IS. <EM>SPARTA</EM></h1>", body
  end

  it "renders with file layouts" do
    liquid_app { liquid 'Hello World', :layout => :layout2 }
    assert ok?
    assert_equal "<h1>Liquid Layout!</h1>\n<p>Hello World</p>\n", body
  end

  it "raises error if template not found" do
    mock_app { get('/') { liquid :no_such_template } }
    assert_raises(Errno::ENOENT) { get('/') }
  end

  it "allows passing locals" do
    liquid_app {
      liquid '{{ value }}', :locals => { :value => 'foo' }
    }
    assert ok?
    assert_equal 'foo', body
  end

  it "can render truly nested layouts by accepting a layout and a block with the contents" do
    mock_app do
      template(:main_outer_layout) { "<h1>Title</h1>\n{{ yield }}" }
      template(:an_inner_layout) { "<h2>Subtitle</h2>\n{{ yield }}" }
      template(:a_page) { "<p>Contents.</p>\n" }
      get('/') do
        liquid :main_outer_layout, :layout => false do
          liquid :an_inner_layout do
            liquid :a_page
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
  warn "#{$!.to_s}: skipping liquid tests"
end
