require File.expand_path('../helper', __FILE__)

begin
require 'radius'

class RadiusTest < Minitest::Test
  def radius_app(&block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      get('/', &block)
    end
    get '/'
  end

  it 'renders inline radius strings' do
    radius_app { radius '<h1>Hiya</h1>' }
    assert ok?
    assert_equal "<h1>Hiya</h1>", body
  end

  it 'renders .radius files in views path' do
    radius_app { radius :hello }
    assert ok?
    assert_equal "<h1>Hello From Radius</h1>\n", body
  end

  it "renders with inline layouts" do
    mock_app do
      layout { "<h1>THIS. IS. <r:yield /></h1>" }
      get('/') { radius '<EM>SPARTA</EM>' }
    end
    get '/'
    assert ok?
    assert_equal "<h1>THIS. IS. <EM>SPARTA</EM></h1>", body
  end

  it "renders with file layouts" do
    radius_app { radius 'Hello World', :layout => :layout2 }
    assert ok?
    assert_equal "<h1>Radius Layout!</h1>\n<p>Hello World</p>\n", body
  end

  it "raises error if template not found" do
    mock_app { get('/') { radius :no_such_template } }
    assert_raises(Errno::ENOENT) { get('/') }
  end

  it "allows passing locals" do
    radius_app {
      radius '<r:value />', :locals => { :value => 'foo' }
    }
    assert ok?
    assert_equal 'foo', body
  end
end

rescue LoadError
  warn "#{$!.to_s}: skipping radius tests"
end
