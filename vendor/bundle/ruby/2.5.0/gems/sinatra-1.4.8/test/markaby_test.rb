require File.expand_path('../helper', __FILE__)

begin
require 'markaby'

class MarkabyTest < Minitest::Test
  def markaby_app(&block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      get('/', &block)
    end
    get '/'
  end

  it 'renders inline markaby strings' do
    markaby_app { markaby 'h1 "Hiya"' }
    assert ok?
    assert_equal "<h1>Hiya</h1>", body
  end

  it 'renders .markaby files in views path' do
    markaby_app { markaby :hello }
    assert ok?
    assert_equal "<h1>Hello From Markaby</h1>", body
  end

  it "renders with inline layouts" do
    mock_app do
      layout { 'h1 { text "THIS. IS. "; yield }' }
      get('/') { markaby 'em "SPARTA"' }
    end
    get '/'
    assert ok?
    assert_equal "<h1>THIS. IS. <em>SPARTA</em></h1>", body
  end

  it "renders with file layouts" do
    markaby_app { markaby 'text "Hello World"', :layout => :layout2 }
    assert ok?
    assert_equal "<h1>Markaby Layout!</h1><p>Hello World</p>", body
  end

  it 'renders inline markaby blocks' do
    markaby_app { markaby { h1 'Hiya' } }
    assert ok?
    assert_equal "<h1>Hiya</h1>", body
  end

  it 'renders inline markaby blocks with inline layouts' do
    markaby_app do
      settings.layout { 'h1 { text "THIS. IS. "; yield }' }
      markaby { em 'SPARTA' }
    end
    assert ok?
    assert_equal "<h1>THIS. IS. <em>SPARTA</em></h1>", body
  end

  it 'renders inline markaby blocks with file layouts' do
    markaby_app { markaby(:layout => :layout2) { text "Hello World" } }
    assert ok?
    assert_equal "<h1>Markaby Layout!</h1><p>Hello World</p>", body
  end

  it "raises error if template not found" do
    mock_app { get('/') { markaby :no_such_template } }
    assert_raises(Errno::ENOENT) { get('/') }
  end

  it "allows passing locals" do
    markaby_app {
      markaby 'text value', :locals => { :value => 'foo' }
    }
    assert ok?
    assert_equal 'foo', body
  end
end

rescue LoadError
  warn "#{$!.to_s}: skipping markaby tests"
end
