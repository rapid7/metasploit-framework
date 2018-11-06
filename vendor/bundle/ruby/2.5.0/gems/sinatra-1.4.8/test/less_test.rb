require File.expand_path('../helper', __FILE__)

begin
require 'less'

class LessTest < Minitest::Test
  def less_app(options = {}, &block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      set options
      get('/', &block)
    end
    get '/'
  end

  it 'renders inline Less strings' do
    less_app {
      less "@white_color: #fff; #main { background-color: @white_color }"
    }
    assert ok?
    assert_equal "#main{background-color:#ffffff;}", body.gsub(/\s/, "")
  end

  it 'defaults content type to css' do
    less_app {
      less "@white_color: #fff; #main { background-color: @white_color }"
    }
    assert ok?
    assert_equal "text/css;charset=utf-8", response['Content-Type']
  end

  it 'defaults allows setting content type per route' do
    less_app do
      content_type :html
      less "@white_color: #fff; #main { background-color: @white_color }"
    end
    assert ok?
    assert_equal "text/html;charset=utf-8", response['Content-Type']
  end

  it 'defaults allows setting content type globally' do
    less_app(:less => { :content_type => 'html' }) do
      less "@white_color: #fff; #main { background-color: @white_color }"
    end
    assert ok?
    assert_equal "text/html;charset=utf-8", response['Content-Type']
  end

  it 'renders .less files in views path' do
    less_app { less :hello }
    assert ok?
    assert_equal "#main{background-color:#ffffff;}", body.gsub(/\s/, "")
  end

  it 'ignores the layout option' do
    less_app { less :hello, :layout => :layout2 }
    assert ok?
    assert_equal "#main{background-color:#ffffff;}", body.gsub(/\s/, "")
  end

  it "raises error if template not found" do
    mock_app { get('/') { less :no_such_template } }
    assert_raises(Errno::ENOENT) { get('/') }
  end
end

rescue LoadError
  warn "#{$!.to_s}: skipping less tests"
end
