require File.expand_path('../helper', __FILE__)

begin
require 'sass'

class ScssTest < Minitest::Test
  def scss_app(options = {}, &block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      set options
      get('/', &block)
    end
    get '/'
  end

  it 'renders inline Scss strings' do
    scss_app { scss "#scss {\n  background-color: white; }\n" }
    assert ok?
    assert_equal "#scss {\n  background-color: white; }\n", body
  end

  it 'defaults content type to css' do
    scss_app { scss "#scss {\n  background-color: white; }\n" }
    assert ok?
    assert_equal "text/css;charset=utf-8", response['Content-Type']
  end

  it 'defaults allows setting content type per route' do
    scss_app do
      content_type :html
      scss "#scss {\n  background-color: white; }\n"
    end
    assert ok?
    assert_equal "text/html;charset=utf-8", response['Content-Type']
  end

  it 'defaults allows setting content type globally' do
    scss_app(:scss => { :content_type => 'html' }) {
      scss "#scss {\n  background-color: white; }\n"
    }
    assert ok?
    assert_equal "text/html;charset=utf-8", response['Content-Type']
  end

  it 'renders .scss files in views path' do
    scss_app { scss :hello }
    assert ok?
    assert_equal "#scss {\n  background-color: white; }\n", body
  end

  it 'ignores the layout option' do
    scss_app { scss :hello, :layout => :layout2 }
    assert ok?
    assert_equal "#scss {\n  background-color: white; }\n", body
  end

  it "raises error if template not found" do
    mock_app { get('/') { scss(:no_such_template) } }
    assert_raises(Errno::ENOENT) { get('/') }
  end

  it "passes scss options to the scss engine" do
    scss_app do
      scss(
        "#scss {\n  background-color: white;\n  color: black\n}",
        :style => :compact
      )
    end
    assert ok?
    assert_equal "#scss { background-color: white; color: black; }\n", body
  end

  it "passes default scss options to the scss engine" do
    mock_app do
      set :scss, {:style => :compact} # default scss style is :nested
      get('/') {
        scss("#scss {\n  background-color: white;\n  color: black;\n}")
      }
    end
    get '/'
    assert ok?
    assert_equal "#scss { background-color: white; color: black; }\n", body
  end
end

rescue LoadError
  warn "#{$!.to_s}: skipping scss tests"
end
