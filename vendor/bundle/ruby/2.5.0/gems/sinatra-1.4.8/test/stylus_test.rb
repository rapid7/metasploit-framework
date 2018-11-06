require File.expand_path('../helper', __FILE__)

begin
  require 'stylus'
  require 'stylus/tilt'

  begin
    Stylus.compile '1'
  rescue RuntimeError
    raise LoadError, 'unable to find Stylus compiler'
  end

  class StylusTest < Minitest::Test
    def stylus_app(options = {}, &block)
      mock_app do
        set :views, File.dirname(__FILE__) + '/views'
        set(options)
        get('/', &block)
      end
      get '/'
    end

    it 'renders inline Stylus strings' do
      stylus_app { stylus "a\n margin auto\n" }
      assert ok?
      assert body.include?("a {\n  margin: auto;\n}\n")
    end

    it 'defaults content type to css' do
      stylus_app { stylus :hello }
      assert ok?
      assert_equal "text/css;charset=utf-8", response['Content-Type']
    end

    it 'defaults allows setting content type per route' do
      stylus_app do
        content_type :html
        stylus :hello
      end
      assert ok?
      assert_equal "text/html;charset=utf-8", response['Content-Type']
    end

    it 'defaults allows setting content type globally' do
      stylus_app(:styl => { :content_type => 'html' }) do
        stylus :hello
      end
      assert ok?
      assert_equal "text/html;charset=utf-8", response['Content-Type']
    end

    it 'renders .styl files in views path' do
      stylus_app { stylus :hello }
      assert ok?
      assert_include body, "a {\n  margin: auto;\n}\n"
    end

    it 'ignores the layout option' do
      stylus_app { stylus :hello, :layout => :layout2 }
      assert ok?
      assert_include body, "a {\n  margin: auto;\n}\n"
    end

    it "raises error if template not found" do
      mock_app {
        get('/') { stylus :no_such_template }
      }
      assert_raises(Errno::ENOENT) { get('/') }
    end

    it "passes stylus options to the stylus engine" do
      stylus_app { stylus :hello, :no_wrap => true }
      assert ok?
      assert_body "a {\n  margin: auto;\n}\n"
    end

    it "passes default stylus options to the stylus engine" do
      mock_app do
        set :stylus, :no_wrap => true # default stylus style is :nested
        get('/') { stylus :hello }
      end
      get '/'
      assert ok?
      assert_body "a {\n  margin: auto;\n}\n"
    end
  end

rescue LoadError
  warn "#{$!.to_s}: skipping stylus tests"
end
