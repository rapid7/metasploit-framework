require File.expand_path('../helper', __FILE__)

begin
require 'rabl'
require 'ostruct'
require 'json'
require 'active_support/core_ext/hash/conversions'

class RablTest < Minitest::Test
  def rabl_app(&block)
    mock_app {
      set :views, File.dirname(__FILE__) + '/views'
      get '/', &block
    }
    get '/'
  end

  it 'renders inline rabl strings' do
    rabl_app do
      @foo = OpenStruct.new(:baz => 'w00t')
      rabl %q{
        object @foo
        attributes :baz
      }
    end
    assert ok?
    assert_equal '{"openstruct":{"baz":"w00t"}}', body
  end
  it 'renders .rabl files in views path' do
    rabl_app do
      @foo = OpenStruct.new(:bar => 'baz')
      rabl :hello
    end
    assert ok?
    assert_equal '{"openstruct":{"bar":"baz"}}', body
  end

  it "renders with file layouts" do
    rabl_app {
      @foo = OpenStruct.new(:bar => 'baz')
      rabl :hello, :layout => :layout2
    }
    assert ok?
    assert_equal '{"qux":{"openstruct":{"bar":"baz"}}}', body
  end

  it "raises error if template not found" do
    mock_app {
      get('/') { rabl :no_such_template }
    }
    assert_raises(Errno::ENOENT) { get('/') }
  end

  it "passes rabl options to the rabl engine" do
    mock_app do
      get('/') do
        @foo = OpenStruct.new(:bar => 'baz')
        rabl %q{
          object @foo
          attributes :bar
        }, :format => 'xml'
      end
    end
    get '/'
    assert ok?
    assert_body '<?xml version="1.0" encoding="UTF-8"?><openstruct><bar>baz</bar></openstruct>'
  end

  it "passes default rabl options to the rabl engine" do
    mock_app do
      set :rabl, :format => 'xml'
      get('/') do
        @foo = OpenStruct.new(:bar => 'baz')
        rabl %q{
          object @foo
          attributes :bar
        }
      end
    end
    get '/'
    assert ok?
    assert_body '<?xml version="1.0" encoding="UTF-8"?><openstruct><bar>baz</bar></openstruct>'
  end

end

rescue LoadError
  warn "#{$!.to_s}: skipping rabl tests"
end
