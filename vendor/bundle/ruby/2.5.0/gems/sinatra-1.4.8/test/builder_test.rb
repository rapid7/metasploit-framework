require File.expand_path('../helper', __FILE__)

begin
require 'builder'

class BuilderTest < Minitest::Test
  def builder_app(options = {}, &block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      set options
      get('/', &block)
    end
    get '/'
  end

  it 'renders inline Builder strings' do
    builder_app { builder 'xml.instruct!' }
    assert ok?
    assert_equal %{<?xml version="1.0" encoding="UTF-8"?>\n}, body
  end

  it 'defaults content type to xml' do
    builder_app { builder 'xml.instruct!' }
    assert ok?
    assert_equal "application/xml;charset=utf-8", response['Content-Type']
  end

  it 'defaults allows setting content type per route' do
    builder_app do
      content_type :html
      builder 'xml.instruct!'
    end
    assert ok?
    assert_equal "text/html;charset=utf-8", response['Content-Type']
  end

  it 'defaults allows setting content type globally' do
    builder_app(:builder => { :content_type => 'html' }) do
      builder 'xml.instruct!'
    end
    assert ok?
    assert_equal "text/html;charset=utf-8", response['Content-Type']
  end

  it 'renders inline blocks' do
    builder_app do
      @name = "Frank & Mary"
      builder { |xml| xml.couple @name }
    end
    assert ok?
    assert_equal "<couple>Frank &amp; Mary</couple>\n", body
  end

  it 'renders .builder files in views path' do
    builder_app do
      @name = "Blue"
      builder :hello
    end
    assert ok?
    assert_equal %(<exclaim>You're my boy, Blue!</exclaim>\n), body
  end

  it "renders with inline layouts" do
    mock_app do
      layout { %(xml.layout { xml << yield }) }
      get('/') { builder %(xml.em 'Hello World') }
    end
    get '/'
    assert ok?
    assert_equal "<layout>\n<em>Hello World</em>\n</layout>\n", body
  end

  it "renders with file layouts" do
    builder_app do
      builder %(xml.em 'Hello World'), :layout => :layout2
    end
    assert ok?
    assert_equal "<layout>\n<em>Hello World</em>\n</layout>\n", body
  end

  it "raises error if template not found" do
    mock_app do
      get('/') { builder :no_such_template }
    end
    assert_raises(Errno::ENOENT) { get('/') }
  end
end

rescue LoadError
  warn "#{$!.to_s}: skipping builder tests"
end
