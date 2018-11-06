require File.expand_path('../helper', __FILE__)

begin
require 'yajl'

class YajlTest < Minitest::Test
  def yajl_app(&block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      get('/', &block)
    end
    get '/'
  end

  it 'renders inline Yajl strings' do
    yajl_app { yajl('json = { :foo => "bar" }') }
    assert ok?
    assert_body '{"foo":"bar"}'
  end

  it 'renders .yajl files in views path' do
    yajl_app { yajl(:hello) }
    assert ok?
    assert_body '{"yajl":"hello"}'
  end

  it 'raises error if template not found' do
    mock_app { get('/') { yajl(:no_such_template) } }
    assert_raises(Errno::ENOENT) { get('/') }
  end

  it 'accepts a :locals option' do
    yajl_app do
      locals = { :object => { :foo => 'bar' } }
      yajl 'json = object', :locals => locals
    end
    assert ok?
    assert_body '{"foo":"bar"}'
  end

  it 'accepts a :scope option' do
    yajl_app do
      scope = { :object => { :foo => 'bar' } }
      yajl 'json = self[:object]', :scope => scope
    end
    assert ok?
    assert_body '{"foo":"bar"}'
  end

  it 'decorates the json with a callback' do
    yajl_app do
      yajl(
        'json = { :foo => "bar" }',
        { :callback => 'baz' }
      )
    end
    assert ok?
    assert_body 'baz({"foo":"bar"});'
  end

  it 'decorates the json with a variable' do
    yajl_app do
      yajl(
        'json = { :foo => "bar" }',
        { :variable => 'qux' }
      )
    end
    assert ok?
    assert_body 'var qux = {"foo":"bar"};'
  end

  it 'decorates the json with a callback and a variable' do
    yajl_app do
      yajl(
        'json = { :foo => "bar" }',
        { :callback => 'baz', :variable => 'qux' }
      )
    end
    assert ok?
    assert_body 'var qux = {"foo":"bar"}; baz(qux);'
  end
end

rescue LoadError
  warn "#{$!.to_s}: skipping yajl tests"
end
