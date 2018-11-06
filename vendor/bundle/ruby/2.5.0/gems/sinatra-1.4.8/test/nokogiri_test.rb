require File.expand_path('../helper', __FILE__)

begin
require 'nokogiri'

class NokogiriTest < Minitest::Test
  def nokogiri_app(&block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      get('/', &block)
    end
    get '/'
  end

  it 'renders inline Nokogiri strings' do
    nokogiri_app { nokogiri 'xml' }
    assert ok?
    assert_body %(<?xml version="1.0"?>\n)
  end

  it 'renders inline blocks' do
    nokogiri_app do
      @name = "Frank & Mary"
      nokogiri { |xml| xml.couple @name }
    end
    assert ok?
    assert_body %(<?xml version="1.0"?>\n<couple>Frank &amp; Mary</couple>\n)
  end

  it 'renders .nokogiri files in views path' do
    nokogiri_app do
      @name = "Blue"
      nokogiri :hello
    end
    assert ok?
    assert_body "<?xml version=\"1.0\"?>\n<exclaim>You're my boy, Blue!</exclaim>\n"
  end

  it "renders with inline layouts" do
    next if Tilt::VERSION <= "1.1"
    mock_app do
      layout { %(xml.layout { xml << yield }) }
      get('/') { nokogiri %(xml.em 'Hello World') }
    end
    get '/'
    assert ok?
    assert_body %(<?xml version="1.0"?>\n<layout>\n  <em>Hello World</em>\n</layout>\n)
  end

  it "renders with file layouts" do
    next if Tilt::VERSION <= "1.1"
    nokogiri_app {
      nokogiri %(xml.em 'Hello World'), :layout => :layout2
    }
    assert ok?
    assert_body %(<?xml version="1.0"?>\n<layout>\n  <em>Hello World</em>\n</layout>\n)
  end

  it "raises error if template not found" do
    mock_app { get('/') { nokogiri :no_such_template } }
    assert_raises(Errno::ENOENT) { get('/') }
  end
end

rescue LoadError
  warn "#{$!.to_s}: skipping nokogiri tests"
end
