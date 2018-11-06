require File.expand_path('../helper', __FILE__)

begin
  require 'wikicloth'

  class MediaWikiTest < Minitest::Test
    def mediawiki_app(&block)
      mock_app do
        set :views, File.dirname(__FILE__) + '/views'
        get('/', &block)
      end
      get '/'
    end

    it 'supports both .mw and .mediawiki extensions' do
      assert_equal Tilt[:mw], Tilt[:mediawiki]
    end

    it 'renders inline mediawiki strings' do
      mediawiki_app { mediawiki "''Hiya''" }
      assert ok?
      assert_include body, '<i>Hiya</i>'
    end

    it 'renders .mediawiki files in views path' do
      mediawiki_app { mediawiki :hello }
      assert ok?
      assert_include body, "<i>Hello from MediaWiki</i>"
    end

    it 'raises error if template not found' do
      mock_app { get('/') { mediawiki :no_such_template } }
      assert_raises(Errno::ENOENT) { get('/') }
    end

    it 'renders with inline layouts' do
      mock_app do
        layout { 'THIS. IS. #{yield.upcase}!' }
        get('/') { mediawiki 'Sparta', :layout_engine => :str }
      end
      get '/'
      assert ok?
      assert_like 'THIS. IS. <P>SPARTA</P>!', body
    end

    it 'renders with file layouts' do
      mediawiki_app do
        mediawiki 'Hello World', :layout => :layout2, :layout_engine => :erb
      end
      assert ok?
      assert_body "ERB Layout!\n<p>Hello World</p>"
    end

    it 'can be used in a nested fashion for partials and whatnot' do
      mock_app do
        template(:inner) { "hi" }
        template(:outer) { "<outer><%= mediawiki :inner %></outer>" }
        get('/') { erb :outer }
      end

      get '/'
      assert ok?
      assert_like '<outer><p>hi</p></outer>', body
    end
  end
rescue LoadError
  warn "#{$!.to_s}: skipping mediawiki tests"
end
