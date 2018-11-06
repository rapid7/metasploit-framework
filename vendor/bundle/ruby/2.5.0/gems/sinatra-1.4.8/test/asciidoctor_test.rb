require File.expand_path('../helper', __FILE__)

begin
  require 'asciidoctor'

  class AsciidoctorTest < Minitest::Test
    def asciidoc_app(&block)
      mock_app do
        set :views, File.dirname(__FILE__) + '/views'
        get('/', &block)
      end
      get '/'
    end

    it 'renders inline AsciiDoc strings' do
      asciidoc_app { asciidoc '== Hiya' }
      assert ok?
      assert_match %r{<h2.*?>Hiya</h2>}, body
    end

    it 'uses the correct engine' do
      engine = Tilt::AsciidoctorTemplate
      assert_equal engine, Tilt[:ad]
      assert_equal engine, Tilt[:adoc]
      assert_equal engine, Tilt[:asciidoc]
    end

    it 'renders .asciidoc files in views path' do
      asciidoc_app { asciidoc :hello }
      assert ok?
      assert_match %r{<h2.*?>Hello from AsciiDoc</h2>}, body
    end

    it 'raises error if template not found' do
      mock_app { get('/') { asciidoc :no_such_template } }
      assert_raises(Errno::ENOENT) { get('/') }
    end

    it 'renders with inline layouts' do
      mock_app do
        layout { 'THIS. IS. #{yield.upcase}!' }
        get('/') { asciidoc 'Sparta', :layout_engine => :str }
      end
      get '/'
      assert ok?
      assert_include body, 'THIS. IS.'
      assert_include body, '<P>SPARTA</P>'
    end

    it 'renders with file layouts' do
      asciidoc_app do
        asciidoc 'Hello World', :layout => :layout2, :layout_engine => :erb
      end
      assert ok?
      assert_include body, 'ERB Layout!'
      assert_include body, '<p>Hello World</p>'
    end

    it 'can be used in a nested fashion for partials and whatnot' do
      mock_app do
        template(:inner) { 'hi' }
        template(:outer) { '<outer><%= asciidoc :inner %></outer>' }
        get('/') { erb :outer }
      end
      get '/'
      assert ok?
      assert_match %r{<outer>.*<p.*?>hi</p>.*</outer>}m, body
    end
  end
rescue LoadError
  warn "#{$!.to_s}: skipping asciidoc tests"
end
