require File.expand_path('../helper', __FILE__)

MarkdownTest = proc do
  def markdown_app(&block)
    mock_app do
      set :views, File.dirname(__FILE__) + '/views'
      get('/', &block)
    end
    get '/'
  end

  def setup
    Tilt.prefer engine, 'markdown', 'mkd', 'md'
    super
  end

  it 'uses the correct engine' do
    assert_equal engine, Tilt[:md]
    assert_equal engine, Tilt[:mkd]
    assert_equal engine, Tilt[:markdown]
  end

  it 'renders inline markdown strings' do
    markdown_app { markdown '# Hiya' }
    assert ok?
    assert_like "<h1>Hiya</h1>\n", body
  end

  it 'renders .markdown files in views path' do
    markdown_app { markdown :hello }
    assert ok?
    assert_like "<h1>Hello From Markdown</h1>", body
  end

  it "raises error if template not found" do
    mock_app { get('/') { markdown :no_such_template } }
    assert_raises(Errno::ENOENT) { get('/') }
  end

  it "renders with inline layouts" do
    mock_app do
      layout { 'THIS. IS. #{yield.upcase}!' }
      get('/') { markdown 'Sparta', :layout_engine => :str }
    end
    get '/'
    assert ok?
    assert_like 'THIS. IS. <P>SPARTA</P>!', body
  end

  it "renders with file layouts" do
    markdown_app {
      markdown 'Hello World', :layout => :layout2, :layout_engine => :erb
    }
    assert ok?
    assert_body "ERB Layout!\n<p>Hello World</p>"
  end

  it "can be used in a nested fashion for partials and whatnot" do
    mock_app do
      template(:inner) { "hi" }
      template(:outer) { "<outer><%= markdown :inner %></outer>" }
      get('/') { erb :outer }
    end

    get '/'
    assert ok?
    assert_like '<outer><p>hi</p></outer>', body
  end
end

# Will generate RDiscountTest, KramdownTest, etc.
map = Tilt.respond_to?(:lazy_map) ? Tilt.lazy_map['md'].map(&:first) : Tilt.mappings['md']

map.each do |t|
  begin
    t = eval(t) if t.is_a? String
    t.new { "" }
    klass = Class.new(Minitest::Test) { define_method(:engine) { t }}
    klass.class_eval(&MarkdownTest)
    name = t.name[/[^:]+$/].sub(/Template$/, '') << "Test"
    Object.const_set name, klass
  rescue LoadError, NameError
    warn "#{$!}: skipping markdown tests with #{t}"
  end
end
