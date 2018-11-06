# frozen_string_literal: true
require File.dirname(__FILE__) + "/shared_signature_examples"
require 'ostruct'

RSpec.describe YARD::Templates::Helpers::HtmlHelper do
  include YARD::Templates::Helpers::BaseHelper
  include YARD::Templates::Helpers::HtmlHelper
  include YARD::Templates::Helpers::MethodHelper

  def options
    Templates::TemplateOptions.new.tap do |o|
      o.reset_defaults
      o.default_return = nil
    end
  end

  describe "#h" do
    it "uses #h to escape HTML" do
      expect(h('Usage: foo "bar" <baz>')).to eq "Usage: foo &quot;bar&quot; &lt;baz&gt;"
    end
  end

  describe "#charset" do
    it "returns foo if LANG=foo" do
      expect(ENV).to receive(:[]).with('LANG').and_return('shift_jis') if YARD.ruby18?
      expect(Encoding.default_external).to receive(:name).and_return('shift_jis') if defined?(Encoding)
      expect(charset).to eq 'shift_jis'
    end

    ['US-ASCII', 'ASCII-7BIT', 'ASCII-8BIT'].each do |type|
      it "converts #{type} to iso-8859-1" do
        expect(ENV).to receive(:[]).with('LANG').and_return(type) if YARD.ruby18?
        expect(Encoding.default_external).to receive(:name).and_return(type) if defined?(Encoding)
        expect(charset).to eq 'iso-8859-1'
      end
    end

    it "supports utf8 as an encoding value for utf-8" do
      type = 'utf8'
      expect(ENV).to receive(:[]).with('LANG').and_return(type) if YARD.ruby18?
      expect(Encoding.default_external).to receive(:name).and_return(type) if defined?(Encoding)
      expect(charset).to eq 'utf-8'
    end

    it "takes file encoding if there is a file" do
      @file = OpenStruct.new(:contents => String.new('foo').force_encoding('sjis'))
      # not the correct charset name, but good enough
      expect(['Shift_JIS', 'Windows-31J']).to include(charset)
    end if YARD.ruby19?

    it "takes file encoding if there is a file" do
      allow(ENV).to receive(:[]).with('LANG').and_return('utf-8') if YARD.ruby18?
      @file = OpenStruct.new(:contents => 'foo')
      expect(charset).to eq 'utf-8'
    end if YARD.ruby18?

    if YARD.ruby18?
      it "returns utf-8 if no LANG env is set" do
        expect(ENV).to receive(:[]).with('LANG').and_return(nil)
        expect(charset).to eq 'utf-8'
      end

      it "only returns charset part of lang" do
        expect(ENV).to receive(:[]).with('LANG').and_return('en_US.UTF-8')
        expect(charset).to eq 'utf-8'
      end
    end
  end

  describe "#format_types" do
    it "includes brackets by default" do
      text = ["String"]
      expect(self).to receive(:linkify).at_least(1).times.with("String", "String").and_return("String")
      expect(format_types(text)).to eq format_types(text, true)
      expect(format_types(text)).to eq "(<tt>String</tt>)"
    end

    it "avoids brackets if brackets=false" do
      expect(self).to receive(:linkify).with("String", "String").and_return("String")
      expect(self).to receive(:linkify).with("Symbol", "Symbol").and_return("Symbol")
      expect(format_types(["String", "Symbol"], false)).to eq "<tt>String</tt>, <tt>Symbol</tt>"
    end

    {"String" => [["String"],
        "<tt><a href=''>String</a></tt>"],
      "A::B::C" => [["A::B::C"],
        "<tt><a href=''>A::B::C</a></tt>"],
      "Array<String>" => [["Array", "String"],
        "<tt><a href=''>Array</a>&lt;<a href=''>String</a>&gt;</tt>"],
      "Array<String, Symbol>" => [["Array", "String", "Symbol"],
        "<tt><a href=''>Array</a>&lt;<a href=''>String</a>, <a href=''>Symbol</a>&gt;</tt>"],
      "Array<{String => Array<Symbol>}>" => [["Array", "String", "Array", "Symbol"],
        "<tt><a href=''>Array</a>&lt;{<a href=''>String</a> =&gt; " \
          "<a href=''>Array</a>&lt;<a href=''>Symbol</a>&gt;}&gt;</tt>"]}.each do |text, values|
      it "links all classes in #{text}" do
        if text.count('<') > 0
          expect(self).to receive(:h).with('<').at_least(text.count('<')).times.and_return("&lt;")
        end
        if text.count('>') > 0
          expect(self).to receive(:h).with('>').at_least(text.count('>')).times.and_return("&gt;")
        end
        values[0].each {|v| expect(self).to receive(:linkify).with(v, v).and_return("<a href=''>#{v}</a>") }
        expect(format_types([text], false)).to eq values[1]
      end
    end
  end

  describe "#htmlify" do
    it "does not use hard breaks for textile markup (RedCloth specific)" do
      begin; require 'redcloth'; rescue LoadError; pending 'test requires redcloth gem' end
      expect(htmlify("A\nB", :textile)).not_to include("<br")
    end

    it "uses hard breaks for textile_strict markup (RedCloth specific)" do
      begin; require 'redcloth'; rescue LoadError; pending 'test requires redcloth gem' end
      expect(htmlify("A\nB", :textile_strict)).to include("<br")
    end

    it "handles various encodings" do
      allow(self).to receive(:object).and_return(Registry.root)
      text = String.new("\xB0\xB1")
      if defined?(Encoding)
        utf8 = Encoding.find('utf-8')

        Encoding.default_internal = utf8 unless Encoding.default_internal == utf8
        text = text.force_encoding('binary')
      end
      htmlify(text, :text)
      # TODO: add more encoding tests
    end

    it "returns pre-formatted text with :pre markup" do
      expect(htmlify("fo\no\n\nbar<>", :pre)).to eq "<pre>fo\no\n\nbar&lt;&gt;</pre>"
    end

    it "returns regular text with :text markup" do
      expect(htmlify("fo\no\n\nbar<>", :text)).to eq "fo<br/>o<br/><br/>bar&lt;&gt;"
    end

    it "returns unmodified text with :none markup" do
      expect(htmlify("fo\no\n\nbar<>", :none)).to eq "fo\no\n\nbar&lt;&gt;"
    end

    it "highlights ruby if markup is :ruby" do
      expect(htmlify("class Foo; end", :ruby)).to match(/\A<pre class="code ruby"><span/)
    end

    it "includes file and htmlifies it" do
      load_markup_provider(:rdoc)
      expect(File).to receive(:file?).with('foo.rdoc').and_return(true)
      expect(File).to receive(:read).with('foo.rdoc').and_return('HI')
      expect(htmlify("{include:file:foo.rdoc}", :rdoc).gsub(/\s+/, '')).to eq "<p>HI</p>"
    end

    it "allows inline includes for {include:} in the middle of a line" do
      load_markup_provider(:rdoc)
      expect(File).to receive(:file?).with('foo.rdoc').and_return(true)
      expect(File).to receive(:read).with('foo.rdoc').and_return('HI')
      expect(htmlify("test {include:file:foo.rdoc}", :rdoc).gsub(/[\r?\n]+/, '')).to eq '<p>test HI</p>'
    end

    it "autolinks URLs (markdown specific)" do
      log.enter_level(Logger::FATAL) do
        unless markup_class(:markdown).to_s == "RedcarpetCompat"
          pending 'This test depends on a markdown engine that supports autolinking'
        end
      end
      expect(htmlify('http://example.com', :markdown).chomp.gsub('&#47;', '/')).to eq(
        '<p><a href="http://example.com">http://example.com</a></p>'
      )
    end

    it "does not autolink URLs inside of {} (markdown specific)" do
      log.enter_level(Logger::FATAL) do
        pending 'This test depends on markdown' unless markup_class(:markdown)
      end
      expect(htmlify('{http://example.com Title}', :markdown).chomp).to match(
        %r{<p><a href="http://example.com".*>Title</a></p>}
      )
      expect(htmlify('{http://example.com}', :markdown).chomp).to match(
        %r{<p><a href="http://example.com".*>http://example.com</a></p>}
      )
    end

    it "creates tables (markdown specific)" do
      log.enter_level(Logger::FATAL) do
        supports_table = %w(RedcarpetCompat Kramdown::Document)
        unless supports_table.include?(markup_class(:markdown).to_s)
          pending "This test depends on a markdown engine that supports tables"
        end
      end

      markdown = <<-EOF.strip
        City    | State | Country
        --------|-------|--------
        Raleigh | NC    | US
        Seattle | WA    | US
      EOF

      html = htmlify(markdown, :markdown)
      expect(html).to match(/<table>/)
      expect(html).to match %r{<th>City</th>}
      expect(html).to match %r{<td>NC</td>}
    end

    it "handles fenced code blocks (Redcarpet specific)" do
      log.enter_level(Logger::FATAL) do
        unless markup_class(:markdown).to_s == 'RedcarpetCompat'
          pending 'This test is Redcarpet specific'
        end
      end

      markdown = "Introduction:\n```ruby\nputs\n\nputs\n```"
      html = htmlify(markdown, :markdown)
      expect(html).to match %r{^<p>Introduction:</p>.*<code class="ruby">}m
    end
  end

  describe "#link_object" do
    let(:object) { CodeObjects::NamespaceObject.new(nil, :YARD) }

    it "returns the object path if there's no serializer and no title" do
      allow(self).to receive(:serializer).and_return(nil)
      expect(link_object(CodeObjects::NamespaceObject.new(nil, :YARD))).to eq "YARD"
    end

    it "returns the title if there's a title but no serializer" do
      allow(self).to receive(:serializer).and_return(nil)
      expect(link_object(CodeObjects::NamespaceObject.new(nil, :YARD), 'title')).to eq "title"
    end

    it "links objects from overload tag" do
      YARD.parse_string <<-'eof'
        module Foo
          class Bar; def a; end end
          class Baz
            # @overload a
            def a; end
          end
        end
      eof
      obj = Registry.at('Foo::Baz#a').tag(:overload)
      allow(self).to receive(:serializer).and_return(Serializers::FileSystemSerializer.new)
      allow(self).to receive(:object).and_return(obj)
      expect(link_object("Bar#a")).to match(/href="Bar.html#a-instance_method"/)
    end

    it "uses relative path in title" do
      CodeObjects::ModuleObject.new(:root, :YARD)
      CodeObjects::ClassObject.new(P('YARD'), :Bar)
      allow(self).to receive(:object).and_return(CodeObjects::ModuleObject.new(P('YARD'), :Foo))
      allow(self).to receive(:serializer).and_return(Serializers::FileSystemSerializer.new)
      expect(link_object("Bar")).to match %r{>Bar</a>}
    end

    it "uses #title if overridden" do
      CodeObjects::ModuleObject.new(:root, :YARD)
      CodeObjects::ClassObject.new(P('YARD'), :Bar)
      allow(Registry.at('YARD::Bar')).to receive(:title).and_return('TITLE!')
      allow(self).to receive(:object).and_return(Registry.at('YARD::Bar'))
      allow(self).to receive(:serializer).and_return(Serializers::FileSystemSerializer.new)
      expect(link_object("Bar")).to match %r{>TITLE!</a>}
    end

    it "uses relative path to parent class in title" do
      root = CodeObjects::ModuleObject.new(:root, :YARD)
      obj = CodeObjects::ModuleObject.new(root, :SubModule)
      allow(self).to receive(:object).and_return(obj)
      allow(self).to receive(:serializer).and_return(Serializers::FileSystemSerializer.new)
      expect(link_object("YARD")).to match %r{>YARD</a>}
    end

    it "uses Klass.foo when linking to class method in current namespace" do
      root = CodeObjects::ModuleObject.new(:root, :Klass)
      CodeObjects::MethodObject.new(root, :foo, :class)
      allow(self).to receive(:object).and_return(root)
      allow(self).to receive(:serializer).and_return(Serializers::FileSystemSerializer.new)
      expect(link_object("foo")).to match %r{>Klass.foo</a>}
    end

    it "escapes method name in title" do
      YARD.parse_string <<-'eof'
        class Array
          def &(other)
          end
        end
      eof
      obj = Registry.at('Array#&')
      allow(self).to receive(:serializer).and_return(Serializers::FileSystemSerializer.new)
      allow(self).to receive(:object).and_return(obj)
      expect(link_object("Array#&")).to match(/title="Array#&amp; \(method\)"/)
    end
  end

  describe "#url_for" do
    before { Registry.clear }

    it "returns nil if serializer is nil" do
      allow(self).to receive(:serializer).and_return nil
      allow(self).to receive(:object).and_return Registry.root
      expect(url_for(P("Mod::Class#meth"))).to be nil
    end

    it "returns nil if object is hidden" do
      yard = CodeObjects::ModuleObject.new(:root, :YARD)

      allow(self).to receive(:serializer).and_return(Serializers::FileSystemSerializer.new)
      allow(self).to receive(:object).and_return Registry.root
      allow(self).to receive(:options).and_return OpenStruct.new(:verifier => Verifier.new('false'))

      expect(url_for(yard)).to be nil
    end

    it "returns nil if serializer does not implement #serialized_path" do
      allow(self).to receive(:serializer).and_return Serializers::Base.new
      allow(self).to receive(:object).and_return Registry.root
      expect(url_for(P("Mod::Class#meth"))).to be nil
    end

    it "links to a path/file for a namespace object" do
      allow(self).to receive(:serializer).and_return Serializers::FileSystemSerializer.new
      allow(self).to receive(:object).and_return Registry.root

      yard = CodeObjects::ModuleObject.new(:root, :YARD)
      expect(url_for(yard)).to eq 'YARD.html'
    end

    it "links to the object's namespace path/file and use the object as the anchor" do
      allow(self).to receive(:serializer).and_return Serializers::FileSystemSerializer.new
      allow(self).to receive(:object).and_return Registry.root

      yard = CodeObjects::ModuleObject.new(:root, :YARD)
      meth = CodeObjects::MethodObject.new(yard, :meth)
      expect(url_for(meth)).to eq 'YARD.html#meth-instance_method'
    end

    it "properly urlencodes methods with punctuation in links" do
      obj = CodeObjects::MethodObject.new(nil, :/)
      serializer = double(:serializer, :serialized_path => "file.html")
      allow(self).to receive(:serializer).and_return serializer
      allow(self).to receive(:object).and_return obj
      expect(url_for(obj)).to eq "#%2F-instance_method"
    end
  end

  describe "#anchor_for" do
    it "does not urlencode data when called directly" do
      obj = CodeObjects::MethodObject.new(nil, :/)
      expect(anchor_for(obj)).to eq "/-instance_method"
    end
  end

  describe "#resolve_links" do
    def parse_link(link)
      results = {}
      link =~ %r{<a (.+?)>(.+?)</a>}m
      params = $1
      results[:inner_text] = $2
      params.scan(/\s*(\S+?)=['"](.+?)['"]\s*/).each do |key, value|
        results[key.to_sym] = value.gsub(/^["'](.+)["']$/, '\1')
      end
      results
    end

    it "escapes {} syntax with backslash (\\{foo bar})" do
      input  = '\{foo bar} \{XYZ} \{file:FOO} $\{N-M}'
      output = '{foo bar} {XYZ} {file:FOO} ${N-M}'
      expect(resolve_links(input)).to eq output
    end

    it "escapes {} syntax with ! (!{foo bar})" do
      input  = '!{foo bar} !{XYZ} !{file:FOO} $!{N-M}'
      output = '{foo bar} {XYZ} {file:FOO} ${N-M}'
      expect(resolve_links(input)).to eq output
    end

    it "links static files with file: prefix" do
      allow(self).to receive(:serializer).and_return Serializers::FileSystemSerializer.new
      allow(self).to receive(:object).and_return Registry.root

      expect(parse_link(resolve_links("{file:TEST.txt#abc}"))).to eq(
        :inner_text => "TEST",
        :title => "TEST",
        :href => "file.TEST.html#abc"
      )
      expect(parse_link(resolve_links("{file:TEST.txt title}"))).to eq(
        :inner_text => "title",
        :title => "title",
        :href => "file.TEST.html"
      )
    end

    it "creates regular links with http:// or https:// prefixes" do
      expect(parse_link(resolve_links("{http://example.com}"))).to eq(
        :inner_text => "http://example.com",
        :target => "_parent",
        :href => "http://example.com",
        :title => "http://example.com"
      )
      expect(parse_link(resolve_links("{http://example.com title}"))).to eq(
        :inner_text => "title",
        :target => "_parent",
        :href => "http://example.com",
        :title => "title"
      )
    end

    it "creates mailto links with mailto: prefixes" do
      expect(parse_link(resolve_links('{mailto:joanna@example.com}'))).to eq(
        :inner_text => 'mailto:joanna@example.com',
        :target => '_parent',
        :href => 'mailto:joanna@example.com',
        :title => 'mailto:joanna@example.com'
      )
      expect(parse_link(resolve_links('{mailto:steve@example.com Steve}'))).to eq(
        :inner_text => 'Steve',
        :target => '_parent',
        :href => 'mailto:steve@example.com',
        :title => 'Steve'
      )
    end

    it "ignores {links} that begin with |...|" do
      expect(resolve_links("{|x|x == 1}")).to eq "{|x|x == 1}"
    end

    it "gracefully ignores {} in links" do
      allow(self).to receive(:linkify).with('Foo', 'Foo').and_return('FOO')
      expect(resolve_links("{} {} {Foo Foo}")).to eq '{} {} FOO'
    end

    %w(tt code pre).each do |tag|
      it "ignores links in <#{tag}>" do
        text = "<#{tag}>{Foo}</#{tag}>"
        expect(resolve_links(text)).to eq text
      end
    end

    it "resolves {Name}" do
      expect(self).to receive(:link_file).with('TEST', nil, nil).and_return('')
      resolve_links("{file:TEST}")
    end

    it "resolves ({Name})" do
      expect(self).to receive(:link_file).with('TEST', nil, nil).and_return('')
      resolve_links("({file:TEST})")
    end

    it "resolves link with newline in title-part" do
      expect(parse_link(resolve_links("{http://example.com foo\nbar}"))).to eq(
        :inner_text => "foo bar",
        :target => "_parent",
        :href => "http://example.com",
        :title => "foo bar"
      )
    end

    it "resolves links to methods whose names have been escaped" do
      expect(self).to receive(:linkify).with('Object#<<', nil).and_return('')
      resolve_links("{Object#&lt;&lt;}")
    end

    it "warns about missing reference at right file location for object" do
      YARD.parse_string <<-eof
        # Comments here
        # And a reference to {InvalidObject}
        class MyObject; end
      eof
      logger = double(:log)
      expect(logger).to receive(:warn).ordered.with(
        "In file `(stdin)':2: Cannot resolve link to InvalidObject from text:\n\t...{InvalidObject}"
      )
      allow(self).to receive(:log).and_return(logger)
      allow(self).to receive(:object).and_return(Registry.at('MyObject'))
      resolve_links(object.docstring)
    end

    it "shows ellipsis on either side if there is more on the line in a reference warning" do
      YARD.parse_string <<-eof
        # {InvalidObject1} beginning of line
        # end of line {InvalidObject2}
        # Middle of {InvalidObject3} line
        # {InvalidObject4}
        class MyObject; end
      eof
      logger = double(:log)
      expect(logger).to receive(:warn).ordered.with("In file `(stdin)':1: Cannot resolve link to InvalidObject1 from text:\n\t{InvalidObject1}...")
      expect(logger).to receive(:warn).ordered.with("In file `(stdin)':2: Cannot resolve link to InvalidObject2 from text:\n\t...{InvalidObject2}")
      expect(logger).to receive(:warn).ordered.with("In file `(stdin)':3: Cannot resolve link to InvalidObject3 from text:\n\t...{InvalidObject3}...")
      expect(logger).to receive(:warn).ordered.with("In file `(stdin)':4: Cannot resolve link to InvalidObject4 from text:\n\t{InvalidObject4}")
      allow(self).to receive(:log).and_return(logger)
      allow(self).to receive(:object).and_return(Registry.at('MyObject'))
      resolve_links(object.docstring)
    end

    it "warns about missing reference for file template (no object)" do
      @file = CodeObjects::ExtraFileObject.new('myfile.txt', '')
      logger = double(:log)
      expect(logger).to receive(:warn).ordered.with("In file `myfile.txt':3: Cannot resolve link to InvalidObject from text:\n\t...{InvalidObject Some Title}")
      allow(self).to receive(:log).and_return(logger)
      allow(self).to receive(:object).and_return(Registry.root)
      resolve_links(<<-eof)
        Hello world
        This is a line
        And {InvalidObject Some Title}
        And more.
      eof
    end
  end

  describe "#signature" do
    before do
      arrow = "&#x21d2;"
      @results = {
        :regular => "#<strong>foo</strong> #{arrow} Object",
        :default_return => "#<strong>foo</strong> #{arrow} Hello",
        :no_default_return => "#<strong>foo</strong>",
        :private_class => ".<strong>foo</strong> #{arrow} Object <span class=\"extras\">(private)</span>",
        :single => "#<strong>foo</strong> #{arrow} String",
        :two_types => "#<strong>foo</strong> #{arrow} String, Symbol",
        :two_types_multitag => "#<strong>foo</strong> #{arrow} String, Symbol",
        :type_nil => "#<strong>foo</strong> #{arrow} Type<sup>?</sup>",
        :type_array => "#<strong>foo</strong> #{arrow} Type<sup>+</sup>",
        :multitype => "#<strong>foo</strong> #{arrow} Type, ...",
        :void => "#<strong>foo</strong> #{arrow} void",
        :hide_void => "#<strong>foo</strong>",
        :block => "#<strong>foo</strong> {|a, b, c| ... } #{arrow} Object",
        :empty_overload => "#<strong>foobar</strong> #{arrow} String"
      }
    end

    def format_types(types, _brackets = false) types.join(", ") end
    def signature(obj, link = false) super(obj, link).strip end

    it_should_behave_like "signature"

    it "links to regular method if overload name does not have the same method name" do
      YARD.parse_string <<-eof
        class Foo
          # @overload bar(a, b, c)
          def foo; end
        end
      eof
      serializer = double(:serializer)
      allow(serializer).to receive(:serialized_path).with(Registry.at('Foo')).and_return('')
      allow(self).to receive(:serializer).and_return(serializer)
      allow(self).to receive(:object).and_return(Registry.at('Foo'))
      expect(signature(Registry.at('Foo#foo').tag(:overload), true)).to eq(
        "<a href=\"#foo-instance_method\" title=\"#bar (instance method)\">#<strong>bar</strong>(a, b, c)  </a>"
      )
    end
  end

  describe "#html_syntax_highlight" do
    subject do
      obj = OpenStruct.new
      obj.options = options
      obj.object = Registry.root
      obj.extend(Templates::Helpers::HtmlHelper)
      obj
    end

    it "returns empty string on nil input" do
      expect(subject.html_syntax_highlight(nil)).to eq ''
    end

    it "calls #html_syntax_highlight_ruby by default" do
      Registry.root.source_type = nil
      expect(subject).to receive(:html_syntax_highlight_ruby).with('def x; end')
      subject.html_syntax_highlight('def x; end')
    end

    it "calls #html_syntax_highlight_NAME if there's an object with a #source_type" do
      subject.object = OpenStruct.new(:source_type => :NAME)
      expect(subject).to receive(:html_markup_html) {|text| text }
      expect(subject).to receive(:html_syntax_highlight_NAME).and_return("foobar")
      expect(subject.htmlify('<pre><code>def x; end</code></pre>', :html)).to eq(
        '<pre class="code NAME"><code class="NAME">foobar</code></pre>'
      )
    end

    it "adds !!!LANG to className in outputted pre tag" do
      subject.object = OpenStruct.new(:source_type => :LANG)
      expect(subject).to receive(:html_markup_html) {|text| text }
      expect(subject).to receive(:html_syntax_highlight_LANG).and_return("foobar")
      expect(subject.htmlify("<pre><code>!!!LANG\ndef x; end</code></pre>", :html)).to eq(
        '<pre class="code LANG"><code class="LANG">foobar</code></pre>'
      )
    end

    it "calls html_syntax_highlight_NAME if source starts with !!!NAME" do
      expect(subject).to receive(:html_syntax_highlight_NAME).and_return("foobar")
      expect(subject.html_syntax_highlight(<<-eof
        !!!NAME
        def x; end
      eof
                                          )).to eq "foobar"
    end

    it "does not highlight if highlight option is false" do
      subject.options.highlight = false
      expect(subject).not_to receive(:html_syntax_highlight_ruby)
      expect(subject.html_syntax_highlight('def x; end')).to eq 'def x; end'
    end

    it "does not highlight if there is no highlight method specified by !!!NAME" do
      def subject.respond_to?(method, include_all = false)
        return false if method == 'html_syntax_highlight_NAME'
        super
      end
      expect(subject).not_to receive(:html_syntax_highlight_NAME)
      expect(subject.html_syntax_highlight("!!!NAME\ndef x; end")).to eq "def x; end"
    end

    it "highlights as ruby if htmlify(text, :ruby) is called" do
      expect(subject).to receive(:html_syntax_highlight_ruby).with('def x; end').and_return('x')
      expect(subject.htmlify('def x; end', :ruby)).to eq '<pre class="code ruby">x</pre>'
    end

    it "does not prioritize object source type when called directly" do
      expect(subject).to receive(:html_syntax_highlight_ruby).with('def x; end').and_return('x')
      subject.object = OpenStruct.new(:source_type => :c)
      expect(subject.html_syntax_highlight("def x; end")).to eq "x"
    end

    it "doesn't escape code snippets twice" do
      expect(subject.htmlify('<pre lang="foo"><code>{"foo" => 1}</code></pre>', :html)).to eq(
        '<pre class="code foo"><code class="foo">{&quot;foo&quot; =&gt; 1}</code></pre>'
      )
    end

    it "highlights source when matching a pre lang= tag" do
      expect(subject.htmlify('<pre lang="foo"><code>x = 1</code></pre>', :html)).to eq(
        '<pre class="code foo"><code class="foo">x = 1</code></pre>'
      )
    end

    it "highlights source when matching a code class= tag" do
      expect(subject.htmlify('<pre><code class="foo">x = 1</code></pre>', :html)).to eq(
        '<pre class="code foo"><code class="foo">x = 1</code></pre>'
      )
    end
  end

  describe "#link_url" do
    it "adds target if scheme is provided" do
      expect(link_url("http://url.com")).to include(" target=\"_parent\"")
      expect(link_url("https://url.com")).to include(" target=\"_parent\"")
      expect(link_url("irc://url.com")).to include(" target=\"_parent\"")
      expect(link_url("../not/scheme")).not_to include("target")
    end
  end
end
