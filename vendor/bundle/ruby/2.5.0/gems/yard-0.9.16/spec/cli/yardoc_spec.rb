# frozen_string_literal: true

RSpec.describe YARD::CLI::Yardoc do
  before do
    @yardoc = YARD::CLI::Yardoc.new
    @yardoc.statistics = false
    @yardoc.use_document_file = false
    @yardoc.use_yardopts_file = false
    @yardoc.generate = false
    allow(Templates::Engine).to receive(:render)
    allow(Templates::Engine).to receive(:generate)
    allow(YARD).to receive(:parse)
    allow(Registry).to receive(:load)
    allow(Registry).to receive(:save)
    allow(File).to receive(:open!)
  end

  describe "Defaults" do
    before do
      @yardoc = CLI::Yardoc.new
      allow(@yardoc).to receive(:yardopts).and_return([])
      allow(@yardoc).to receive(:support_rdoc_document_file!).and_return([])
      @yardoc.parse_arguments
    end

    it "does not use cache by default" do
      expect(@yardoc.use_cache).to be false
    end

    it "prints statistics by default" do
      expect(@yardoc.statistics).to be true
    end

    it "generates output by default" do
      expect(@yardoc.generate).to be true
    end

    it "reads .yardopts by default" do
      expect(@yardoc.use_yardopts_file).to be true
    end

    it "reads .document by default" do
      expect(@yardoc.use_document_file).to be true
    end

    it "uses lib, app, and ext as default file glob paths" do
      expect(@yardoc.files).to eq Parser::SourceParser::DEFAULT_PATH_GLOB
    end

    it "uses rdoc as default markup type (but falls back on none)" do
      expect(@yardoc.options.markup).to eq :rdoc
    end

    it "uses default as default template" do
      expect(@yardoc.options.template).to eq :default
    end

    it "uses HTML as default format" do
      expect(@yardoc.options.format).to eq :html
    end

    it "uses 'Object' as default return type" do
      expect(@yardoc.options.default_return).to eq 'Object'
    end

    it "does not hide void return types by default" do
      expect(@yardoc.options.hide_void_return).to be false
    end

    it "only shows public visibility by default" do
      expect(@yardoc.visibilities).to eq [:public]
    end

    it "does not list objects by default" do
      expect(@yardoc.list).to be false
    end

    it "does not embed mixins by default" do
      expect(@yardoc.options.embed_mixins).to be_empty
    end

    it "does not set any locale by default" do
      expect(@yardoc.options.locale).to be nil
    end
  end

  describe "General options" do
    def self.should_accept(*args, &block)
      @counter ||= 0
      @counter += 1
      counter = @counter
      define_method("test_options_#{@counter}", &block)
      args.each do |arg|
        it("accepts #{arg}") { send("test_options_#{counter}", arg) }
      end
    end

    should_accept('--single-db') do |arg|
      @yardoc.parse_arguments(arg)
      expect(Registry.single_object_db).to be true
      Registry.single_object_db = nil
    end

    should_accept('--no-single-db') do |arg|
      @yardoc.parse_arguments(arg)
      expect(Registry.single_object_db).to be false
      Registry.single_object_db = nil
    end

    should_accept('-c', '--use-cache') do |arg|
      @yardoc.parse_arguments(arg)
      expect(@yardoc.use_cache).to be true
    end

    should_accept('--no-cache') do |arg|
      @yardoc.parse_arguments(arg)
      expect(@yardoc.use_cache).to be false
    end

    should_accept('--yardopts') do |arg|
      @yardoc = CLI::Yardoc.new
      @yardoc.use_document_file = false
      expect(@yardoc).to receive(:yardopts).at_least(1).times.and_return([])
      @yardoc.parse_arguments(arg)
      expect(@yardoc.use_yardopts_file).to be true
      @yardoc.parse_arguments('--no-yardopts', arg)
      expect(@yardoc.use_yardopts_file).to be true
    end

    should_accept('--yardopts with filename') do |_arg|
      @yardoc = CLI::Yardoc.new
      expect(File).to receive(:read_binary).with('.foobar').and_return('')
      @yardoc.use_document_file = false
      @yardoc.parse_arguments('--yardopts', '.foobar')
      expect(@yardoc.use_yardopts_file).to be true
      expect(@yardoc.options_file).to eq '.foobar'
    end

    should_accept('--no-yardopts') do |arg|
      @yardoc = CLI::Yardoc.new
      @yardoc.use_document_file = false
      expect(@yardoc).not_to receive(:yardopts)
      @yardoc.parse_arguments(arg)
      expect(@yardoc.use_yardopts_file).to be false
      @yardoc.parse_arguments('--yardopts', arg)
      expect(@yardoc.use_yardopts_file).to be false
    end

    should_accept('--document') do |arg|
      @yardoc = CLI::Yardoc.new
      @yardoc.use_yardopts_file = false
      expect(@yardoc).to receive(:support_rdoc_document_file!).and_return([])
      @yardoc.parse_arguments('--no-document', arg)
      expect(@yardoc.use_document_file).to be true
    end

    should_accept('--no-document') do |arg|
      @yardoc = CLI::Yardoc.new
      @yardoc.use_yardopts_file = false
      expect(@yardoc).not_to receive(:support_rdoc_document_file!)
      @yardoc.parse_arguments('--document', arg)
      expect(@yardoc.use_document_file).to be false
    end

    should_accept('-b', '--db') do |arg|
      @yardoc.parse_arguments(arg, 'test')
      expect(Registry.yardoc_file).to eq 'test'
      Registry.yardoc_file = '.yardoc'
    end

    should_accept('-n', '--no-output') do |arg|
      expect(Templates::Engine).not_to receive(:generate)
      @yardoc.run(arg)
    end

    should_accept('--exclude') do |arg|
      expect(YARD).to receive(:parse).with(['a'], ['nota', 'b'])
      @yardoc.run(arg, 'nota', arg, 'b', 'a')
    end

    should_accept('--no-save') do |arg|
      expect(YARD).to receive(:parse)
      expect(Registry).not_to receive(:save)
      @yardoc.run(arg)
    end

    should_accept('--fail-on-warning') do |arg|
      expect(YARD).to receive(:parse)
      @yardoc.run(arg)
    end
  end

  describe "Output options" do
    it "accepts --title" do
      @yardoc.parse_arguments('--title', 'hello world')
      expect(@yardoc.options.title).to eq 'hello world'
    end

    it "allows --title to have multiple spaces in .yardopts" do
      expect(File).to receive(:read_binary).with("test").and_return("--title \"Foo Bar\"")
      @yardoc.options_file = "test"
      @yardoc.use_yardopts_file = true
      @yardoc.run
      expect(@yardoc.options.title).to eq "Foo Bar"
    end

    it "aliases --main to the --readme flag" do
      Dir.chdir(File.join(File.dirname(__FILE__), '..', '..')) do
        @yardoc.parse_arguments('--main', 'README.md')
        expect(@yardoc.options.readme).to eq CodeObjects::ExtraFileObject.new('README.md', '')
      end
    end

    it "selects a markup provider when --markup-provider or -mp is set" do
      @yardoc.parse_arguments("-M", "test")
      expect(@yardoc.options.markup_provider).to eq :test
      @yardoc.parse_arguments("--markup-provider", "test2")
      expect(@yardoc.options.markup_provider).to eq :test2
    end

    it "selects a markup format when -m is set" do
      expect(@yardoc).to receive(:verify_markup_options).and_return(true)
      @yardoc.generate = true
      @yardoc.parse_arguments('-m', 'markdown')
      expect(@yardoc.options.markup).to eq :markdown
    end

    it "accepts --default-return" do
      @yardoc.parse_arguments(*%w(--default-return XYZ))
      expect(@yardoc.options.default_return).to eq "XYZ"
    end

    it "allows --hide-void-return to be set" do
      @yardoc.parse_arguments(*%w(--hide-void-return))
      expect(@yardoc.options.hide_void_return).to be true
    end

    it "accepts --embed-mixins" do
      @yardoc.parse_arguments(*%w(--embed-mixins))
      expect(@yardoc.options.embed_mixins).to eq ['*']
    end

    it "accepts --embed-mixin MODULE" do
      @yardoc.parse_arguments(*%w(--embed-mixin MyModule))
      expect(@yardoc.options.embed_mixins).to eq ['MyModule']
    end

    it "generates all objects with --use-cache" do
      expect(YARD).to receive(:parse)
      expect(Registry).to receive(:load)
      expect(Registry).to receive(:load_all)
      allow(@yardoc).to receive(:generate).and_return(true)
      @yardoc.run(*%w(--use-cache))
    end

    it "does not print statistics with --no-stats" do
      allow(@yardoc).to receive(:statistics).and_return(false)
      expect(CLI::Stats).not_to receive(:new)
      @yardoc.run(*%w(--no-stats))
    end

    it "disables progress bar with --no-progress" do
      old = log.show_progress
      log.show_progress = true
      @yardoc.run(*%w(--no-progress))
      expect(log.show_progress).to eq false
      log.show_progress = old
    end

    describe "--asset" do
      before do
        @yardoc.generate = true
        allow(@yardoc).to receive(:run_generate)
      end

      it "copies assets to output directory" do
        expect(FileUtils).to receive(:cp_r).with('a', 'doc/a')
        @yardoc.run(*%w(--asset a))
        expect(@yardoc.assets).to eq('a' => 'a')
      end

      it "allows multiple --asset options" do
        expect(FileUtils).to receive(:cp_r).with('a', 'doc/a')
        expect(FileUtils).to receive(:cp_r).with('b', 'doc/b')
        @yardoc.run(*%w(--asset a --asset b))
        expect(@yardoc.assets).to eq('a' => 'a', 'b' => 'b')
      end

      it "does not allow from or to to refer to a path above current path" do
        expect(log).to receive(:warn).exactly(4).times.with(/invalid/i)
        @yardoc.run(*%w(--asset ../../../etc/passwd))
        expect(@yardoc.assets).to be_empty
        @yardoc.run(*%w(--asset a/b/c/d/../../../../../../etc/passwd))
        expect(@yardoc.assets).to be_empty
        @yardoc.run(*%w(--asset /etc/passwd))
        expect(@yardoc.assets).to be_empty
        @yardoc.run(*%w(--asset normal:/etc/passwd))
        expect(@yardoc.assets).to be_empty
      end

      it "allows from:to syntax" do
        expect(FileUtils).to receive(:cp_r).with(%r{foo(\/\.)?}, 'doc/bar')
        @yardoc.run(*%w(--asset foo:bar))
        expect(@yardoc.assets).to eq('foo' => 'bar')
      end

      it "does not put from inside of to/ if from is a directory" do
        begin
          from = 'tmp_foo'
          to = 'tmp_bar'
          full_to = File.join(File.dirname(__FILE__), to)
          FileUtils.mkdir_p(from)
          @yardoc.options.serializer.basepath = File.dirname(__FILE__)
          @yardoc.run("--asset", "#{from}:#{to}")
          @yardoc.run("--asset", "#{from}:#{to}")
          expect(File.directory?(full_to)).to be true
          expect(File.directory?(File.join(full_to, 'tmp_foo'))).to be false
        ensure
          FileUtils.rm_rf(from)
          FileUtils.rm_rf(full_to)
        end
      end
    end

    describe "--locale" do
      it "applies specified locale to all extra file objects" do
        allow(File).to receive(:read).with('extra_file1').and_return('')
        allow(File).to receive(:read).with('extra_file2').and_return('')

        extra_file_object1 = CodeObjects::ExtraFileObject.new('extra_file1')
        extra_file_object2 = CodeObjects::ExtraFileObject.new('extra_file2')
        expect(extra_file_object1).to receive(:locale=).with('fr')
        expect(extra_file_object2).to receive(:locale=).with('fr')

        allow(CodeObjects::ExtraFileObject).to receive(:new).with('extra_file1').and_return(extra_file_object1)
        allow(CodeObjects::ExtraFileObject).to receive(:new).with('extra_file2').and_return(extra_file_object2)
        allow(Dir).to receive(:glob).with('README{,*[^~]}').and_return([])
        allow(File).to receive(:file?).with('extra_file1').and_return(true)
        allow(File).to receive(:file?).with('extra_file2').and_return(true)
        @yardoc.run('--locale=fr', '-', 'extra_file1', 'extra_file2')
      end
    end

    describe "--po-dir" do
      it "sets Registry.po_dir" do
        expect(Registry).to receive(:po_dir=).with("locale")
        @yardoc.run('--po-dir=locale')
      end
    end
  end

  describe "--[no-]api" do
    before { Registry.clear }

    it "allows --api name" do
      YARD.parse_string <<-eof
        # @api private
        class Foo; end
        # @api public
        class Bar; end
        class Baz; end
      eof
      @yardoc.run('--api', 'private')
      expect(@yardoc.options.verifier.run(Registry.all)).to eq [P('Foo')]
    end

    it "allows multiple --api's to all be shown" do
      YARD.parse_string <<-eof
        # @api private
        class Foo; end
        # @api public
        class Bar; end
        class Baz; end
      eof
      @yardoc.run('--api', 'private', '--api', 'public')
      expect(@yardoc.options.verifier.run(Registry.all).
        sort_by(&:path)).to eq [P('Bar'), P('Foo')]
    end

    it "allows --no-api to specify objects with no @api tag" do
      YARD.parse_string <<-eof
        # @api private
        class Foo; end
        # @api public
        class Bar; end
        class Baz; end
      eof
      @yardoc.run('--api', '')
      expect(@yardoc.options.verifier.run(Registry.all)).to eq [P('Baz')]
      @yardoc.options.verifier = Verifier.new
      @yardoc.run('--no-api')
      expect(@yardoc.options.verifier.run(Registry.all)).to eq [P('Baz')]
    end

    it "allows --no-api to work with other --api switches" do
      YARD.parse_string <<-eof
        # @api private
        class Foo; end
        # @api public
        class Bar; end
        class Baz; end
      eof
      @yardoc.run('--no-api', '--api', 'public')
      expect(@yardoc.options.verifier.run(Registry.all).
        sort_by(&:path)).to eq [P('Bar'), P('Baz')]
    end

    it "ensures Ruby code cannot be used" do
      [':symbol', '42', '"; exit'].each do |ruby|
        @yardoc.options.verifier.expressions = []
        @yardoc.run('--api', ruby)
        expect(@yardoc.options.verifier.expressions[1]).to include(ruby.inspect)
      end
    end
  end

  describe "--hide-api option" do
    it "allows --hide-api to hide objects with api tags" do
      YARD.parse_string <<-eof
        # @api private
        class Foo; end
        class Bar; end
        class Baz; end
      eof
      @yardoc.run('--hide-api', 'private')
      expect(@yardoc.options.verifier.run(Registry.all).
        sort_by(&:path)).to eq [P('Bar'), P('Baz')]
    end

    it "allows --hide-api to work with --api" do
      YARD.parse_string <<-eof
        # @api private
        class Foo; end
        # @api public
        class Bar; end
        class Baz; end
      eof
      @yardoc.run('--api', 'public', '--hide-api', 'private')
      expect(@yardoc.options.verifier.run(Registry.all).
        sort_by(&:path)).to eq [P('Bar')]
    end
  end

  describe "--no-private option" do
    it "accepts --no-private" do
      obj = double(:object)
      expect(obj).to receive(:tag).ordered.with(:private).and_return(true)
      @yardoc.parse_arguments(*%w(--no-private))
      expect(@yardoc.options.verifier.call(obj)).to be false
    end

    it "hides object if namespace is @private with --no-private" do
      ns = double(:namespace, :type => :module)
      expect(ns).to receive(:tag).with(:private).and_return(true)
      obj = double(:object, :namespace => ns)
      expect(obj).to receive(:tag).with(:private).and_return(false)
      @yardoc.parse_arguments(*%w(--no-private))
      expect(@yardoc.options.verifier.call(obj)).to be false
    end

    it "does not call #tag on namespace if namespace is proxy with --no-private" do
      ns = double(:namespace)
      expect(ns).to receive(:is_a?).with(CodeObjects::Proxy).and_return(true)
      expect(ns).not_to receive(:tag)
      obj = double(:object, :type => :class, :namespace => ns, :visibility => :public)
      expect(obj).to receive(:tag).ordered.with(:private).and_return(false)
      @yardoc.parse_arguments(*%w(--no-private))
      expect(@yardoc.options.verifier.call(obj)).to be true
    end

    # @bug gh-197
    it "does not call #tag on namespace if namespace is proxy with --no-private" do
      Registry.clear
      YARD.parse_string "module Qux; class Foo::Bar; end; end"
      foobar = Registry.at('Foo::Bar')
      foobar.namespace.type = :module
      @yardoc.parse_arguments(*%w(--no-private))
      expect(@yardoc.options.verifier.call(foobar)).to be true
    end

    it "does not call #tag on proxy object" do # @bug gh-197
      @yardoc.parse_arguments(*%w(--no-private))
      expect(@yardoc.options.verifier.call(P('ProxyClass'))).to be true
    end

    it "hides methods inside a 'private' class/module with --no-private" do
      Registry.clear
      YARD.parse_string <<-eof
        # @private
        class ABC
          def foo; end
        end
      eof
      @yardoc.parse_arguments(*%w(--no-private))
      expect(@yardoc.options.verifier.call(Registry.at('ABC'))).to be false
      expect(@yardoc.options.verifier.call(Registry.at('ABC#foo'))).to be false
    end
  end

  describe ".yardopts and .document handling" do
    before do
      @yardoc.use_yardopts_file = true
    end

    it "searches for and uses yardopts file specified by #options_file" do
      expect(File).to receive(:read_binary).with("test").and_return("-o \n\nMYPATH\nFILE1 FILE2")
      @yardoc.use_document_file = false
      @yardoc.options_file = "test"
      @yardoc.run
      expect(@yardoc.options.serializer.options[:basepath]).to eq "MYPATH"
      expect(@yardoc.files).to eq ["FILE1", "FILE2"]
    end

    it "uses String#shell_split to split .yardopts tokens" do
      optsdata = String.new("foo bar")
      expect(optsdata).to receive(:shell_split)
      expect(File).to receive(:read_binary).with("test").and_return(optsdata)
      @yardoc.options_file = "test"
      @yardoc.run
    end

    it "allows opts specified in command line to override yardopts file" do
      expect(File).to receive(:read_binary).with(".yardopts").and_return("-o NOTMYPATH")
      @yardoc.run("-o", "MYPATH", "FILE")
      expect(@yardoc.options.serializer.options[:basepath]).to eq "MYPATH"
      expect(@yardoc.files).to eq ["FILE"]
    end

    it "loads the RDoc .document file if found" do
      expect(File).to receive(:read_binary).with(".yardopts").and_return("-o NOTMYPATH")
      @yardoc.use_document_file = true
      allow(@yardoc).to receive(:support_rdoc_document_file!).and_return(["FILE2", "FILE3"])
      @yardoc.run("-o", "MYPATH", "FILE1")
      expect(@yardoc.options.serializer.options[:basepath]).to eq "MYPATH"
      expect(@yardoc.files).to eq ["FILE2", "FILE3", "FILE1"]
    end
  end

  describe "Query options" do
    after { Registry.clear }

    it "hides private constants in with default visibilities" do
      classobj = CodeObjects::ClassObject.new(:root, :Foo) {|o| o.visibility = :private }
      @yardoc.run
      expect(@yardoc.options.verifier.run([classobj])).to eq []
    end

    it "sets up visibility rules as verifier" do
      methobj = CodeObjects::MethodObject.new(:root, :test) {|o| o.visibility = :private }
      expect(File).to receive(:read_binary).with("test").and_return("--private")
      @yardoc.use_yardopts_file = true
      @yardoc.options_file = "test"
      @yardoc.run
      expect(@yardoc.options.verifier.call(methobj)).to be true
    end

    it "accepts a --query" do
      @yardoc.parse_arguments(*%w(--query @return))
      expect(@yardoc.options.verifier).to be_a(Verifier)
    end

    it "accepts multiple --query arguments" do
      obj = double(:object)
      expect(obj).to receive(:tag).ordered.with('return').and_return(true)
      expect(obj).to receive(:tag).ordered.with('tag').and_return(false)
      @yardoc.parse_arguments(*%w(--query @return --query @tag))
      expect(@yardoc.options.verifier).to be_a(Verifier)
      expect(@yardoc.options.verifier.call(obj)).to be false
    end
  end

  describe "Extra file arguments" do
    it "accepts extra files if specified after '-' with source files" do
      expect(Dir).to receive(:glob).with('README{,*[^~]}').and_return([])
      expect(File).to receive(:file?).with('extra_file1').and_return(true)
      expect(File).to receive(:file?).with('extra_file2').and_return(true)
      expect(File).to receive(:read).with('extra_file1').and_return('')
      expect(File).to receive(:read).with('extra_file2').and_return('')
      @yardoc.parse_arguments(*%w(file1 file2 - extra_file1 extra_file2))
      expect(@yardoc.files).to eq %w(file1 file2)
      expect(@yardoc.options.files).to eq(
        [CodeObjects::ExtraFileObject.new('extra_file1', ''),
          CodeObjects::ExtraFileObject.new('extra_file2', '')]
      )
    end

    it "accepts files section only containing extra files" do
      expect(Dir).to receive(:glob).with('README{,*[^~]}').and_return([])
      @yardoc.parse_arguments(*%w(- LICENSE))
      expect(@yardoc.files).to eq Parser::SourceParser::DEFAULT_PATH_GLOB
      expect(@yardoc.options.files).to eq [CodeObjects::ExtraFileObject.new('LICENSE', '')]
    end

    it "accepts globs as extra files" do
      expect(Dir).to receive(:glob).with('README{,*[^~]}').and_return []
      expect(Dir).to receive(:glob).with('*.txt').and_return ['a.txt', 'b.txt']
      expect(File).to receive(:read).with('a.txt').and_return('')
      expect(File).to receive(:read).with('b.txt').and_return('')
      expect(File).to receive(:file?).with('a.txt').and_return(true)
      expect(File).to receive(:file?).with('b.txt').and_return(true)
      @yardoc.parse_arguments(*%w(file1 file2 - *.txt))
      expect(@yardoc.files).to eq %w(file1 file2)
      expect(@yardoc.options.files).to eq(
        [CodeObjects::ExtraFileObject.new('a.txt', ''),
          CodeObjects::ExtraFileObject.new('b.txt', '')]
      )
    end

    it "warns if extra file is not found" do
      expect(log).to receive(:warn).with(/Could not find file: UNKNOWN/)
      @yardoc.parse_arguments(*%w(- UNKNOWN))
    end

    it "warns if readme file is not found" do
      expect(log).to receive(:warn).with(/Could not find file: UNKNOWN/)
      @yardoc.parse_arguments(*%w(-r UNKNOWN))
    end

    it "warns on absolute paths in extra files" do
      expect(log).to receive(:warn).with(%r{Invalid file: /path/to/file})
      @yardoc.parse_arguments(*%w(- /path/to/file))
    end

    it "warns on absolute paths in readme" do
      expect(log).to receive(:warn).with(%r{Invalid file: /path/to/file})
      @yardoc.parse_arguments(*%w(-r /path/to/file))
    end

    it "uses first file as readme if no readme is specified when using --one-file" do
      expect(Dir).to receive(:glob).with('README{,*[^~]}').and_return []
      expect(Dir).to receive(:glob).with('lib/*.rb').and_return(['lib/foo.rb'])
      expect(File).to receive(:read).with('lib/foo.rb').and_return('')
      @yardoc.parse_arguments(*%w(--one-file lib/*.rb))
      expect(@yardoc.options.readme).to eq CodeObjects::ExtraFileObject.new('lib/foo.rb', '')
    end

    it "uses readme it exists when using --one-file" do
      expect(Dir).to receive(:glob).with('README{,*[^~]}').and_return ['README']
      expect(File).to receive(:read).with('README').and_return('')
      @yardoc.parse_arguments(*%w(--one-file lib/*.rb))
      expect(@yardoc.options.readme).to eq CodeObjects::ExtraFileObject.new('README', '')
    end

    it "does not allow US-ASCII charset when using --one-file" do
      ienc = Encoding.default_internal
      eenc = Encoding.default_external
      expect(log).to receive(:warn).with(/not compatible with US-ASCII.*using ASCII-8BIT/)
      @yardoc.parse_arguments(*%w(--one-file --charset us-ascii))
      expect(Encoding.default_internal.name).to eq 'ASCII-8BIT'
      expect(Encoding.default_external.name).to eq 'ASCII-8BIT'
      Encoding.default_internal = ienc
      Encoding.default_external = eenc
    end if defined?(::Encoding)
  end

  describe "Source file arguments" do
    it "accepts no params and parse {lib,app}/**/*.rb ext/**/*.c" do
      @yardoc.parse_arguments
      expect(@yardoc.files).to eq Parser::SourceParser::DEFAULT_PATH_GLOB
    end
  end

  describe "Tags options" do
    def tag_created(switch, factory_method)
      visible_tags = double(:visible_tags)
      expect(visible_tags).to receive(:|).ordered.with([:foo])
      expect(visible_tags).to receive(:-).ordered.with([]).and_return(visible_tags)
      expect(Tags::Library).to receive(:define_tag).with('Foo', :foo, factory_method)
      allow(Tags::Library).to receive(:visible_tags=)
      expect(Tags::Library).to receive(:visible_tags).at_least(1).times.and_return(visible_tags)
      @yardoc.parse_arguments("--#{switch}-tag", 'foo')
    end

    def tag_hidden(tag)
      visible_tags = double(:visible_tags)
      expect(visible_tags).to receive(:|).ordered.with([tag])
      expect(visible_tags).to receive(:-).ordered.with([tag]).and_return([])
      expect(Tags::Library).to receive(:define_tag).with(tag.to_s.capitalize, tag, nil)
      allow(Tags::Library).to receive(:visible_tags=)
      expect(Tags::Library).to receive(:visible_tags).at_least(1).times.and_return(visible_tags)
    end

    it "accepts --tag" do
      expect(Tags::Library).to receive(:define_tag).with('Title of Foo', :foo, nil)
      @yardoc.parse_arguments('--tag', 'foo:Title of Foo')
    end

    it "accepts --tag without title (and default to capitalized tag name)" do
      expect(Tags::Library).to receive(:define_tag).with('Foo', :foo, nil)
      @yardoc.parse_arguments('--tag', 'foo')
    end

    it "only lists tag once if declared twice" do
      visible_tags = []
      allow(Tags::Library).to receive(:define_tag)
      allow(Tags::Library).to receive(:visible_tags).and_return([:foo])
      allow(Tags::Library).to receive(:visible_tags=) {|value| visible_tags = value }
      @yardoc.parse_arguments('--tag', 'foo', '--tag', 'foo')
      expect(visible_tags).to eq [:foo]
    end

    it "accepts --type-tag" do
      tag_created 'type', :with_types
    end

    it "accepts --type-name-tag" do
      tag_created 'type-name', :with_types_and_name
    end

    it "accepts --name-tag" do
      tag_created 'name', :with_name
    end

    it "accepts --title-tag" do
      tag_created 'title', :with_title_and_text
    end

    it "accepts --hide-tag before tag is listed" do
      tag_hidden(:anewfoo)
      @yardoc.parse_arguments('--hide-tag', 'anewfoo', '--tag', 'anewfoo')
    end

    it "accepts --hide-tag after tag is listed" do
      tag_hidden(:anewfoo2)
      @yardoc.parse_arguments('--tag', 'anewfoo2', '--hide-tag', 'anewfoo2')
    end

    it "accepts --transitive-tag" do
      @yardoc.parse_arguments('--transitive-tag', 'foo')
      expect(Tags::Library.transitive_tags).to include(:foo)
    end

    it "accepts --non-transitive-tag" do
      Tags::Library.transitive_tags |= [:foo]
      @yardoc.parse_arguments('--non-transitive-tag', 'foo')
      expect(Tags::Library.transitive_tags).not_to include(:foo)
    end
  end

  describe "Safe mode" do
    before do
      allow(YARD::Config).to receive(:options).and_return(:safe_mode => true)
    end

    it "does not allow --load or -e in safe mode" do
      expect(@yardoc).not_to receive(:require)
      @yardoc.run('--load', 'foo')
      @yardoc.run('-e', 'foo')
    end

    it "does not allow --query in safe mode" do
      @yardoc.run('--query', 'foo')
      expect(@yardoc.options.verifier.expressions).not_to include("foo")
    end

    it "does not allow modifying the template paths" do
      expect(YARD::Templates::Engine).not_to receive(:register_template_path)
      @yardoc.run('-p', 'foo')
      @yardoc.run('--template-path', 'foo')
    end
  end

  describe "Markup Loading" do
    it "loads rdoc markup if no markup is provided" do
      @yardoc.generate = true
      @yardoc.run
      expect(@yardoc.options.markup).to eq :rdoc
    end

    it "loads rdoc markup even when no output is specified" do
      @yardoc.parse_arguments('--no-output')
      expect(@yardoc.options.markup).to eq :rdoc
    end

    it "warns if rdoc cannot be loaded and fallback to :none" do
      mod = YARD::Templates::Helpers::MarkupHelper
      mod.clear_markup_cache
      expect(mod.const_get(:MARKUP_PROVIDERS)).to receive(:[]).with(:rdoc).and_return([{:lib => 'INVALID'}])
      expect(log).to receive(:warn).with(/Could not load default RDoc formatter/)
      allow(@yardoc).to receive(:generate) { @yardoc.options.files = []; true }
      @yardoc.run
      expect(@yardoc.options.markup).to eq :none
      mod.clear_markup_cache
    end

    it "returns an error immediately if markup for any files are missing" do
      mod = YARD::Templates::Helpers::MarkupHelper
      mod.clear_markup_cache
      expect(mod.const_get(:MARKUP_PROVIDERS)).to receive(:[]).with(:markdown).and_return([{:lib => 'INVALID'}])
      expect(log).to receive(:error).with(/Missing 'INVALID' gem for Markdown formatting/)
      files = [CodeObjects::ExtraFileObject.new('test.md', '')]
      allow(@yardoc).to receive(:generate) { @yardoc.options.files = files; true }
      @yardoc.run
      mod.clear_markup_cache
    end

    it "returns an error immediately if markup for any files are missing (file markup specified in attributes)" do
      mod = YARD::Templates::Helpers::MarkupHelper
      mod.clear_markup_cache
      expect(mod.const_get(:MARKUP_PROVIDERS)).to receive(:[]).with(:markdown).and_return([{:lib => 'INVALID'}])
      expect(log).to receive(:error).with(/Missing 'INVALID' gem for Markdown formatting/)
      files = [CodeObjects::ExtraFileObject.new('test', '# @markup markdown')]
      allow(@yardoc).to receive(:generate) { @yardoc.options.files = files; true }
      @yardoc.run
      mod.clear_markup_cache
    end
  end

  describe "#run" do
    it "parses arguments if run() is called" do
      expect(@yardoc).to receive(:parse_arguments)
      @yardoc.run
    end

    it "parses arguments if run(arg1, arg2, ...) is called" do
      expect(@yardoc).to receive(:parse_arguments)
      @yardoc.run('--private', '-p', 'foo')
    end

    it "does not parse arguments if run(nil) is called" do
      expect(@yardoc).not_to receive(:parse_arguments)
      @yardoc.run(nil)
    end

    it "creates processing lock if saving" do
      expect(Registry).to receive(:lock_for_writing).and_yield
      @yardoc.run
    end

    it "does not create processing lock if not saving" do
      expect(Registry).not_to receive(:lock_for_writing)
      @yardoc.run('--no-save')
    end

    context "with --fail-on-warning" do
      it "exits with error status code if a warning occurs" do
        allow(log).to receive(:warned).and_return(true)
        expect { @yardoc.run("--fail-on-warning") }.to raise_error(SystemExit) do |error|
          expect(error).not_to be_success
        end
      end

      it "does not exit if a warning does not occur" do
        allow(log).to receive(:warned).and_return(false)
        expect { @yardoc.run("--fail-on-warning") }.not_to raise_error
      end
    end
  end
end
