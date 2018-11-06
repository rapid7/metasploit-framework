# frozen_string_literal: true

class MyParser < Parser::Base; end

RSpec.shared_examples_for "parser type registration" do
  after do
    Parser::SourceParser.parser_types.delete(:my_parser)
    Parser::SourceParser.parser_type_extensions.delete(:my_parser)
  end
end

RSpec.describe YARD::Parser::SourceParser do
  before do
    Registry.clear
  end

  def parse_list(*list)
    files = list.map do |v|
      filename, source = *v
      allow(File).to receive(:read_binary).with(filename).and_return(source)
      filename
    end
    Parser::SourceParser.send(:parse_in_order, *files)
  end

  def before_list(&block)
    Parser::SourceParser.before_parse_list(&block)
  end

  def after_list(&block)
    Parser::SourceParser.after_parse_list(&block)
  end

  def before_file(&block)
    Parser::SourceParser.before_parse_file(&block)
  end

  def after_file(&block)
    Parser::SourceParser.after_parse_file(&block)
  end

  describe ".before_parse_list" do
    before do
      Parser::SourceParser.before_parse_list_callbacks.clear
      Parser::SourceParser.after_parse_list_callbacks.clear
    end

    it "handles basic callback support" do
      before_list do |files, globals|
        expect(files).to eq ['foo.rb', 'bar.rb']
        expect(globals).to eq OpenStruct.new
      end
      parse_list ['foo.rb', 'foo!'], ['bar.rb', 'class Foo; end']
      expect(Registry.at('Foo')).not_to be nil
    end

    it "supports multiple callbacks" do
      checks = []
      before_list { checks << :one }
      before_list { checks << :two }
      parse_list ['file.rb', ''], ['file2.rb', ''], ['file3.rb', 'class Foo; end']
      expect(Registry.at('Foo')).not_to be nil
      expect(checks).to eq [:one, :two]
    end

    it "cancels parsing if it returns false" do
      checks = []
      before_list { checks << :one }
      before_list { false }
      before_list { checks << :three }
      parse_list ['file.rb', ''], ['file2.rb', ''], ['file3.rb', 'class Foo; end']
      expect(Registry.at('Foo')).to be nil
      expect(checks).to eq [:one]
    end

    it "does not cancel on nil" do
      checks = []
      before_list { checks << :one }
      before_list { nil }
      before_list { checks << :two }
      parse_list ['file.rb', ''], ['file2.rb', ''], ['file3.rb', 'class Foo; end']
      expect(Registry.at('Foo')).not_to be nil
      expect(checks).to eq [:one, :two]
    end

    it "passes in globals" do
      before_list {|_f, g| g.x = 1 }
      before_list {|_f, g| g.x += 1 }
      before_list {|_f, g| g.x += 1 }
      after_list {|_f, g| expect(g.x).to eq 3 }
      parse_list ['file.rb', ''], ['file2.rb', ''], ['file3.rb', 'class Foo; end']
      expect(Registry.at('Foo')).not_to be nil
    end
  end

  describe ".after_parse_list" do
    before do
      Parser::SourceParser.before_parse_list_callbacks.clear
      Parser::SourceParser.after_parse_list_callbacks.clear
    end

    it "handles basic callback support and maintain files/globals" do
      before_list {|_f, g| g.foo = :bar }
      after_list do |files, globals|
        expect(files).to eq ['foo.rb', 'bar.rb']
        expect(globals.foo).to eq :bar
      end
      parse_list ['foo.rb', 'foo!'], ['bar.rb', 'class Foo; end']
      expect(Registry.at('Foo')).not_to be nil
    end

    it "supports multiple callbacks" do
      checks = []
      after_list { checks << :one }
      after_list { checks << :two }
      parse_list ['file.rb', ''], ['file2.rb', ''], ['file3.rb', 'class Foo; end']
      expect(Registry.at('Foo')).not_to be nil
      expect(checks).to eq [:one, :two]
    end

    it "does not cancel parsing if it returns false" do
      checks = []
      after_list { checks << :one }
      after_list { false }
      after_list { checks << :three }
      parse_list ['file.rb', ''], ['file2.rb', ''], ['file3.rb', 'class Foo; end']
      expect(Registry.at('Foo')).not_to be nil
      expect(checks).to eq [:one, :three]
    end
  end

  describe ".before_parse_file" do
    before do
      Parser::SourceParser.before_parse_file_callbacks.clear
      Parser::SourceParser.after_parse_file_callbacks.clear
    end

    it "handles basic callback support" do
      before_file do |parser|
        expect(parser.contents).to eq 'class Foo; end'
        expect(parser.file).to match(/(foo|bar)\.rb/)
      end
      parse_list ['foo.rb', 'class Foo; end'], ['bar.rb', 'class Foo; end']
      expect(Registry.at('Foo')).not_to be nil
    end

    it "supports multiple callbacks" do
      checks = []
      before_file { checks << :one }
      before_file { checks << :two }
      parse_list ['file.rb', ''], ['file2.rb', ''], ['file3.rb', 'class Foo; end']
      expect(Registry.at('Foo')).not_to be nil
      expect(checks).to eq [:one, :two, :one, :two, :one, :two]
    end

    it "cancels parsing if it returns false" do
      checks = []
      before_file { checks << :one }
      before_file { false }
      before_file { checks << :three }
      parse_list ['file.rb', ''], ['file2.rb', ''], ['file3.rb', 'class Foo; end']
      expect(Registry.at('Foo')).to be nil
      expect(checks).to eq [:one, :one, :one]
    end

    it "does not cancel on nil" do
      checks = []
      before_file { checks << :one }
      before_file { nil }
      before_file { checks << :two }
      parse_list ['file.rb', ''], ['file2.rb', ''], ['file3.rb', 'class Foo; end']
      expect(Registry.at('Foo')).not_to be nil
      expect(checks).to eq [:one, :two, :one, :two, :one, :two]
    end
  end

  describe ".after_parse_file" do
    before do
      Parser::SourceParser.before_parse_file_callbacks.clear
      Parser::SourceParser.after_parse_file_callbacks.clear
    end

    it "handles basic callback support" do
      after_file do |parser|
        expect(parser.contents).to eq 'class Foo; end'
        expect(parser.file).to match(/(foo|bar)\.rb/)
      end
      parse_list ['foo.rb', 'class Foo; end'], ['bar.rb', 'class Foo; end']
      expect(Registry.at('Foo')).not_to be nil
    end

    it "supports multiple callbacks" do
      checks = []
      after_file { checks << :one }
      after_file { checks << :two }
      parse_list ['file.rb', ''], ['file2.rb', ''], ['file3.rb', 'class Foo; end']
      expect(Registry.at('Foo')).not_to be nil
      expect(checks).to eq [:one, :two, :one, :two, :one, :two]
    end

    it "does not cancel parsing if it returns false" do
      checks = []
      after_file { checks << :one }
      after_file { false }
      after_file { checks << :three }
      parse_list ['file.rb', ''], ['file2.rb', ''], ['file3.rb', 'class Foo; end']
      expect(Registry.at('Foo')).not_to be nil
      expect(checks).to eq [:one, :three, :one, :three, :one, :three]
    end
  end

  describe ".register_parser_type" do
    it_should_behave_like "parser type registration"

    it "registers a subclass of Parser::Base" do
      parser = double(:parser)
      expect(parser).to receive(:parse)
      expect(MyParser).to receive(:new).with('content', '(stdin)').and_return(parser)
      Parser::SourceParser.register_parser_type(:my_parser, MyParser, 'myparser')
      Parser::SourceParser.parse_string('content', :my_parser)
    end

    it "requires class to be a subclass of Parser::Base" do
      expect { Parser::SourceParser.register_parser_type(:my_parser, String) }.to raise_error(ArgumentError)
      expect { Parser::SourceParser.register_parser_type(:my_parser, Parser::Base) }.to raise_error(ArgumentError)
    end
  end

  describe ".parser_type_for_extension" do
    it_should_behave_like "parser type registration"

    it "finds an extension in a registered array of extensions" do
      Parser::SourceParser.register_parser_type(:my_parser, MyParser, ['a', 'b', 'd'])
      expect(Parser::SourceParser.parser_type_for_extension('a')).to eq :my_parser
      expect(Parser::SourceParser.parser_type_for_extension('b')).to eq :my_parser
      expect(Parser::SourceParser.parser_type_for_extension('d')).to eq :my_parser
      expect(Parser::SourceParser.parser_type_for_extension('c')).not_to eq :my_parser
    end

    it "finds an extension in a Regexp" do
      Parser::SourceParser.register_parser_type(:my_parser, MyParser, /abc$/)
      expect(Parser::SourceParser.parser_type_for_extension('dabc')).to eq :my_parser
      expect(Parser::SourceParser.parser_type_for_extension('dabcd')).not_to eq :my_parser
    end

    it "finds an extension in a list of Regexps" do
      Parser::SourceParser.register_parser_type(:my_parser, MyParser, [/ab$/, /abc$/])
      expect(Parser::SourceParser.parser_type_for_extension('dabc')).to eq :my_parser
      expect(Parser::SourceParser.parser_type_for_extension('dabcd')).not_to eq :my_parser
    end

    it "finds an extension in a String" do
      Parser::SourceParser.register_parser_type(:my_parser, MyParser, "abc")
      expect(Parser::SourceParser.parser_type_for_extension('abc')).to eq :my_parser
      expect(Parser::SourceParser.parser_type_for_extension('abcd')).not_to eq :my_parser
    end
  end

  describe "#parse_string" do
    it "parses basic Ruby code" do
      YARD.parse_string(<<-eof)
        module Hello
          class Hi
            # Docstring
            # Docstring2
            def me; "VALUE" end
          end
        end
      eof
      expect(Registry.at(:Hello)).not_to eq nil
      expect(Registry.at("Hello::Hi#me")).not_to eq nil
      expect(Registry.at("Hello::Hi#me").docstring).to eq "Docstring\nDocstring2"
      expect(Registry.at("Hello::Hi#me").docstring.line_range).to eq(3..4)
    end

    it "parses Ruby code with metaclasses" do
      YARD.parse_string(<<-eof)
        module Hello
          class Hi
            class <<self
              # Docstring
              def me; "VALUE" end
            end
          end
        end
      eof
      expect(Registry.at(:Hello)).not_to eq nil
      expect(Registry.at("Hello::Hi.me")).not_to eq nil
      expect(Registry.at("Hello::Hi.me").docstring).to eq "Docstring"
    end

    it "only uses prepended comments for an object" do
      YARD.parse_string(<<-eof)
        # Test

        # PASS
        module Hello
        end # FAIL
      eof
      expect(Registry.at(:Hello).docstring).to eq "PASS"
    end

    it "does not add comments appended to last line of block" do
      YARD.parse_string <<-eof
        module Hello2
        end # FAIL
      eof
      expect(Registry.at(:Hello2).docstring).to be_blank
    end

    it "adds comments appended to an object's first line" do
      YARD.parse_string <<-eof
        module Hello # PASS
          HELLO
        end

        module Hello2 # PASS
          # ANOTHER PASS
          def x; end
        end
      eof

      expect(Registry.at(:Hello).docstring).to eq "PASS"
      expect(Registry.at(:Hello2).docstring).to eq "PASS"
      expect(Registry.at('Hello2#x').docstring).to eq "ANOTHER PASS"
    end

    it "takes preceding comments only if they exist" do
      YARD.parse_string <<-eof
        # PASS
        module Hello # FAIL
          HELLO
        end
      eof

      expect(Registry.at(:Hello).docstring).to eq "PASS"
    end

    it "strips all hashes prefixed on comment line" do
      YARD.parse_string(<<-eof)
        ### PASS
        #### PASS
        ##### PASS
        module Hello
        end
      eof
      expect(Registry.at(:Hello).docstring).to eq "PASS\nPASS\nPASS"
    end

    it "handles =begin/=end style comments" do
      YARD.parse_string "=begin\nfoo\nbar\n=end\nclass Foo; end\n"
      expect(Registry.at(:Foo).docstring).to eq "foo\nbar"

      YARD.parse_string "=begin\n\nfoo\nbar\n=end\nclass Foo; end\n"
      expect(Registry.at(:Foo).docstring).to eq "foo\nbar"

      YARD.parse_string "=begin\nfoo\n\nbar\n=end\nclass Foo; end\n"
      expect(Registry.at(:Foo).docstring).to eq "foo\n\nbar"
    end

    it "knows about docstrings starting with ##" do
      {'#' => false, '##' => true}.each do |hash, expected|
        YARD.parse_string "#{hash}\n# Foo bar\nclass Foo; end"
        expect(Registry.at(:Foo).docstring.hash_flag).to eq expected
      end
    end

    it "removes shebang from initial file comments" do
      YARD.parse_string "#!/bin/ruby\n# this is a comment\nclass Foo; end"
      expect(Registry.at(:Foo).docstring).to eq "this is a comment"
    end

    it "removes encoding line from initial file comments" do
      YARD.parse_string "# encoding: utf-8\n# this is a comment\nclass Foo; end"
      expect(Registry.at(:Foo).docstring).to eq "this is a comment"
    end

    it "adds macros on any object" do
      YARD.parse_string <<-eof
        # @!macro [new] foo
        #   This is a macro
        #   @return [String] the string
        class Foo
          # @!macro foo
          def foo; end
        end
      eof

      macro = CodeObjects::MacroObject.find('foo')
      expect(macro.macro_data).to eq "This is a macro\n@return [String] the string"
      expect(Registry.at('Foo').docstring.to_raw).to eq  macro.macro_data
      expect(Registry.at('Foo#foo').docstring.to_raw).to eq macro.macro_data
    end

    it "allows directives parsed on lone comments" do
      YARD.parse_string(<<-eof)
        class Foo
          # @!method foo(a = "hello")
          # @!scope class
          # @!visibility private
          # @param [String] a the name of the foo
          # @return [Symbol] the symbolized foo

          # @!method bar(value)
        end
      eof
      foo = Registry.at('Foo.foo')
      bar = Registry.at('Foo#bar')
      expect(foo).not_to be nil
      expect(foo.visibility).to eq :private
      expect(foo.tag(:param).name).to eq 'a'
      expect(foo.tag(:return).types).to eq ['Symbol']
      expect(bar).not_to be nil
      expect(bar.signature).to eq 'def bar(value)'
    end

    it "parses lone comments at end of blocks" do
      YARD.parse_string(<<-eof)
        class Foo
          none

          # @!method foo(a = "hello")
        end
      eof
      foo = Registry.at('Foo#foo')
      expect(foo).not_to be nil
      expect(foo.signature).to eq 'def foo(a = "hello")'
    end

    it "handles lone comment with no code" do
      YARD.parse_string '# @!method foo(a = "hello")'
      foo = Registry.at('#foo')
      expect(foo).not_to be nil
      expect(foo.signature).to eq 'def foo(a = "hello")'
    end

    it "handles non-ASCII encoding in heredoc" do
      YARD.parse_string <<-eof
        # encoding: utf-8

        heredoc <<-ending
          foo\u{ffe2} bar.
        ending

        # Hello \u{ffe2} world
        class Foo < Bar
          attr_accessor :foo
        end
      eof
      expect(Registry.at('Foo').superclass).to eq P('Bar')
    end
  end

  describe "#parse" do
    it "parses a basic Ruby file" do
      parse_file :example1, __FILE__
      expect(Registry.at(:Hello)).not_to eq nil
      expect(Registry.at("Hello::Hi#me")).not_to eq nil
      expect(Registry.at("Hello::Hi#me").docstring).to eq "Docstring"
    end

    it "parses a set of file globs" do
      expect(Dir).to receive(:[]).with('lib/**/*.rb').and_return([])
      YARD.parse('lib/**/*.rb')
    end

    it "parses a set of absolute paths" do
      expect(Dir).not_to receive(:[])
      expect(File).to receive(:file?).with('/path/to/file').and_return(true)
      expect(File).to receive(:read_binary).with('/path/to/file').and_return("")
      YARD.parse('/path/to/file')
    end

    it "cleans paths before parsing" do
      expect(File).to receive(:open).and_return("")
      parser = Parser::SourceParser.new(:ruby, true)
      parser.parse('a//b//c')
      expect(parser.file).to eq 'a/b/c'
    end

    it "parses files with '*' in them as globs and others as absolute paths" do
      expect(Dir).to receive(:[]).with('*.rb').and_return(['a.rb', 'b.rb'])
      expect(File).to receive(:file?).with('/path/to/file').and_return(true)
      expect(File).to receive(:file?).with('a.rb').and_return(true)
      expect(File).to receive(:file?).with('b.rb').and_return(true)
      expect(File).to receive(:read_binary).with('/path/to/file').and_return("")
      expect(File).to receive(:read_binary).with('a.rb').and_return("")
      expect(File).to receive(:read_binary).with('b.rb').and_return("")
      YARD.parse ['/path/to/file', '*.rb']
    end

    it "converts directories into globs" do
      expect(Dir).to receive(:[]).with('foo/**/*.{rb,c,cc,cxx,cpp}').and_return(['foo/a.rb', 'foo/bar/b.rb'])
      expect(File).to receive(:directory?).with('foo').and_return(true)
      expect(File).to receive(:file?).with('foo/a.rb').and_return(true)
      expect(File).to receive(:file?).with('foo/bar/b.rb').and_return(true)
      expect(File).to receive(:read_binary).with('foo/a.rb').and_return("")
      expect(File).to receive(:read_binary).with('foo/bar/b.rb').and_return("")
      YARD.parse ['foo']
    end

    it "uses Registry.checksums cache if file is cached" do
      data = 'DATA'
      hash = Registry.checksum_for(data)
      cmock = double(:cmock)
      expect(cmock).to receive(:[]).with('foo/bar').and_return(hash)
      expect(Registry).to receive(:checksums).and_return(cmock)
      expect(File).to receive(:file?).with('foo/bar').and_return(true)
      expect(File).to receive(:read_binary).with('foo/bar').and_return(data)
      YARD.parse('foo/bar')
    end

    it "supports excluded paths" do
      expect(File).to receive(:file?).with('foo/bar').and_return(true)
      expect(File).to receive(:file?).with('foo/baz').and_return(true)
      expect(File).not_to receive(:read_binary)
      YARD.parse(["foo/bar", "foo/baz"], ["foo", /baz$/])
    end

    it "converts file contents to proper encoding if coding line is present" do
      valid = []
      valid << "# encoding: sjis"
      valid << "# encoding: utf-8"
      valid << "# xxxxxencoding: sjis"
      valid << "# xxxxxencoding: sjis xxxxxx"
      valid << "# ENCODING: sjis"
      valid << "#coDiNG: sjis"
      valid << "# -*- coding: sjis -*-"
      valid << "# -*- coding: utf-8; indent-tabs-mode: nil"
      valid << "### coding: sjis"
      valid << "# encoding=sjis"
      valid << "# encoding:sjis"
      valid << "# encoding   =   sjis"
      valid << "# encoding   ==   sjis"
      valid << "# encoding :  sjis"
      valid << "# encoding ::  sjis"
      valid << "#!/bin/shebang\n# encoding: sjis"
      valid << "#!/bin/shebang\r\n# coding: sjis"
      invalid = []
      invalid << "#\n# encoding: sjis"
      invalid << "#!/bin/shebang\n#\n# encoding: sjis"
      invalid << "# !/bin/shebang\n# encoding: sjis"
      {:to => valid, :not_to => invalid}.each do |msg, list|
        list.each do |src|
          Registry.clear
          parser = Parser::SourceParser.new
          expect(File).to receive(:read_binary).with('tmpfile').and_return(src)
          result = parser.parse("tmpfile")
          if HAVE_RIPPER && YARD.ruby19?
            if msg == :not_to
              default_encoding = 'UTF-8'
              expect(result.enumerator[0].source.encoding.to_s).to eq(default_encoding)
            else
              expect(['Shift_JIS', 'Windows-31J', 'UTF-8']).send(msg,
                include(result.enumerator[0].source.encoding.to_s))
            end
          end
          expect(result.encoding_line).send(msg, eq(src.split("\n").last))
        end
      end
    end

    it "converts C file contents to proper encoding if coding line is present" do
      valid = []
      valid << "/* coding: utf-8 */"
      valid << "/* -*- coding: utf-8; c-file-style: \"ruby\" -*- */"
      valid << "// coding: utf-8"
      valid << "// -*- coding: utf-8; c-file-style: \"ruby\" -*-"
      invalid = []
      {:to => valid, :not_to => invalid}.each do |msg, list|
        list.each do |src|
          Registry.clear
          parser = Parser::SourceParser.new
          expect(File).to receive(:read_binary).with('tmpfile.c').and_return(src)
          result = parser.parse("tmpfile.c")
          content = result.instance_variable_get("@content")
          expect(['UTF-8']).send(msg, include(content.encoding.to_s))
        end
      end
    end if YARD.ruby19?

    Parser::SourceParser::ENCODING_BYTE_ORDER_MARKS.each do |encoding, bom|
      it "understands #{encoding.upcase} BOM" do
        parser = Parser::SourceParser.new
        src = bom + String.new("class FooBar; end").force_encoding('binary')
        src.force_encoding('binary')
        expect(File).to receive(:read_binary).with('tmpfile').and_return(src)
        result = parser.parse('tmpfile')
        expect(Registry.all(:class).first.path).to eq "FooBar"
        expect(result.enumerator[0].source.encoding.to_s.downcase).to eq encoding
      end
    end if HAVE_RIPPER && YARD.ruby19?
  end

  describe "#parse_in_order" do
    def in_order_parse(*files)
      paths = files.map {|f| File.join(File.dirname(__FILE__), 'examples', f.to_s + '.rb.txt') }
      YARD::Parser::SourceParser.parse(paths, [], Logger::DEBUG)
    end

    it "attempts to parse files in order" do
      log.enter_level(Logger::DEBUG) do
        msgs = []
        expect(log).to receive(:debug) {|m| msgs << m }.at_least(:once)
        allow(log).to receive(:<<)
        in_order_parse 'parse_in_order_001', 'parse_in_order_002'
        expect(msgs[1]).to match(/Parsing .+parse_in_order_001.+/)
        expect(msgs[2]).to match(/Missing object MyModule/)
        expect(msgs[3]).to match(/Parsing .+parse_in_order_002.+/)
        expect(msgs[4]).to match(/Re-processing .+parse_in_order_001.+/)
      end
    end

    it "attempts to order files by length for globs (process toplevel files first)" do
      files = %w(a a/b a/b/c)
      files.each do |file|
        expect(File).to receive(:file?).with(file).and_return(true)
        expect(File).to receive(:read_binary).with(file).ordered.and_return('')
      end
      expect(Dir).to receive(:[]).with('a/**/*').and_return(files.reverse)
      YARD.parse 'a/**/*'
    end

    it "allows overriding of length sorting when single file is presented" do
      files = %w(a/b/c a a/b)
      files.each do |file|
        expect(File).to receive(:file?).with(file).at_least(1).times.and_return(true)
        expect(File).to receive(:read_binary).with(file).ordered.and_return('')
      end
      expect(Dir).to receive(:[]).with('a/**/*').and_return(files.reverse)
      YARD.parse ['a/b/c', 'a/**/*']
    end
  end

  describe "#parse_statements" do
    before do
      Registry.clear
    end

    it "displays a warning for invalid parser type" do
      expect(log).to receive(:warn).with(/unrecognized file/)
      expect(log).to receive(:backtrace)
      YARD::Parser::SourceParser.parse_string("int main() { }", :d)
    end

    if HAVE_RIPPER
      it "displays a warning for a syntax error (with new parser)" do
        expect(log).to receive(:warn).with(/Syntax error in/)
        expect(log).to receive(:backtrace)
        YARD::Parser::SourceParser.parse_string("%!!!", :ruby)
      end
    end

    it "handles groups" do
      YARD.parse_string <<-eof
        class A
          # @group Group Name
          def foo; end
          def foo2; end

          # @endgroup

          def bar; end

          # @group Group 2
          def baz; end
        end
      eof

      expect(Registry.at('A').groups).to eq ['Group Name', 'Group 2']
      expect(Registry.at('A#bar').group).to be nil
      expect(Registry.at('A#foo').group).to eq "Group Name"
      expect(Registry.at('A#foo2').group).to eq "Group Name"
      expect(Registry.at('A#baz').group).to eq "Group 2"
    end

    it "handles multi-line class/module references" do
      YARD.parse_string <<-eof
        class A::
          B::C; end
      eof
      expect(Registry.all).to eq [P('A::B::C')]
    end

    it "handles sclass definitions of multi-line class/module references" do
      YARD.parse_string <<-eof
        class << A::
          B::C
          def foo; end
        end
      eof
      expect(Registry.all.size).to eq 2
      expect(Registry.at('A::B::C')).not_to be nil
      expect(Registry.at('A::B::C.foo')).not_to be nil
    end

    it "handles lone comment blocks at the end of a namespace" do
      YARD.parse_string <<-eof
        module A
          class B
            def c; end

            # @!method d
          end
        end
      eof
      expect(Registry.at('A#d')).to be nil
      expect(Registry.at('A::B#d')).not_to be nil
    end

    if YARD.ruby2?
      it "supports named arguments with default values" do
        YARD.parse_string 'def foo(a, b = 1, *c, d, e: 3, **f, &g) end'
        args = [['a', nil], ['b', '1'], ['*c', nil], ['d', nil], ['e:', '3'], ['**f', nil], ['&g', nil]]
        expect(Registry.at('#foo').parameters).to eq(args)
      end
    end

    if NAMED_OPTIONAL_ARGUMENTS && !LEGACY_PARSER
      it "supports named arguments without default values" do
        YARD.parse_string 'def foo(a, b = 1, *c, d, e: 3, f:, **g, &h) end'
        args = [['a', nil], ['b', '1'], ['*c', nil], ['d', nil], ['e:', '3'], ['f:', nil], ['**g', nil], ['&h', nil]]
        expect(Registry.at('#foo').parameters).to eq(args)
      end
    end
  end
end
