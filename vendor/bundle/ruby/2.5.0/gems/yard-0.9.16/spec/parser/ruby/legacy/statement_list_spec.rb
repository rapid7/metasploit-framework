# frozen_string_literal: true

RSpec.describe YARD::Parser::Ruby::Legacy::StatementList do
  def stmts(code) YARD::Parser::Ruby::Legacy::StatementList.new(code) end
  def stmt(code) stmts(code).first end

  it "parses dangling block expressions" do
    s = stmt <<-eof
      if
          foo
        puts 'hi'
      end
eof

    expect(s.tokens.to_s(true)).to eq "if\n          foo\n        ...\n      end"
    expect(s.tokens.to_s).to eq "if\n          foo"
    expect(s.block.to_s).to eq "puts 'hi'"

    s = stmt <<-eof
      if foo ||
          bar
        puts 'hi'
      end
eof

    expect(s.tokens.to_s(true)).to eq "if foo ||\n          bar\n        ...\n      end"
    expect(s.tokens.to_s).to eq "if foo ||\n          bar"
    expect(s.block.to_s).to eq "puts 'hi'"
  end

  it "allows semicolons within parentheses" do
    s = stmt "(foo; bar)"

    expect(s.tokens.to_s(true)).to eq "(foo; bar)"
    expect(s.block).to be nil
  end

  it "allows for non-block statements" do
    s = stmt "hello_world(1, 2, 3)"
    expect(s.tokens.to_s).to eq "hello_world(1, 2, 3)"
    expect(s.block).to be nil
  end

  it "allows block statements to be used as part of other block statements" do
    s = stmt "while (foo; bar); foo = 12; end; while"

    expect(s.tokens.to_s(true)).to eq "while (foo; bar); ... end"
    expect(s.tokens.to_s).to eq "while (foo; bar)"
    expect(s.block.to_s).to eq "foo = 12"
  end

  it "allows continued processing after a block" do
    s = stmt "if foo; end.stuff"
    expect(s.tokens.to_s(true)).to eq "if foo; end.stuff"
    expect(s.block.to_s).to eq ""

    s = stmt "if foo; end[stuff]"
    expect(s.tokens.to_s(true)).to eq "if foo; end[stuff]"
    expect(s.block.to_s).to eq ""

    s = stmt "if foo; hi end.map do; 123; end"
    expect(s.tokens.to_s(true)).to eq "if foo; ... end.map do; 123; end"
    expect(s.block.to_s).to eq "hi"
  end

  it "parses default arguments" do
    s = stmt "def foo(bar, baz = 1, bang = 2); bar; end"
    expect(s.tokens.to_s(true)).to eq "def foo(bar, baz = 1, bang = 2) ... end"
    expect(s.block.to_s).to eq "bar"

    s = stmt "def foo bar, baz = 1, bang = 2; bar; end"
    expect(s.tokens.to_s(true)).to eq "def foo bar, baz = 1, bang = 2; ... end"
    expect(s.block.to_s).to eq "bar"

    s = stmt "def foo bar , baz = 1 , bang = 2; bar; end"
    expect(s.tokens.to_s(true)).to eq "def foo bar , baz = 1 , bang = 2; ... end"
    expect(s.block.to_s).to eq "bar"
  end

  it "parses complex default arguments" do
    s = stmt "def foo(bar, baz = File.new(1, 2), bang = 3); bar; end"
    expect(s.tokens.to_s(true)).to eq "def foo(bar, baz = File.new(1, 2), bang = 3) ... end"
    expect(s.block.to_s).to eq "bar"

    s = stmt "def foo bar, baz = File.new(1, 2), bang = 3; bar; end"
    expect(s.tokens.to_s(true)).to eq "def foo bar, baz = File.new(1, 2), bang = 3; ... end"
    expect(s.block.to_s).to eq "bar"

    s = stmt "def foo bar , baz = File.new(1, 2) , bang = 3; bar; end"
    expect(s.tokens.to_s(true)).to eq "def foo bar , baz = File.new(1, 2) , bang = 3; ... end"
    expect(s.block.to_s).to eq "bar"
  end

  it "parses blocks with do/end" do
    s = stmt <<-eof
      foo do
        puts 'hi'
      end
    eof

    expect(s.tokens.to_s(true)).to eq "foo do\n        ...\n      end"
    expect(s.block.to_s).to eq "puts 'hi'"
  end

  it "parses blocks with {}" do
    s = stmt "x { y }"
    expect(s.tokens.to_s(true)).to eq "x { ... }"
    expect(s.block.to_s).to eq "y"

    s = stmt "x() { y }"
    expect(s.tokens.to_s(true)).to eq "x() { ... }"
    expect(s.block.to_s).to eq "y"
  end

  it "parses blocks with begin/end" do
    s = stmt "begin xyz end"
    expect(s.tokens.to_s(true)).to eq "begin ... end"
    expect(s.block.to_s).to eq "xyz"
  end

  it "parses nested blocks" do
    s = stmt "foo(:x) { baz(:y) { skippy } }"

    expect(s.tokens.to_s(true)).to eq "foo(:x) { ... }"
    expect(s.block.to_s).to eq "baz(:y) { skippy }"
  end

  it "does not parse hashes as blocks" do
    s = stmt "x({})"
    expect(s.tokens.to_s(true)).to eq "x({})"
    expect(s.block.to_s).to eq ""

    s = stmt "x = {}"
    expect(s.tokens.to_s(true)).to eq "x = {}"
    expect(s.block.to_s).to eq ""

    s = stmt "x(y, {})"
    expect(s.tokens.to_s(true)).to eq "x(y, {})"
    expect(s.block.to_s).to eq ""
  end

  it "parses hashes in blocks with {}" do
    s = stmt "x {x = {}}"

    expect(s.tokens.to_s(true)).to eq "x {...}"
    expect(s.block.to_s).to eq "x = {}"
  end

  it "parses blocks with {} in hashes" do
    s = stmt "[:foo, x {}]"

    expect(s.tokens.to_s(true)).to eq "[:foo, x {}]"
    expect(s.block.to_s).to eq ""
  end

  it "handles multiple methods" do
    s = stmt <<-eof
      def %; end
      def b; end
    eof
    expect(s.to_s).to eq "def %; end"
  end

  it "handles nested methods" do
    s = stmt <<-eof
      def *(o) def +@; end
        def ~@
        end end
    eof
    expect(s.tokens.to_s(true)).to eq "def *(o) ... end"
    expect(s.block.to_s).to eq "def +@; end\n        def ~@\n        end"

    s = stmts(<<-eof)
      def /(other) 'hi' end
      def method1
        def dynamic; end
      end
    eof
    expect(s[1].to_s).to eq "def method1\n        def dynamic; end\n      end"
  end

  it "gets comment line numbers" do
    s = stmt <<-eof
      # comment
      # comment
      # comment
      def method; end
    eof
    expect(s.comments).to eq ["comment", "comment", "comment"]
    expect(s.comments_range).to eq(1..3)

    s = stmt <<-eof

      # comment
      # comment
      def method; end
    eof
    expect(s.comments).to eq ["comment", "comment"]
    expect(s.comments_range).to eq(2..3)

    s = stmt <<-eof
      # comment
      # comment

      def method; end
    eof
    expect(s.comments).to eq ["comment", "comment"]
    expect(s.comments_range).to eq(1..2)

    s = stmt <<-eof
      # comment
      def method; end
    eof
    expect(s.comments).to eq ["comment"]
    expect(s.comments_range).to eq(1..1)

    s = stmt <<-eof
      def method; end # comment
    eof
    expect(s.comments).to eq ["comment"]
    expect(s.comments_range).to eq(1..1)
  end

  it "only looks up to two lines back for comments" do
    s = stmt <<-eof
      # comments

      # comments

      def method; end
    eof
    expect(s.comments).to eq ["comments"]

    s = stmt <<-eof
      # comments


      def method; end
    eof
    expect(s.comments).to eq nil

    ss = stmts <<-eof
      # comments


      def method; end

      # hello
      def method2; end
    eof
    expect(ss[0].comments).to eq nil
    expect(ss[1].comments).to eq ['hello']
  end

  it "handles CRLF (Windows) newlines" do
    s = stmts("require 'foo'\r\n\r\n# Test Test\r\n# \r\n# Example:\r\n#   example code\r\ndef test\r\nend\r\n")
    expect(s[1].comments).to eq ['Test Test', '', 'Example:', '  example code']
  end

  it "handles elsif blocks" do
    s = stmts(stmt("if 0\n  foo\nelsif 2\n  bar\nend\nbaz").block)
    expect(s.size).to eq 2
    expect(s[1].tokens.to_s).to eq "elsif 2"
    expect(s[1].block.to_s).to eq "bar"
  end

  it "handles else blocks" do
    s = stmts(stmt("if 0\n  foo\nelse\n  bar\nend\nbaz").block)
    expect(s.size).to eq 2
    expect(s[1].tokens.to_s).to eq "else"
    expect(s[1].block.to_s).to eq "bar"
  end

  it "allows aliasing keywords" do
    ['do x', 'x do', 'end begin', 'begin end'].each do |a|
      s = stmt("alias #{a}\ndef foo; end")
      expect(s.tokens.to_s).to eq "alias #{a}"
      expect(s.block).to be nil
    end

    s = stmt("alias do x if 2 ==\n 2")
    expect(s.tokens.to_s).to eq "alias do x if 2 ==\n 2"
  end

  it "does not open a block on an aliased keyword block opener" do
    s = stmts(<<-eof)
      class A; alias x do end
      class B; end
    eof
    expect(s[0].block.to_s).to eq 'alias x do'
    expect(s.size).to be > 1
  end

  it "converts heredoc to string" do
    src = "<<-XML\n  foo\n\nXML"
    s = stmt(src)
    expect(s.source).to eq '"foo\n\n"'
  end
end
