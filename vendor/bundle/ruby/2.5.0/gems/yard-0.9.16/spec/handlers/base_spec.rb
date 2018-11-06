# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'
require 'ostruct'

include Parser

RSpec.describe YARD::Handlers::Base do
  describe "#handles and inheritance" do
    before do
      allow(Handlers::Base).to receive(:inherited)
    end

    it "keeps track of subclasses" do
      expect(Handlers::Base).to receive(:inherited).once
      class TestHandler < Handlers::Base; end
    end

    it "raises NotImplementedError if process is called on a class with no #process" do
      class TestNotImplementedHandler < Handlers::Base
      end

      expect { TestNotImplementedHandler.new(0, 0).process }.to raise_error(NotImplementedError)
    end

    it "allows multiple handles arguments" do
      expect(Handlers::Base).to receive(:inherited).once
      class TestHandler1 < Handlers::Base
        handles :a, :b, :c
      end
      expect(TestHandler1.handlers).to eq [:a, :b, :c]
    end

    it "allows multiple handles calls" do
      expect(Handlers::Base).to receive(:inherited).once
      class TestHandler2 < Handlers::Base
        handles :a
        handles :b
        handles :c
      end
      expect(TestHandler2.handlers).to eq [:a, :b, :c]
    end
  end

  describe "#abort! (and HandlerAborted)" do
    it "allows HandlerAborted to be raised" do
      class AbortHandler1 < Handlers::Ruby::Base
        process { abort! }
      end
      expect { AbortHandler1.new(nil, nil).process }.to raise_error(HandlerAborted)
    end
  end

  describe "transitive tags" do
    it "adds transitive tags to children" do
      Registry.clear
      YARD.parse_string <<-eof
        # @since 1.0
        # @author Foo
        class A
          def foo; end
          # @since 1.1
          def bar; end
        end
      eof
      expect(Registry.at('A').tag(:since).text).to eq "1.0"
      expect(Registry.at('A#foo').tag(:since).text).to eq "1.0"
      expect(Registry.at('A#bar').tag(:since).text).to eq "1.1"
      expect(Registry.at('A#bar').tag(:author)).to be nil
    end
  end

  describe "sharing global state" do
    it "allows globals to share global state among handlers" do
      class GlobalStateHandler1 < Handlers::Ruby::Base
        class << self; attr_accessor :state end
        handles :class
        process { self.class.state = globals.foo; globals.foo = :bar }
      end

      class GlobalStateHandler2 < Handlers::Ruby::Base
        class << self; attr_accessor :state end
        handles :def
        process { self.class.state = globals.foo }
      end

      2.times do
        YARD.parse_string 'class Foo; end; def foo; end'
        expect(GlobalStateHandler1.state).to eq nil
        expect(GlobalStateHandler2.state).to eq :bar
      end
    end
  end if HAVE_RIPPER

  describe "#push_state" do
    def process(klass)
      state = OpenStruct.new(:namespace => "ROOT", :scope => :instance, :owner => "ROOT")
      klass.new(state, nil).process
    end

    it "pushes and return all old state info after block" do
      class PushStateHandler1 < Handlers::Base
        include RSpec::Matchers
        RSpec::Expectations::Syntax.enable_expect(self)

        def process
          push_state(:namespace => "FOO", :scope => :class, :owner => "BAR") do
            expect(namespace).to eq "FOO"
            expect(scope).to eq :class
            expect(owner).to eq "BAR"
          end
          expect(namespace).to eq "ROOT"
          expect(owner).to eq "ROOT"
          expect(scope).to eq :instance
        end
      end
      process PushStateHandler1
    end

    it "allows owner to be pushed individually" do
      class PushStateHandler2 < Handlers::Base
        include RSpec::Matchers
        RSpec::Expectations::Syntax.enable_expect(self)

        def process
          push_state(:owner => "BAR") do
            expect(namespace).to eq "ROOT"
            expect(scope).to eq :instance
            expect(owner).to eq "BAR"
          end
          expect(owner).to eq "ROOT"
        end
      end
      process PushStateHandler2
    end

    it "allows scope to be pushed individually" do
      class PushStateHandler3 < Handlers::Base
        include RSpec::Matchers
        RSpec::Expectations::Syntax.enable_expect(self)

        def process
          push_state(:scope => :foo) do
            expect(namespace).to eq "ROOT"
            expect(scope).to eq :foo
            expect(owner).to eq "ROOT"
          end
          expect(scope).to eq :instance
        end
      end
      process PushStateHandler3
    end
  end

  describe ".in_file" do
    def parse(filename, parser_type, src = "class A; end")
      parser = Parser::SourceParser.new(parser_type)
      parser.instance_variable_set("@file", filename)
      parser.parse(StringIO.new(src))
    end

    def create_handler(stmts, parser_type)
      $handler_counter ||= 0
      sklass = parser_type == :ruby ? "Base" : "Legacy::Base"
      instance_eval(<<-eof, __FILE__, __LINE__ + 1)
        class ::InFileHandler#{$handler_counter += 1} < Handlers::Ruby::#{sklass}
          handles(/^class/)
          #{stmts}
          def process; MethodObject.new(:root, :FOO) end
        end
      eof
    end

    def test_handler(file, stmts, creates = true, parser_type = :ruby)
      Registry.clear
      expect(Registry.at('#FOO')).to be nil
      create_handler(stmts, parser_type)
      parse(file, parser_type)
      expect(Registry.at('#FOO')).send(creates ? :not_to : :to, be_nil)
      Handlers::Base.subclasses.delete_if {|k, _v| k.to_s =~ /^InFileHandler/ }
    end

    [:ruby, :ruby18].each do |parser_type|
      next if parser_type == :ruby && LEGACY_PARSER
      describe "Parser type = #{parser_type.inspect}" do
        it "allows handler to be specific to a file" do
          test_handler 'file_a.rb', 'in_file "file_a.rb"', true, parser_type
        end

        it "ignores handler if filename does not match" do
          test_handler 'file_b.rb', 'in_file "file_a.rb"', false, parser_type
        end

        it "only tests filename part when given a String" do
          test_handler '/path/to/file_a.rb', 'in_file "/to/file_a.rb"', false, parser_type
        end

        it "tests exact match for entire String" do
          test_handler 'file_a.rb', 'in_file "file"', false, parser_type
        end

        it "allows a Regexp as argument and test against full path" do
          test_handler 'file_a.rbx', 'in_file(/\.rbx$/)', true, parser_type
          test_handler '/path/to/file_a.rbx', 'in_file(/\/to\/file_/)', true, parser_type
          test_handler '/path/to/file_a.rbx', 'in_file(/^\/path/)', true, parser_type
        end

        it "allows multiple in_file declarations" do
          stmts = 'in_file "x"; in_file(/y/); in_file "foo.rb"'
          test_handler 'foo.rb', stmts, true, parser_type
          test_handler 'xyzzy.rb', stmts, true, parser_type
          test_handler 'x', stmts, true, parser_type
        end
      end
    end
  end
end
