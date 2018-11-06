# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::CodeObjects::Base do
  before { Registry.clear }

  it "does not allow empty object name" do
    expect { Base.new(:root, '') }.to raise_error(ArgumentError)
  end

  it "returns a unique instance of any registered object" do
    obj = ClassObject.new(:root, :Me)
    obj2 = ClassObject.new(:root, :Me)
    expect(obj.object_id).to eq obj2.object_id

    obj3 = ModuleObject.new(obj, :Too)
    obj4 = CodeObjects::Base.new(obj3, :Hello)
    obj4.parent = obj

    obj5 = CodeObjects::Base.new(obj3, :hello)
    expect(obj4.object_id).not_to eq obj5.object_id
  end

  it "creates a new object if cached object is not of the same class" do
    expect(ConstantObject.new(:root, "MYMODULE")).to be_instance_of(ConstantObject)
    expect(ModuleObject.new(:root, "MYMODULE")).to be_instance_of(ModuleObject)
    expect(ClassObject.new(:root, "MYMODULE")).to be_instance_of(ClassObject)
    expect(YARD::Registry.at("MYMODULE")).to be_instance_of(ClassObject)
  end

  it "simplifies complex namespace paths" do
    obj = ClassObject.new(:root, "A::B::C::D")
    expect(obj.name).to eq :D
    expect(obj.path).to eq "A::B::C::D"
    expect(obj.namespace).to eq P("A::B::C")
  end

  # @bug gh-552
  it "simplifies complex namespace paths when path starts with ::" do
    obj = ClassObject.new(:root, "::A::B::C::D")
    expect(obj.name).to eq :D
    expect(obj.path).to eq "A::B::C::D"
    expect(obj.namespace).to eq P("A::B::C")
  end

  it "calls the block again if #new is called on an existing object" do
    o1 = ClassObject.new(:root, :Me) do |o|
      o.docstring = "DOCSTRING"
    end

    o2 = ClassObject.new(:root, :Me) do |o|
      o.docstring = "NOT_DOCSTRING"
    end

    expect(o1.object_id).to eq o2.object_id
    expect(o1.docstring).to eq "NOT_DOCSTRING"
    expect(o2.docstring).to eq "NOT_DOCSTRING"
  end

  it "allows complex name and converts it to namespace" do
    obj = CodeObjects::Base.new(nil, "A::B")
    expect(obj.namespace.path).to eq "A"
    expect(obj.name).to eq :B
  end

  it "allows namespace to be nil and not register in the Registry" do
    obj = CodeObjects::Base.new(nil, :Me)
    expect(obj.namespace).to eq nil
    expect(Registry.at(:Me)).to eq nil
  end

  it "allows namespace to be a NamespaceObject" do
    ns = ModuleObject.new(:root, :Name)
    obj = CodeObjects::Base.new(ns, :Me)
    expect(obj.namespace).to eq ns
  end

  it "allows :root to be the shorthand namespace of `Registry.root`" do
    obj = CodeObjects::Base.new(:root, :Me)
    expect(obj.namespace).to eq Registry.root
  end

  it "does not allow any other types as namespace" do
    expect { CodeObjects::Base.new("ROOT!", :Me) }.to raise_error(ArgumentError)
  end

  it "registers itself in the registry if namespace is supplied" do
    obj = ModuleObject.new(:root, :Me)
    expect(Registry.at(:Me)).to eq obj

    obj2 = ModuleObject.new(obj, :Too)
    expect(Registry.at(:"Me::Too")).to eq obj2
  end

  describe "#[]=" do
    it "sets any attribute" do
      obj = ModuleObject.new(:root, :YARD)
      obj[:some_attr] = "hello"
      expect(obj[:some_attr]).to eq "hello"
    end

    it "uses the accessor method if available" do
      obj = CodeObjects::Base.new(:root, :YARD)
      obj[:source] = "hello"
      expect(obj.source).to eq "hello"
      obj.source = "unhello"
      expect(obj[:source]).to eq "unhello"
    end
  end

  it "sets attributes via attr= through method_missing" do
    obj = CodeObjects::Base.new(:root, :YARD)
    obj.something = 2
    expect(obj.something).to eq 2
    expect(obj[:something]).to eq 2
  end

  it "exists in the parent's #children after creation" do
    obj = ModuleObject.new(:root, :YARD)
    obj2 = MethodObject.new(obj, :testing)
    expect(obj.children).to include(obj2)
  end

  it "properly re-indents source starting from 0 indentation" do
    obj = CodeObjects::Base.new(nil, :test)
    obj.source = <<-eof
      def mymethod
        if x == 2 &&
            5 == 5
          3
        else
          1
        end
      end
    eof
    expect(obj.source).to eq "def mymethod\n  if x == 2 &&\n      5 == 5\n    3\n  else\n    1\n  end\nend"

    Registry.clear
    Parser::SourceParser.parse_string <<-eof
      def key?(key)
        super(key)
      end
    eof
    expect(Registry.at('#key?').source).to eq "def key?(key)\n  super(key)\nend"

    Registry.clear
    Parser::SourceParser.parse_string <<-eof
        def key?(key)
          if x == 2
            puts key
          else
            exit
          end
        end
    eof
    expect(Registry.at('#key?').source).to eq "def key?(key)\n  if x == 2\n    puts key\n  else\n    exit\n  end\nend"
  end

  it "does not add newlines to source when parsing sub blocks" do
    Parser::SourceParser.parse_string <<-eof
      module XYZ
        module ZYX
          class ABC
            def msg
              hello_world
            end
          end
        end
      end
    eof
    expect(Registry.at('XYZ::ZYX::ABC#msg').source).to eq "def msg\n  hello_world\nend"
  end

  it "handles source for 'def x; end'" do
    Registry.clear
    Parser::SourceParser.parse_string "def x; 2 end"
    expect(Registry.at('#x').source).to eq "def x; 2 end"
  end

  it "sets file and line information" do
    Parser::SourceParser.parse_string <<-eof
      class X; end
    eof
    expect(Registry.at(:X).file).to eq '(stdin)'
    expect(Registry.at(:X).line).to eq 1
  end

  it "maintains all file associations when objects are defined multiple times in one file" do
    Parser::SourceParser.parse_string <<-eof
      class X; end
      class X; end
      class X; end
    eof

    expect(Registry.at(:X).file).to eq '(stdin)'
    expect(Registry.at(:X).line).to eq 1
    expect(Registry.at(:X).files).to eq [['(stdin)', 1], ['(stdin)', 2], ['(stdin)', 3]]
  end

  it "maintains all file associations when objects are defined multiple times in multiple files" do
    3.times do |i|
      allow(File).to receive(:read_binary).and_return("class X; end")
      Parser::SourceParser.new.parse("file#{i + 1}.rb")
    end

    expect(Registry.at(:X).file).to eq 'file1.rb'
    expect(Registry.at(:X).line).to eq 1
    expect(Registry.at(:X).files).to eq [['file1.rb', 1], ['file2.rb', 1], ['file3.rb', 1]]
  end

  it "prioritizes the definition with a docstring when returning #file" do
    Parser::SourceParser.parse_string <<-eof
      class X; end
      class X; end
      # docstring
      class X; end
    eof

    expect(Registry.at(:X).file).to eq '(stdin)'
    expect(Registry.at(:X).line).to eq 4
    expect(Registry.at(:X).files).to eq [['(stdin)', 4], ['(stdin)', 1], ['(stdin)', 2]]
  end

  describe "#format" do
    it "sends object to Templates.render" do
      object = MethodObject.new(:root, :method)
      expect(Templates::Engine).to receive(:render).with(:x => 1, :object => object, :type => object.type)
      object.format :x => 1
    end

    it "does not change options object class" do
      opts = YARD::Templates::TemplateOptions.new
      opts.type = "test"
      object = MethodObject.new(:root, :method)
      expect(Templates::Engine).to receive(:render).with kind_of(YARD::Templates::TemplateOptions)
      object.format(opts)
    end
  end

  describe "#source_type" do
    it "defaults to :ruby" do
      object = MethodObject.new(:root, :method)
      expect(object.source_type).to eq :ruby
    end
  end

  describe "#relative_path" do
    it "accepts a string" do
      YARD.parse_string "module A; class B; end; class C; end; end"
      expect(Registry.at('A::B').relative_path(Registry.at('A::C'))).to eq(
        Registry.at('A::B').relative_path('A::C')
      )
    end

    it "returns full class name when objects share a common class prefix" do
      YARD.parse_string "module User; end; module UserManager; end"
      expect(Registry.at('User').relative_path('UserManager')).to eq 'UserManager'
      expect(Registry.at('User').relative_path(Registry.at('UserManager'))).to eq 'UserManager'
    end

    it "returns the relative path when they share a common namespace" do
      YARD.parse_string "module A; class B; end; class C; end; end"
      expect(Registry.at('A::B').relative_path(Registry.at('A::C'))).to eq 'C'
      YARD.parse_string "module Foo; module A; end; module B; def foo; end end end"
      expect(Registry.at('Foo::A').relative_path(Registry.at('Foo::B#foo'))).to eq 'B#foo'
    end

    it "returns the full path if they don't have a common namespace" do
      YARD.parse_string "module A; class B; end; end; module D; class C; end; end"
      expect(Registry.at('A::B').relative_path('D::C')).to eq 'D::C'
      YARD.parse_string 'module C::B::C; module Apple; end; module Ant; end end'
      expect(Registry.at('C::B::C::Apple').relative_path('C::B::C::Ant')).to eq 'Ant'
      YARD.parse_string 'module OMG::ABC; end; class Object; end'
      expect(Registry.at('OMG::ABC').relative_path('Object')).to eq "Object"
      YARD.parse_string("class YARD::Config; MYCONST = 1; end")
      expect(Registry.at('YARD::Config').relative_path('YARD::Config::MYCONST')).to eq "MYCONST"
    end

    it "returns a relative path for class methods" do
      YARD.parse_string "module A; def self.b; end; def self.c; end; end"
      expect(Registry.at('A.b').relative_path('A.c')).to eq 'c'
      expect(Registry.at('A').relative_path('A.c')).to eq 'c'
    end

    it "returns a relative path for instance methods" do
      YARD.parse_string "module A; def b; end; def c; end; end"
      expect(Registry.at('A#b').relative_path('A#c')).to eq '#c'
      expect(Registry.at('A').relative_path('A#c')).to eq '#c'
    end

    it "returns full path if relative path is to parent namespace" do
      YARD.parse_string "module A; module B; end end"
      expect(Registry.at('A::B').relative_path('A')).to eq 'A'
    end

    it "only returns name for relative path to self" do
      YARD.parse_string("class A::B::C; def foo; end end")
      expect(Registry.at('A::B::C').relative_path('A::B::C')).to eq 'C'
      expect(Registry.at('A::B::C#foo').relative_path('A::B::C#foo')).to eq '#foo'
    end
  end

  describe "#docstring=" do
    it "converts string into Docstring when #docstring= is set" do
      o = ClassObject.new(:root, :Me)
      o.docstring = "DOCSTRING"
      expect(o.docstring).to be_instance_of(Docstring)
    end

    it "sets docstring to docstring of other object if docstring is '(see Path)'" do
      ClassObject.new(:root, :AnotherObject) {|x| x.docstring = "FOO" }
      o = ClassObject.new(:root, :Me)
      o.docstring = '(see AnotherObject)'
      expect(o.docstring).to eq "FOO"
    end

    it "does not copy docstring mid-docstring" do
      doc = "Hello.\n(see file.rb)\nmore documentation"
      o = ClassObject.new(:root, :Me)
      o.docstring = doc
      expect(o.docstring).to eq doc
    end

    it "allows extra docstring after (see Path)" do
      ClassObject.new(:root, :AnotherObject) {|x| x.docstring = "FOO" }
      o = ClassObject.new(:root, :Me)
      o.docstring = Docstring.new("(see AnotherObject)\n\nEXTRA\n@api private", o)
      expect(o.docstring).to eq "FOO\n\nEXTRA"
      expect(o.docstring).to have_tag(:api)
    end
  end

  describe "#docstring" do
    it "returns an empty string if docstring was '(see Path)' and Path is not resolved" do
      o = ClassObject.new(:root, :Me)
      o.docstring = '(see AnotherObject)'
      expect(o.docstring).to eq ""
    end

    it "returns docstring when object is resolved" do
      o = ClassObject.new(:root, :Me)
      o.docstring = '(see AnotherObject)'
      expect(o.docstring).to eq ""
      ClassObject.new(:root, :AnotherObject) {|x| x.docstring = "FOO" }
      expect(o.docstring).to eq "FOO"
    end

    describe "localization" do
      it "returns localized docstring" do
        fr_locale = YARD::I18n::Locale.new('fr')
        allow(fr_locale).to receive(:translate).with('Hello').and_return('Bonjour')

        o = ClassObject.new(:root, :Me)
        o.docstring = 'Hello'
        expect(o.docstring).to eq 'Hello'

        allow(Registry).to receive(:locale).with('fr').and_return(fr_locale)
        expect(o.docstring('fr')).to eq "Bonjour"
      end

      it "returns localized docstring tag" do
        o = CodeObjects::MethodObject.new(:root, 'Hello#message')
        o.docstring.add_tag(Tags::Tag.new('return', 'Hello'))

        fr_locale = YARD::I18n::Locale.new('fr')
        allow(fr_locale).to receive(:translate).with('Hello').and_return('Bonjour')
        allow(Registry).to receive(:locale).with('fr').and_return(fr_locale)

        expect(o.docstring('fr').tags.map(&:text)).to eq ['Bonjour']
      end

      it "returns updated localized docstring" do
        fr_locale = YARD::I18n::Locale.new('fr')
        allow(Registry).to receive(:locale).with('fr').and_return(fr_locale)

        o = ClassObject.new(:root, :Me)
        o.docstring = 'Hello'
        expect(o.docstring).to eq 'Hello'

        allow(fr_locale).to receive(:translate).with('Hello').and_return('Bonjour')
        expect(o.docstring('fr')).to eq "Bonjour"

        o.docstring = 'World'
        allow(fr_locale).to receive(:translate).with('World').and_return('Monde')
        expect(o.docstring('fr')).to eq "Monde"
        expect(o.docstring).to eq 'World'
      end
    end
  end

  describe "#add_file" do
    it "only adds a file/line combination once" do
      o = ClassObject.new(:root, :Me)
      o.add_file('filename', 12)
      expect(o.files).to eq [['filename', 12]]
      o.add_file('filename', 12)
      expect(o.files).to eq [['filename', 12]]
      o.add_file('filename', 40) # different line
      expect(o.files).to eq [['filename', 12], ['filename', 40]]
    end
  end

  describe "#copy_to" do
    it "copies all data to new object" do
      YARD.parse_string <<-eof
        private
        # A docstring
        # @return [String] a tag
        def foo(a, b, c)
          source_code_here
        end
      eof
      foo_c = MethodObject.new(:root, :foo, :class)
      Registry.at('#foo').copy_to(foo_c)
      expect(foo_c.scope).to eq :class
      expect(foo_c.visibility).to eq :private
      expect(foo_c.type).to eq :method
      expect(foo_c.class).to eq MethodObject
      expect(foo_c.path).to eq '::foo'
      expect(foo_c.docstring).to eq "A docstring"
      expect(foo_c.tag(:return).types).to eq ['String']
      expect(foo_c.file).to eq '(stdin)'
      expect(foo_c.line).to eq 4
      expect(foo_c.source).to match(/source_code_here/)
      expect(foo_c.signature).to eq 'def foo(a, b, c)'
      expect(foo_c.parameters).to eq [['a', nil], ['b', nil], ['c', nil]]
    end

    it "returns the copied object" do
      YARD.parse_string 'def foo; end'
      foo_c = MethodObject.new(:root, :foo, :class)
      expect(Registry.at('#foo').copy_to(foo_c)).to eq foo_c
    end

    it "copies docstring and rewrite tags to new object" do
      YARD.parse_string <<-eof
        # @return [String] a tag
        def foo; end
      eof
      foo_c = MethodObject.new(:root, :foo, :class)
      foo_i = Registry.at('#foo')
      foo_i.copy_to(foo_c)
      expect(foo_i.tags).not_to eq foo_c.tags
      expect(foo_c.tags.first.object).to eq foo_c
    end

    it "only copies #copyable_attributes" do
      foo = MethodObject.new(:root, :foo)
      expect(foo).to receive(:copyable_attributes).and_return %w(a b c)
      expect(foo).to receive(:instance_variable_get).with('@a').and_return(1)
      expect(foo).to receive(:instance_variable_get).with('@b').and_return(2)
      expect(foo).to receive(:instance_variable_get).with('@c').and_return(3)
      bar = MethodObject.new(:root, :bar)
      expect(bar).to receive(:instance_variable_set).with('@a', 1)
      expect(bar).to receive(:instance_variable_set).with('@b', 2)
      expect(bar).to receive(:instance_variable_set).with('@c', 3)
      foo.copy_to(bar)
    end
  end
end
