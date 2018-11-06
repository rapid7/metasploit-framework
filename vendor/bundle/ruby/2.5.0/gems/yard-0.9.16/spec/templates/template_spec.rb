# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::Templates::Template do
  def template(path)
    YARD::Templates::Engine.template!(path, '/full/path/' + path.to_s)
  end

  before :each do
    YARD::Templates::ErbCache.clear!
  end

  describe ".include_parent" do
    it "does not include parent directory if parent directory is a template root path" do
      mod = template('q')
      expect(mod).not_to include(template(''))
    end

    it "includes overridden parent directory" do
      allow(Engine).to receive(:template_paths).and_return(['/foo', '/bar'])
      expect(File).to receive(:directory?).with('/foo/a/b').and_return(true)
      expect(File).to receive(:directory?).with('/bar/a/b').and_return(false)
      expect(File).to receive(:directory?).with('/foo/a').at_least(1).times.and_return(true)
      expect(File).to receive(:directory?).with('/bar/a').at_least(1).times.and_return(true)
      ancestors = Engine.template('a/b').ancestors.map(&:class_name)
      expect(ancestors[0, 3]).to eq %w(Template__foo_a_b Template__bar_a Template__foo_a)
    end

    it "includes parent directory template if exists" do
      mod1 = template('x')
      mod2 = template('x/y')
      expect(mod2).to include(mod1)
    end
  end

  describe ".full_paths" do
    it "lists full_path" do
      mod = template(:a)
      expect(mod.full_paths).to eq ['/full/path/a']
    end

    it "lists paths of included modules" do
      mod = template(:a)
      mod.send(:include, template(:b))
      expect(mod.full_paths).to eq ['/full/path/a', '/full/path/b']
    end

    it "lists paths from modules of included modules" do
      mod = template(:c)
      mod.send(:include, template(:d))
      mod.send(:include, template(:a))
      expect(mod.full_paths).to eq ['c', 'a', 'b', 'd'].map {|o| '/full/path/' + o }
    end

    it "only lists full paths of modules that respond to full_paths" do
      mod = template(:d)
      mod.send(:include, Enumerable)
      expect(mod.full_paths).to eq ['/full/path/d']
    end
  end

  describe ".load_setup_rb" do
    it "loads setup.rb file for module" do
      expect(File).to receive(:file?).with('/full/path/e/setup.rb').and_return(true)
      expect(File).to receive(:read).with('/full/path/e/setup.rb').and_return(String.new('def success; end'))
      expect(template(:e).new).to respond_to(:success)
    end
  end

  describe ".T" do
    it "loads template from absolute path" do
      mod = template(:a)
      expect(Engine).to receive(:template).with('other')
      mod.T('other')
    end
  end

  describe ".find_file" do
    it "finds file in the module's full_path" do
      expect(File).to receive(:file?).with('/full/path/a/basename').and_return(false)
      expect(File).to receive(:file?).with('/full/path/b/basename').and_return(true)
      expect(template(:a).find_file('basename')).to eq '/full/path/b/basename'
    end

    it "returns nil if no file is found" do
      expect(File).to receive(:file?).with('/full/path/a/basename').and_return(false)
      expect(File).to receive(:file?).with('/full/path/b/basename').and_return(false)
      expect(template(:a).find_file('basename')).to be nil
    end
  end

  describe ".find_nth_file" do
    it "finds 2nd existing file in template paths" do
      expect(File).to receive(:file?).with('/full/path/a/basename').and_return(true)
      expect(File).to receive(:file?).with('/full/path/b/basename').and_return(true)
      expect(template(:a).find_nth_file('basename', 2)).to eq '/full/path/b/basename'
    end

    it "returns nil if no file is found" do
      expect(File).to receive(:file?).with('/full/path/a/basename').and_return(true)
      expect(File).to receive(:file?).with('/full/path/b/basename').and_return(true)
      expect(template(:a).find_nth_file('basename', 3)).to be nil
    end
  end

  describe ".extra_includes" do
    it "is included when a module is initialized" do
      module MyModule; end
      Template.extra_includes << MyModule
      expect(template(:e).new).to be_kind_of(MyModule)
    end

    it "supports lambdas in list" do
      module MyModule2; end
      Template.extra_includes << lambda {|opts| MyModule2 if opts.format == :html }
      expect(template(:f).new(:format => :html)).to be_kind_of(MyModule2)
      metaclass = (class << template(:g).new(:format => :text); self end)
      expect(metaclass.ancestors).not_to include(MyModule2)
    end
  end

  describe ".is_a?" do
    it "is kind of Template" do
      expect(template(:e).is_a?(Template)).to be true
    end
  end

  describe "#T" do
    it "delegates to class method" do
      expect(template(:e)).to receive(:T).with('test')
      template(:e).new.T('test')
    end
  end

  describe "#init" do
    it "is called during initialization" do
      module YARD::Templates::Engine::Template__full_path_e # rubocop:disable Style/ClassAndModuleCamelCase
        def init; sections 1, 2, 3 end
      end
      expect(template(:e).new.sections).to eq Section.new(nil, 1, 2, 3)
    end
  end

  describe "#file" do
    it "reads the file if it exists" do
      expect(File).to receive(:file?).with('/full/path/e/abc').and_return(true)
      expect(IO).to receive(:read).with('/full/path/e/abc').and_return('hello world')
      expect(template(:e).new.file('abc')).to eq 'hello world'
    end

    it "raises ArgumentError if the file does not exist" do
      expect(File).to receive(:file?).with('/full/path/e/abc').and_return(false)
      expect { template(:e).new.file('abc') }.to raise_error(ArgumentError)
    end

    it "replaces {{{__super__}}} with inherited template contents if allow_inherited=true" do
      expect(File).to receive(:file?).with('/full/path/a/abc').twice.and_return(true)
      expect(File).to receive(:file?).with('/full/path/b/abc').and_return(true)
      expect(IO).to receive(:read).with('/full/path/a/abc').and_return(String.new('foo {{{__super__}}}'))
      expect(IO).to receive(:read).with('/full/path/b/abc').and_return(String.new('bar'))
      expect(template(:a).new.file('abc', true)).to eq "foo bar"
    end

    it "does not replace {{{__super__}}} with inherited template contents if allow_inherited=false" do
      expect(File).to receive(:file?).with('/full/path/a/abc').and_return(true)
      expect(IO).to receive(:read).with('/full/path/a/abc').and_return('foo {{{__super__}}}')
      expect(template(:a).new.file('abc')).to eq "foo {{{__super__}}}"
    end
  end

  describe "#superb" do
    it "returns the inherited erb template contents" do
      expect(File).to receive(:file?).with('/full/path/a/test.erb').and_return(true)
      expect(File).to receive(:file?).with('/full/path/b/test.erb').and_return(true)
      expect(IO).to receive(:read).with('/full/path/b/test.erb').and_return('bar')
      template = template(:a).new
      template.section = :test
      expect(template.superb).to eq "bar"
    end

    it "works inside an erb template" do
      expect(File).to receive(:file?).with('/full/path/a/test.erb').twice.and_return(true)
      expect(File).to receive(:file?).with('/full/path/b/test.erb').and_return(true)
      expect(IO).to receive(:read).with('/full/path/a/test.erb').and_return('foo<%= superb %>!')
      expect(IO).to receive(:read).with('/full/path/b/test.erb').and_return('bar')
      template = template(:a).new
      template.section = :test
      expect(template.erb(:test)).to eq "foobar!"
    end
  end

  describe "#sections" do
    it "allows sections to be set if arguments are provided" do
      mod = template(:e).new
      mod.sections 1, 2, [3]
      expect(mod.sections).to eq Section.new(nil, 1, 2, [3])
    end
  end

  describe "#run" do
    it "renders all sections" do
      mod = template(:e).new
      allow(mod).to receive(:render_section) {|section| section.name.to_s }
      mod.sections :a, :b, :c
      expect(mod.run).to eq 'abc'
    end

    it "renders all sections with options" do
      mod = template(:e).new
      allow(mod).to receive(:render_section) {|section| section.name.to_s }
      expect(mod).to receive(:add_options).with(:a => 1).and_yield
      mod.sections :a
      expect(mod.run(:a => 1)).to eq 'a'
    end

    it "runs section list if provided" do
      mod = template(:e).new
      expect(mod).to receive(:render_section).exactly(2).times do |section|
        expect([:q, :x]).to include(section.name)
        section.name.to_s
      end
      mod.run({}, [:q, :x])
    end

    it "accepts a nil section as empty string" do
      mod = template(:e).new
      allow(mod).to receive(:render_section) { nil }
      mod.sections :a
      expect(mod.run).to eq ""
    end
  end

  describe "#add_options" do
    it "sets instance variables in addition to options" do
      mod = template(:f).new
      mod.send(:add_options, :a => 1, :b => 2)
      expect(mod.options).to eq(:a => 1, :b => 2)
      expect(mod.instance_variable_get("@a")).to eq 1
      expect(mod.instance_variable_get("@b")).to eq 2
    end

    it "sets instance variables and options only for the block" do
      mod = template(:f).new
      mod.send(:add_options, :a => 100, :b => 200) do
        expect(mod.options).to eq(:a => 100, :b => 200)
      end
      expect(mod.options).not_to eq(:a => 100, :b => 200)
    end
  end

  describe "#render_section" do
    it "calls method if method exists by section name as Symbol" do
      mod = template(:f).new
      expect(mod).to receive(:respond_to?).with(:a).and_return(true)
      expect(mod).to receive(:respond_to?).with('a').and_return(true)
      expect(mod).to receive(:send).with(:a).and_return('a')
      expect(mod).to receive(:send).with('a').and_return('a')
      expect(mod.run({}, [:a, 'a'])).to eq 'aa'
    end

    it "calls erb if no method exists by section name" do
      mod = template(:f).new
      expect(mod).to receive(:respond_to?).with(:a).and_return(false)
      expect(mod).to receive(:respond_to?).with('a').and_return(false)
      expect(mod).to receive(:erb).with(:a).and_return('a')
      expect(mod).to receive(:erb).with('a').and_return('a')
      expect(mod.run({}, [:a, 'a'])).to eq 'aa'
    end

    it "runs a template if section is one" do
      mod2 = template(:g)
      expect(mod2).to receive(:run)
      mod = template(:f).new
      mod.sections mod2
      mod.run
    end

    it "runs a template instance if section is one" do
      mod2 = template(:g).new
      expect(mod2).to receive(:run)
      mod = template(:f).new
      mod.sections mod2
      mod.run
    end
  end

  describe "#yield" do
    it "yields a subsection" do
      mod = template(:e).new
      mod.sections :a, [:b, :c]
      class << mod
        def a; "(" + yield + ")" end
        def b; "b" end
        def c; "c" end
      end

      expect(mod.run).to eq "(b)"
    end

    it "yields a subsection within a yielded subsection" do
      mod = template(:e).new
      mod.sections :a, [:b, [:c]]
      class << mod
        def a; "(" + yield + ")" end
        def b; yield end
        def c; "c" end
      end

      expect(mod.run).to eq "(c)"
    end

    it "supports arbitrary nesting" do
      mod = template(:e).new
      mod.sections :a, [:b, [:c, [:d, [:e]]]]
      class << mod
        def a; "(" + yield + ")" end
        def b; yield end
        def c; yield end
        def d; yield end
        def e; "e" end
      end

      expect(mod.run).to eq "(e)"
    end

    it "yields first two elements if yield is called twice" do
      mod = template(:e).new
      mod.sections :a, [:b, :c, :d]
      class << mod
        def a; "(" + yield + yield + ")" end
        def b; 'b' end
        def c; "c" end
      end

      expect(mod.run).to eq "(bc)"
    end

    it "ignores any subsections inside subsection yields" do
      mod = template(:e).new
      mod.sections :a, [:b, [:c], :d]
      class << mod
        def a; "(" + yield + yield + ")" end
        def b; 'b' end
        def d; "d" end
      end

      expect(mod.run).to eq "(bd)"
    end

    it "allows extra options passed via yield" do
      mod = template(:e).new
      mod.sections :a, [:b]
      class << mod
        def a; "(" + yield(:x => "a") + ")" end
        def b; options.x + @x end
      end

      expect(mod.run).to eq "(aa)"
    end
  end

  describe "#yieldall" do
    it "yields all subsections" do
      mod = template(:e).new
      mod.sections :a, [:b, [:d, [:e]], :c]
      class << mod
        def a; "(" + yieldall + ")" end
        def b; "b" + yieldall end
        def c; "c" end
        def d; 'd' + yieldall end
        def e; 'e' end
      end

      expect(mod.run).to eq "(bdec)"
    end

    it "yields options to all subsections" do
      mod = template(:e).new
      mod.sections :a, [:b, :c]
      class << mod
        def a; "(" + yieldall(:x => "2") + ")" end
        def b; @x end
        def c; @x end
      end
      expect(mod.run).to eq "(22)"
    end

    it "yields all subsections more than once" do
      mod = template(:e).new
      mod.sections :a, [:b]
      class << mod
        def a; "(" + yieldall + yieldall + ")" end
        def b; "b" end
      end

      expect(mod.run).to eq "(bb)"
    end

    it "does not yield if no yieldall is called" do
      mod = template(:e).new
      mod.sections :a, [:b]
      class << mod
        def a; "()" end
        def b; "b" end
      end

      expect(mod.run).to eq "()"
    end
  end
end
