# frozen_string_literal: true
include CodeObjects

require "thread"

RSpec.describe YARD::Registry do
  before { Registry.clear }

  describe ".yardoc_file_for_gem" do
    before do
      @gem = double('gem')
      allow(@gem).to receive(:name).and_return('foo')
      allow(@gem).to receive(:full_name).and_return('foo-1.0')
      allow(@gem).to receive(:full_gem_path).and_return('/path/to/foo')
      allow(@gem).to receive(:doc_dir).and_return('/path/to/foo/doc')
      allow(@gem).to receive(:doc_dir).with('.yardoc').and_return('/path/to/foo/doc/.yardoc')
    end

    it "returns nil if gem isn't found" do
      allow(YARD::GemIndex).to receive(:find_all_by_name).with('foo', '>= 0').and_return([])
      expect(Registry.yardoc_file_for_gem('foo')).to eq nil
    end

    it "allows version to be specified" do
      allow(YARD::GemIndex).to receive(:find_all_by_name).with('foo', '= 2').and_return([])
      expect(Registry.yardoc_file_for_gem('foo', '= 2')).to eq nil
    end

    it "returns existing .yardoc path for gem when for_writing=false" do
      allow(File).to receive(:exist?).twice.and_return(false)
      allow(File).to receive(:exist?).with('/path/to/foo/.yardoc').and_return(true)
      allow(YARD::GemIndex).to receive(:find_all_by_name).with('foo', '>= 0').and_return([@gem])
      expect(Registry.yardoc_file_for_gem('foo')).to eq '/path/to/foo/.yardoc'
    end

    it "returns new existing .yardoc path for gem when for_writing=false" do
      allow(File).to receive(:exist?).and_return(false)
      allow(File).to receive(:exist?).with('/path/to/foo/doc/.yardoc').and_return(true)
      allow(YARD::GemIndex).to receive(:find_all_by_name).with('foo', '>= 0').and_return([@gem])
      expect(Registry.yardoc_file_for_gem('foo')).to eq '/path/to/foo/doc/.yardoc'
    end

    it "returns nil if no .yardoc path exists in gem when for_writing=false" do
      allow(File).to receive(:exist?).twice.and_return(false)
      allow(File).to receive(:exist?).with('/path/to/foo/.yardoc').and_return(false)
      allow(YARD::GemIndex).to receive(:find_all_by_name).with('foo', '>= 0').and_return([@gem])
      expect(Registry.yardoc_file_for_gem('foo')).to eq nil
    end

    it "searches local gem path first if for_writing=false" do
      allow(File).to receive(:exist?).and_return(true)
      allow(YARD::GemIndex).to receive(:find_all_by_name).with('foo', '>= 0').and_return([@gem])
      expect(Registry.yardoc_file_for_gem('foo')).to match %r{/.yard/gem_index/foo-1.0.yardoc$}
    end

    it "returns global .yardoc path for gem if for_writing=true and dir is writable" do
      allow(File).to receive(:exist?).and_return(false)
      allow(File).to receive(:directory?).with(@gem.doc_dir).and_return(true)
      allow(File).to receive(:writable?).with(@gem.doc_dir).and_return(false)
      allow(File).to receive(:writable?).with(@gem.full_gem_path).and_return(true)
      allow(YARD::GemIndex).to receive(:find_all_by_name).with('foo', '>= 0').and_return([@gem])
      expect(Registry.yardoc_file_for_gem('foo', '>= 0', true)).to eq '/path/to/foo/.yardoc'
    end

    it "returns new global .yardoc path for gem if for_writing=true and dir is writable" do
      allow(File).to receive(:writable?).with(@gem.doc_dir).and_return(true)
      allow(YARD::GemIndex).to receive(:find_all_by_name).with('foo', '>= 0').and_return([@gem])
      expect(Registry.yardoc_file_for_gem('foo', '>= 0', true)).to eq '/path/to/foo/doc/.yardoc'
    end

    it "returns new global .yardoc path for gem if for_writing=true and parent dir is writable (but dir does not exist)" do
      allow(File).to receive(:writable?).with(@gem.doc_dir).and_return(false)
      allow(File).to receive(:directory?).with(@gem.doc_dir).and_return(false)
      allow(File).to receive(:writable?).with(File.dirname(@gem.doc_dir)).and_return(true)
      allow(YARD::GemIndex).to receive(:find_all_by_name).with('foo', '>= 0').and_return([@gem])
      expect(Registry.yardoc_file_for_gem('foo', '>= 0', true)).to eq '/path/to/foo/doc/.yardoc'
    end

    it "returns local .yardoc path for gem if for_writing=true and dir is not writable" do
      allow(File).to receive(:writable?).with(@gem.doc_dir).and_return(false)
      allow(File).to receive(:writable?).with(@gem.full_gem_path).and_return(false)
      allow(YARD::GemIndex).to receive(:find_all_by_name).with('foo', '>= 0').and_return([@gem])
      expect(Registry.yardoc_file_for_gem('foo', '>= 0', true)).to match %r{/.yard/gem_index/foo-1.0.yardoc$}
    end

    it "returns gem path if gem starts with yard-doc- and for_writing=false" do
      allow(@gem).to receive(:name).and_return('yard-doc-core')
      allow(@gem).to receive(:full_name).and_return('yard-doc-core-1.0')
      allow(@gem).to receive(:full_gem_path).and_return('/path/to/yard-doc-core')
      allow(YARD::GemIndex).to receive(:find_all_by_name).with('yard-doc-core', '>= 0').and_return([@gem])
      allow(File).to receive(:exist?).with('/path/to/yard-doc-core/.yardoc').and_return(true)
      expect(Registry.yardoc_file_for_gem('yard-doc-core')).to eq '/path/to/yard-doc-core/.yardoc'
    end

    it "returns nil if gem starts with yard-doc- and for_writing=true" do
      allow(@gem).to receive(:name).and_return('yard-doc-core')
      allow(@gem).to receive(:full_name).and_return('yard-doc-core-1.0')
      allow(@gem).to receive(:full_gem_path).and_return('/path/to/yard-doc-core')
      allow(YARD::GemIndex).to receive(:find_all_by_name).with('yard-doc-core', '>= 0').and_return([@gem])
      allow(File).to receive(:exist?).with('/path/to/yard-doc-core/.yardoc').and_return(true)
      expect(Registry.yardoc_file_for_gem('yard-doc-core', '>= 0', true)).to eq nil
    end
  end

  describe ".root" do
    it "has an empty path for root" do
      expect(Registry.root.path).to eq ""
    end
  end

  describe ".locale" do
    it "loads locale object" do
      fr_locale = I18n::Locale.new("fr")
      store = Registry.send(:thread_local_store)
      expect(store).to receive(:locale).with("fr").and_return(fr_locale)
      expect(Registry.locale("fr")).to eq fr_locale
    end
  end

  describe ".resolve" do
    it "resolves any existing namespace" do
      o1 = ModuleObject.new(:root, :A)
      o2 = ModuleObject.new(o1, :B)
      o3 = ModuleObject.new(o2, :C)
      expect(Registry.resolve(o1, "B::C")).to eq o3
      Registry.resolve(:root, "A::B::C")
    end

    it "resolves an object in the root namespace when prefixed with ::" do
      o1 = ModuleObject.new(:root, :A)
      o2 = ModuleObject.new(o1, :B)
      o3 = ModuleObject.new(o2, :C)
      expect(Registry.resolve(o3, "::A")).to eq o1

      expect(Registry.resolve(o3, "::String", false, true)).to eq P(:String)
    end

    it "resolves instance methods with # prefix" do
      o1 = ModuleObject.new(:root, :A)
      o2 = ModuleObject.new(o1, :B)
      o3 = ModuleObject.new(o2, :C)
      o4 = MethodObject.new(o3, :methname)
      expect(Registry.resolve(o1, "B::C#methname")).to eq o4
      expect(Registry.resolve(o2, "C#methname")).to eq o4
      expect(Registry.resolve(o3, "#methname")).to eq o4
    end

    it "resolves instance methods in the root without # prefix" do
      o = MethodObject.new(:root, :methname)
      expect(Registry.resolve(:root, 'methname')).to eq o
    end

    it "does lexical lookup on the initial namespace" do
      YARD.parse_string <<-eof
        module A
          module B; module C; end end
          module D; module E; end end
        end
      eof

      d = Registry.at('A::B::C')
      expect(Registry.resolve(d, 'D::E')).to eq Registry.at('A::D::E')
    end

    it "resolves superclass methods when inheritance = true" do
      superyard = ClassObject.new(:root, :SuperYard)
      yard = ClassObject.new(:root, :YARD)
      yard.superclass = superyard
      imeth = MethodObject.new(superyard, :hello)
      cmeth = MethodObject.new(superyard, :class_hello, :class)

      expect(Registry.resolve(yard, "#hello", false)).to be nil
      expect(Registry.resolve(yard, "#hello", true)).to eq imeth
      expect(Registry.resolve(yard, "class_hello", false)).to be nil
      expect(Registry.resolve(yard, "class_hello", true)).to eq cmeth
    end

    it "does not look at superclass proxies when inheritance = true" do
      YARD.parse_string "class A::B; end"
      expect(Registry.resolve(Registry.at('A::B'), "#bar", true)).to eq nil
    end

    it "resolves mixin methods when inheritance = true" do
      yard = ClassObject.new(:root, :YARD)
      mixin = ModuleObject.new(:root, :Mixin)
      yard.mixins(:instance) << mixin
      imeth = MethodObject.new(mixin, :hello)
      cmeth = MethodObject.new(mixin, :class_hello, :class)

      expect(Registry.resolve(yard, "#hello", false)).to be nil
      expect(Registry.resolve(yard, "#hello", true)).to eq imeth
      expect(Registry.resolve(yard, "class_hello", false)).to be nil
      expect(Registry.resolve(yard, "class_hello", true)).to eq cmeth
    end

    it "resolves methods in Object when inheritance = true" do
      YARD.parse_string <<-eof
        class Object; def foo; end end
        class A; end
        class MyObject < A; end
      eof

      expect(Registry.resolve(P('MyObject'), '#foo', true)).to eq P('Object#foo')
    end

    it "resolves methods in BasicObject when inheritance = true" do
      YARD.parse_string <<-eof
        class BasicObject; def foo; end end
        class A; end
        class MyObject < A; end
      eof

      expect(Registry.resolve(P('MyObject'), '#foo', true)).to eq P('BasicObject#foo')
    end

    it "does not perform lexical lookup to resolve a method object by more than one namespace" do
      YARD.parse_string <<-eof
        module A
          def foo; end
          def self.bar; end
          module B; module C; end end
        end
      eof

      expect(Registry.resolve(P('A::B::C'), '#foo', true)).to be nil
      expect(Registry.resolve(P('A::B::C'), '.bar', true)).to be nil
      expect(Registry.resolve(P('A::B'), '#foo', true)).not_to be nil
      expect(Registry.resolve(P('A::B'), '.bar', true)).not_to be nil
    end

    it "does not resolve methods in Object if inheriting BasicObject when inheritance = true" do
      YARD.parse_string <<-eof
        class Object; def foo; end end
        class MyObject < BasicObject; end
      eof

      expect(Registry.resolve(P('MyObject'), '#foo', true)).to be nil
    end

    it "performs lookups on each individual namespace when inheritance = true" do
      YARD.parse_string <<-eof
        module A
          module B; include A::D end
          module C; extend A::D end
          module D; def bar; end end
        end
      eof

      r = Registry.root
      expect(Registry.resolve(r, 'A::B#bar', true)).to eq Registry.at('A::D#bar')
      expect(Registry.resolve(r, 'A::C.bar', true)).to eq Registry.at('A::D#bar')
    end

    it "allows type=:typename to ensure resolved object is of a certain type" do
      YARD.parse_string "class Foo; end"
      expect(Registry.resolve(Registry.root, 'Foo')).to eq Registry.at('Foo')
      expect(Registry.resolve(Registry.root, 'Foo', false, false, :method)).to be nil
    end

    it "allows keep trying to find obj where type equals object type" do
      YARD.parse_string <<-eof
        module Foo
          class Bar; end
          def self.Bar; end
        end
      eof
      expect(Registry.resolve(P('Foo'), 'Bar', false, false, :class)).to eq Registry.at('Foo::Bar')
      expect(Registry.resolve(P('Foo'), 'Bar', false, false, :method)).to eq(
        Registry.at('Foo.Bar')
      )
    end

    it "returns proxy fallback with given type if supplied" do
      YARD.parse_string "module Foo; end"
      proxy = Registry.resolve(P('Foo'), 'Bar', false, true, :method)
      expect(proxy.type).to eq :method
      proxy = Registry.resolve(P('Qux'), 'Bar', false, true, :method)
      expect(proxy.type).to eq :method
    end

    it "does not return proxy on original namespace if path is anchored to root" do
      YARD.parse_string "module Foo; class Bar; def baz; end end end"
      proxy = Registry.resolve(P('Foo::Bar#baz'), '::Bar', true, true)
      expect(proxy.path).to eq('Bar')
      expect(proxy.namespace).to equal(Registry.root)
      expect(proxy.type).to eq(:proxy)
    end

    it "only checks 'Path' in lookup on root namespace" do
      expect(Registry).to receive(:at).once.with('Test').and_return(true)
      Registry.resolve(Registry.root, "Test")
    end

    it "does not perform lookup by joining namespace and name without separator" do
      yard = ClassObject.new(:root, :YARD)
      expect(Registry).not_to receive(:at).with('YARDB')
      Registry.resolve(yard, 'B')
    end
  end

  describe ".all" do
    it "returns objects of types specified by arguments" do
      ModuleObject.new(:root, :A)
      o1 = ClassObject.new(:root, :B)
      o2 = MethodObject.new(:root, :testing)
      r = Registry.all(:method, :class)
      expect(r).to include(o1, o2)
    end

    it "returns code objects" do
      o1 = ModuleObject.new(:root, :A)
      o2 = ClassObject.new(:root, :B)
      MethodObject.new(:root, :testing)
      r = Registry.all.select {|t| NamespaceObject === t }
      expect(r).to include(o1, o2)
    end

    it "allows .all to omit list" do
      o1 = ModuleObject.new(:root, :A)
      o2 = ClassObject.new(:root, :B)
      r = Registry.all
      expect(r).to include(o1, o2)
    end
  end

  describe ".paths" do
    it "returns all object paths" do
      ModuleObject.new(:root, :A)
      ClassObject.new(:root, :B)
      expect(Registry.paths).to include('A', 'B')
    end
  end

  describe ".load_yardoc" do
    it "delegates load to RegistryStore" do
      store = RegistryStore.new
      expect(store).to receive(:load).with('foo')
      expect(RegistryStore).to receive(:new).and_return(store)
      Registry.yardoc_file = 'foo'
      Registry.load_yardoc
    end

    it "returns itself" do
      expect(Registry.load_yardoc).to eq Registry
    end

    it "maintains hash key equality on loaded objects" do
      Registry.clear
      Registry.load!(File.dirname(__FILE__) + '/serializers/data/serialized_yardoc')
      baz = Registry.at('Foo#baz')
      expect(Registry.at('Foo').aliases.keys).to include(baz)
      expect(Registry.at('Foo').aliases.key?(baz)).to be true
    end
  end

  ['load', 'load_all', 'load!'].each do |meth|
    describe('.' + meth) do
      it "returns itself" do
        expect(Registry.send(meth)).to eq Registry
      end
    end
  end

  describe ".each" do
    before do
      YARD.parse_string "def a; end; def b; end; def c; end"
    end

    after { Registry.clear }

    it "iterates over .all" do
      items = []
      Registry.each {|x| items << x.path }
      expect(items.sort).to eq ['#a', '#b', '#c']
    end

    it "includes Enumerable and allow for find, select" do
      expect(Registry.find {|x| x.path == "#a" }).to be_a(CodeObjects::MethodObject)
    end
  end

  describe ".instance" do
    it "returns itself" do
      expect(Registry.instance).to eq Registry
    end
  end

  describe ".single_object_db" do
    it "defaults to nil" do
      expect(Registry.single_object_db).to eq nil
      Thread.new { expect(Registry.single_object_db).to eq nil }.join
    end
  end

  describe "Thread local" do
    it "maintains two Registries in separate threads" do
      barrier = 0
      mutex   = Mutex.new
      threads = []
      threads << Thread.new do
        Registry.clear
        YARD.parse_string "# docstring 1\nclass Foo; end"
        mutex.synchronize { barrier += 1 }
        "barrier < 2, spinning" while barrier < 2
        expect(Registry.at('Foo').docstring).to eq "docstring 1"
      end
      threads << Thread.new do
        Registry.clear
        YARD.parse_string "# docstring 2\nclass Foo; end"
        mutex.synchronize { barrier += 1 }
        "barrier < 2, spinning" while barrier < 2
        expect(Registry.at('Foo').docstring).to eq "docstring 2"
      end
      threads.each(&:join)
    end

    it "allows setting of yardoc_file in separate threads" do
      barrier = 0
      mutex   = Mutex.new
      threads = []
      threads << Thread.new do
        expect(Registry.yardoc_file).to eq '.yardoc'
        Registry.yardoc_file = 'foo'
        mutex.synchronize { barrier += 1 }
        "barrier = 1, spinning" while barrier == 1
        expect(Registry.yardoc_file).to eq 'foo'
      end
      threads << Thread.new do
        "barrier = 0, spinning" while barrier == 0
        expect(Registry.yardoc_file).to eq '.yardoc'
        mutex.synchronize { barrier += 1 }
        Registry.yardoc_file = 'foo2'
      end
      threads.each(&:join)
      Registry.yardoc_file = Registry::DEFAULT_YARDOC_FILE
    end

    it "automatically clears in new threads" do
      Thread.new { expect(Registry.all).to be_empty }.join
    end

    it "allows setting of po_dir in separate threads" do
      barrier = 0
      mutex   = Mutex.new
      threads = []
      threads << Thread.new do
        expect(Registry.po_dir).to eq 'po'
        Registry.po_dir = 'locale'
        mutex.synchronize { barrier += 1 }
        "barrier = 1, spinning" while barrier == 1
        expect(Registry.po_dir).to eq 'locale'
      end
      threads << Thread.new do
        "barrier = 0, spinning" while barrier == 0
        expect(Registry.po_dir).to eq 'po'
        mutex.synchronize { barrier += 1 }
        Registry.po_dir = '.'
      end
      threads.each(&:join)
      Registry.po_dir = Registry::DEFAULT_PO_DIR
    end
  end
end
