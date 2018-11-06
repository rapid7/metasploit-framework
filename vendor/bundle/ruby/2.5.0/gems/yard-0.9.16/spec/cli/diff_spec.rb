# frozen_string_literal: true
require 'stringio'
require 'open-uri'

RSpec.describe YARD::CLI::Diff do
  before do
    allow(CLI::Yardoc).to receive(:run)
    allow(CLI::Gems).to receive(:run)
    @diff = CLI::Diff.new
  end

  describe "Argument handling" do
    it "exits if there is only one gem name" do
      expect(@diff).to receive(:exit)
      expect(log).to receive(:puts).with(/Usage/)
      @diff.run
    end
  end

  describe "Diffing" do
    before do
      @objects1 = nil
      @objects2 = nil
    end

    def run(*args)
      @all_call = -1
      @data = StringIO.new
      @objects1 ||= %w(C#fooey C#baz D.bar)
      @objects2 ||= %w(A A::B A::B::C A.foo A#foo B C.foo C.bar C#baz)
      @objects = [@objects1, @objects2]
      expect(@diff).to receive(:load_gem_data).ordered.with('gem1') do
        Registry.clear
        YARD.parse_string <<-eof
          class C
            def fooey; end
            def baz; FOO end
          end
          class D
            def self.bar; end
          end
        eof
      end
      expect(@diff).to receive(:load_gem_data).ordered.with('gem2') do
        Registry.clear
        YARD.parse_string <<-eof
          module A
            module B
              class C; end
            end
            def self.foo; end
            def foo; end
          end
          class C
            def self.foo; end
            def self.bar; end
            def baz; BAR end
          end
        eof
      end
      allow(log).to receive(:print) {|data| @data << data }
      allow(log).to receive(:puts) {|*pargs| @data << pargs.join("\n"); @data << "\n" }
      @diff.run(*(args + ['gem1', 'gem2']))
    end

    it "shows differences between objects" do
      run
      expect(@data.string).to eq <<-eof
Added objects:

  A ((stdin):1) (...)
  A::B::C ((stdin):3)
  C.bar ((stdin):10)
  C.foo ((stdin):9)

Modified objects:

  C#baz ((stdin):3)

Removed objects:

  C#fooey ((stdin):2)
  D ((stdin):5) (...)

eof
    end

    it "accepts --compact" do
      run('--compact')
      expect(@data.string).to eq <<-eof
A A ((stdin):1) (...)
A A::B::C ((stdin):3)
A C.bar ((stdin):10)
A C.foo ((stdin):9)
M C#baz ((stdin):3)
D C#fooey ((stdin):2)
D D ((stdin):5) (...)
eof
    end

    it "accepts -a/--all" do
      ['-a', '--all'].each do |opt|
        run(opt)
        expect(@data.string).to eq <<-eof
Added objects:

  A ((stdin):1)
  A#foo ((stdin):6)
  A.foo ((stdin):5)
  A::B ((stdin):2)
  A::B::C ((stdin):3)
  C.bar ((stdin):10)
  C.foo ((stdin):9)

Modified objects:

  C#baz ((stdin):3)

Removed objects:

  C#fooey ((stdin):2)
  D ((stdin):5)
  D.bar ((stdin):6)

eof
      end
    end

    it "accepts --compact and --all" do
      run('--compact', '--all')
      expect(@data.string).to eq <<-eof
A A ((stdin):1)
A A#foo ((stdin):6)
A A.foo ((stdin):5)
A A::B ((stdin):2)
A A::B::C ((stdin):3)
A C.bar ((stdin):10)
A C.foo ((stdin):9)
M C#baz ((stdin):3)
D C#fooey ((stdin):2)
D D ((stdin):5)
D D.bar ((stdin):6)
eof
    end

    it "accepts --no-modified" do
      run('--compact', '--no-modified')
      expect(@data.string).to eq <<-eof
A A ((stdin):1) (...)
A A::B::C ((stdin):3)
A C.bar ((stdin):10)
A C.foo ((stdin):9)
D C#fooey ((stdin):2)
D D ((stdin):5) (...)
eof
    end

    it "accepts --query" do
      run('--compact', '--query', 'o.type == :method')
      expect(@data.string).to eq <<-eof
A A#foo ((stdin):6)
A A.foo ((stdin):5)
A C.bar ((stdin):10)
A C.foo ((stdin):9)
M C#baz ((stdin):3)
D C#fooey ((stdin):2)
D D.bar ((stdin):6)
eof
    end
  end

  describe "File searching" do
    before do
      allow(@diff).to receive(:generate_yardoc)
    end

    it "searches for gem/.yardoc" do
      expect(File).to receive(:directory?).with('gem1/.yardoc').and_return(true)
      expect(File).to receive(:directory?).with('gem2/.yardoc').and_return(true)
      expect(Registry).to receive(:load_yardoc).with('gem1/.yardoc')
      expect(Registry).to receive(:load_yardoc).with('gem2/.yardoc')
      @diff.run('gem1', 'gem2')
    end

    it "searches for argument as yardoc" do
      expect(File).to receive(:directory?).with('gem1/.yardoc').and_return(false)
      expect(File).to receive(:directory?).with('gem2/.yardoc').and_return(false)
      expect(File).to receive(:directory?).with('gem1').and_return(true)
      expect(File).to receive(:directory?).with('gem2').and_return(true)
      expect(Registry).to receive(:load_yardoc).with('gem1')
      expect(Registry).to receive(:load_yardoc).with('gem2')
      @diff.run('gem1', 'gem2')
    end

    it "searches for installed gem" do
      expect(File).to receive(:directory?).with('gem1-1.0.0.gem/.yardoc').and_return(false)
      expect(File).to receive(:directory?).with('gem2-1.0.0/.yardoc').and_return(false)
      expect(File).to receive(:directory?).with('gem1-1.0.0.gem').and_return(false)
      expect(File).to receive(:directory?).with('gem2-1.0.0').and_return(false)
      spec1   = double(:spec)
      spec2   = double(:spec)
      allow(YARD::GemIndex).to receive(:each) {|&b| [spec1, spec2].each(&b) }
      allow(spec1).to receive(:full_name).and_return('gem1-1.0.0')
      allow(spec1).to receive(:name).and_return('gem1')
      allow(spec1).to receive(:version).and_return('1.0.0')
      allow(spec2).to receive(:full_name).and_return('gem2-1.0.0')
      allow(spec2).to receive(:name).and_return('gem2')
      allow(spec2).to receive(:version).and_return('1.0.0')
      expect(Registry).to receive(:yardoc_file_for_gem).with('gem1', '= 1.0.0').and_return('/path/to/file')
      expect(Registry).to receive(:yardoc_file_for_gem).with('gem2', '= 1.0.0').and_return(nil)
      expect(Registry).to receive(:load_yardoc).with('/path/to/file')
      expect(CLI::Gems).to receive(:run).with('gem2', '1.0.0').and_return(nil)
      allow(Dir).to receive(:chdir)
      @diff.run('gem1-1.0.0.gem', 'gem2-1.0.0')
    end

    it "searches for .gem file" do
      expect(File).to receive(:directory?).with('gem1/.yardoc').and_return(false)
      expect(File).to receive(:directory?).with('gem2.gem/.yardoc').and_return(false)
      expect(File).to receive(:directory?).with('gem1').and_return(false)
      expect(File).to receive(:directory?).with('gem2.gem').and_return(false)
      expect(File).to receive(:exist?).with('gem1.gem').and_return(true)
      expect(File).to receive(:exist?).with('gem2.gem').and_return(true)
      expect(File).to receive(:open).with('gem1.gem', 'rb')
      expect(File).to receive(:open).with('gem2.gem', 'rb')
      allow(FileUtils).to receive(:mkdir_p)
      allow(Gem::Package).to receive(:open)
      allow(FileUtils).to receive(:rm_rf)
      @diff.run('gem1', 'gem2.gem')
    end

    it "searches for .gem file on rubygems.org" do
      expect(File).to receive(:directory?).with('gem1/.yardoc').and_return(false)
      expect(File).to receive(:directory?).with('gem2.gem/.yardoc').and_return(false)
      expect(File).to receive(:directory?).with('gem1').and_return(false)
      expect(File).to receive(:directory?).with('gem2.gem').and_return(false)
      expect(File).to receive(:exist?).with('gem1.gem').and_return(false)
      expect(File).to receive(:exist?).with('gem2.gem').and_return(false)
      expect(@diff).to receive(:open).with('http://rubygems.org/downloads/gem1.gem')
      expect(@diff).to receive(:open).with('http://rubygems.org/downloads/gem2.gem')
      allow(FileUtils).to receive(:mkdir_p)
      allow(Gem::Package).to receive(:open)
      allow(FileUtils).to receive(:rm_rf)
      @diff.run('gem1', 'gem2.gem')
    end

    it "raises an error if gem is not found" do
      expect(log).to receive(:error).with("Cannot find gem gem1")
      expect(log).to receive(:error).with("Cannot find gem gem2.gem")
      allow(@diff).to receive(:load_gem_data).and_return(false)
      @diff.run('gem1', 'gem2.gem')
    end
  end
end
