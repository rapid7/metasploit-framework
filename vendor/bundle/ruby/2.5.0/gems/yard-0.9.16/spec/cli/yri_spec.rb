# frozen_string_literal: true

class TestYRI < YARD::CLI::YRI
  public :optparse, :find_object, :cache_object
  def test_stub; end
  def print_object(*args) test_stub; super end
end

RSpec.describe YARD::CLI::YRI do
  before do
    @yri = TestYRI.new
    allow(Registry).to receive(:load)
  end

  describe "#find_object" do
    it "uses cache if available" do
      allow(@yri).to receive(:cache_object)
      expect(File).to receive(:exist?).with('.yardoc').and_return(false)
      expect(File).to receive(:exist?).with('bar.yardoc').and_return(true)
      expect(Registry).to receive(:load).with('bar.yardoc')
      expect(Registry).to receive(:at).ordered.with('Foo').and_return(nil)
      expect(Registry).to receive(:at).ordered.with('Foo').and_return('OBJ')
      @yri.instance_variable_set("@cache", 'Foo' => 'bar.yardoc')
      expect(@yri.find_object('Foo')).to eq 'OBJ'
    end

    it "never uses cache ahead of current directory's .yardoc" do
      allow(@yri).to receive(:cache_object)
      expect(File).to receive(:exist?).with('.yardoc').and_return(true)
      expect(Registry).to receive(:load).with('.yardoc')
      expect(Registry).to receive(:at).ordered.with('Foo').and_return(nil)
      expect(Registry).to receive(:at).ordered.with('Foo').and_return('OBJ')
      @yri.instance_variable_set("@cache", 'Foo' => 'bar.yardoc')
      expect(@yri.find_object('Foo')).to eq 'OBJ'
      expect(@yri.instance_variable_get("@search_paths")[0]).to eq '.yardoc'
    end
  end

  describe "#cache_object" do
    it "skips caching for Registry.yardoc_file" do
      expect(File).not_to receive(:open).with(CLI::YRI::CACHE_FILE, 'w')
      @yri.cache_object('Foo', Registry.yardoc_file)
    end
  end

  describe "#initialize" do
    it "loads search paths" do
      path = %r{/\.yard/yri_search_paths$}
      allow(File).to receive(:file?).and_call_original
      allow(File).to receive(:file?).with(%r{/\.yard/yri_cache$}).and_return(false)
      allow(File).to receive(:file?).with(path).and_return(true)
      allow(File).to receive(:readlines).with(path).and_return(%w(line1 line2))
      @yri = YARD::CLI::YRI.new
      spaths = @yri.instance_variable_get("@search_paths")
      expect(spaths).to include('line1')
      expect(spaths).to include('line2')
    end

    it "uses DEFAULT_SEARCH_PATHS prior to other paths" do
      YARD::CLI::YRI::DEFAULT_SEARCH_PATHS.push('foo', 'bar')
      path = %r{/\.yard/yri_search_paths$}
      allow(File).to receive(:file?).and_call_original
      allow(File).to receive(:file?).with(%r{/\.yard/yri_cache$}).and_return(false)
      allow(File).to receive(:file?).with(path).and_return(true)
      allow(File).to receive(:readlines).with(path).and_return(%w(line1 line2))
      @yri = YARD::CLI::YRI.new
      spaths = @yri.instance_variable_get("@search_paths")
      expect(spaths[0, 4]).to eq %w(foo bar line1 line2)
      YARD::CLI::YRI::DEFAULT_SEARCH_PATHS.replace([])
    end
  end

  describe "#run" do
    it "searches for objects and print their documentation" do
      obj = YARD::CodeObjects::ClassObject.new(:root, 'Foo')
      expect(@yri).to receive(:print_object).with(obj)
      @yri.run('Foo')
      Registry.clear
    end

    it "prints usage if no object is provided" do
      expect(@yri).to receive(:print_usage)
      expect(@yri).to receive(:exit).with(1)
      @yri.run('')
    end

    it "prints 'no documentation exists for object' if object is not found" do
      expect(STDERR).to receive(:puts).with("No documentation for `Foo'")
      expect(@yri).to receive(:exit).with(1)
      @yri.run('Foo')
    end

    it "ensures output is serialized" do
      YARD::CodeObjects::ClassObject.new(:root, 'Foo')
      allow(@yri).to receive(:test_stub) do
        expect(@yri.instance_variable_get(:@serializer)).to receive(:serialize).once
      end
      @yri.run('Foo')
    end
  end
end
