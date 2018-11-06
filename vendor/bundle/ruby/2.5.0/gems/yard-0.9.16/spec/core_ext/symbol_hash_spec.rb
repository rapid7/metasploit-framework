# frozen_string_literal: true

RSpec.describe SymbolHash do
  it "allows access to keys as String or Symbol" do
    h = SymbolHash.new(false)
    h['test'] = true
    expect(h[:test]).to be true
    expect(h['test']).to be true
  end

  describe "#delete" do
    it "accepts either Strings or Symbols as deletion key" do
      h = SymbolHash.new
      expect(h.keys.length).to eq 0

      h['test'] = true
      expect(h.keys.length).to eq 1

      h.delete(:test)
      expect(h.keys.length).to eq 0

      h[:test] = true
      expect(h.keys.length).to eq 1

      h.delete('test')
      expect(h.keys.length).to eq 0
    end
  end

  describe "#key?" do
    it "returns same result for String or Symbol" do
      h = SymbolHash.new
      h[:test] = 1
      expect(h.key?(:test)).to be true
      expect(h.has_key?('test')).to be true # rubocop:disable Style/PreferredHashMethods
    end
  end

  it "symbolizes value if it is a String (and only a string)" do
    class Substring < String; end

    h = SymbolHash.new
    h['test1'] = "hello"
    h['test2'] = Substring.new("hello")
    expect(h['test1']).to eq :hello
    expect(h['test2']).to eq "hello"
  end

  it "does not symbolize value if SymbolHash.new(false) is created" do
    h = SymbolHash.new(false)
    h['test'] = "hello"
    expect(h[:test]).to eq "hello"
  end

  it "does not symbolize value if it is not a String" do
    h = SymbolHash.new
    h['test'] = [1, 2, 3]
    expect(h['test']).to eq [1, 2, 3]
  end

  it "supports symbolization using #update or #merge!" do
    h = SymbolHash.new
    h.update('test' => 'value')
    expect(h[:test]).to eq :value
    h.merge!('test' => 'value2') # rubocop:disable Performance/RedundantMerge
    expect(h[:test]).to eq :value2
  end

  it "supports symbolization non-destructively using #merge" do
    h = SymbolHash.new
    expect(h.merge('test' => 'value')[:test]).to eq :value
    expect(h).to eq SymbolHash.new
  end

  it "supports #initializing of a hash" do
    h = SymbolHash[:test => 1]
    expect(h[:test]).to eq 1
    expect(h[:somethingelse]).to be nil
  end

  it "supports reverse merge syntax" do
    opts = {}
    opts = SymbolHash[
      'default' => 1
    ].update(opts)
    expect(opts.keys).to eq [:default]
    expect(opts[:default]).to eq 1
  end
end
