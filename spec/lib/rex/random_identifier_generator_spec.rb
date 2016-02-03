require 'spec_helper'
require 'rex/random_identifier_generator'

RSpec.describe Rex::RandomIdentifierGenerator do
  let(:options) do
    { :min_length => 10, :max_length => 20 }
  end

  subject(:rig) { described_class.new(options) }

  it { is_expected.to respond_to(:generate) }
  it { is_expected.to respond_to(:[]) }
  it { is_expected.to respond_to(:get) }
  it { is_expected.to respond_to(:store) }
  it { is_expected.to respond_to(:to_h) }

  describe "#generate" do
    it "should respect :min_length" do
      1000.times do
        expect(rig.generate.length).to be >= options[:min_length]
      end
    end

    it "should respect :max_length" do
      1000.times do
        expect(rig.generate.length).to be <= options[:max_length]
      end
    end

    it "should allow mangling in a block" do
      ident = rig.generate { |identifier| identifier.upcase }
      expect(ident).to match(/\A[A-Z0-9_]*\Z/)

      ident = subject.generate { |identifier| identifier.downcase }
      expect(ident).to match(/\A[a-z0-9_]*\Z/)

      ident = subject.generate { |identifier| identifier.gsub("A","B") }
      expect(ident).not_to include("A")
    end
  end

  describe "#get" do
    let(:options) do
      { :min_length=>3, :max_length=>3 }
    end
    it "should return the same thing for subsequent calls" do
      expect(rig.get(:rspec)).to eq rig.get(:rspec)
    end
    it "should not return the same for different names" do
      # Statistically...
      count = 1000
      a = Set.new
      count.times do |n|
        a.add rig.get(n)
      end
      expect(a.size).to eq count
    end

    context "with an exhausted set" do
      let(:options) do
        { :char_set => "abcd", :min_length=>2, :max_length=>2 }
      end
      let(:max_permutations) do
        # 26 because first char is hardcoded to be lowercase alpha
        26 * (options[:char_set].length ** options[:min_length])
      end

      it "doesn't infinite loop" do
        Timeout.timeout(1) do
          expect {
            (max_permutations + 1).times { |i| rig.get(i) }
          }.to raise_error(Rex::RandomIdentifierGenerator::ExhaustedSpaceError)
        # don't rescue TimeoutError here because we want that to be a
        # failure case
        end
      end

    end

  end

  describe "#store" do
      let(:options) do
        { :char_set => "abcd", :min_length=>8, :max_length=>20 }
      end

    it "should allow smaller than minimum length" do
      value = "a"*(options[:min_length]-1)
      rig.store(:spec, value)
      expect(rig.get(:spec)).to eq value
    end

    it "should allow bigger than maximum length" do
      value = "a"*(options[:max_length]+1)
      rig.store(:spec, value)
      expect(rig.get(:spec)).to eq value
    end

    it "should raise if value is not unique" do
      value = "a"*(options[:max_length]+1)
      rig.store(:spec0, value)
      expect(rig.get(:spec0)).to eq value
      expect { rig.store(:spec1, value) }.to raise_error(RuntimeError)
    end

    it "should overwrite a previously stored value" do
      orig_value = "a"*(options[:max_length])
      rig.store(:spec, orig_value)
      expect(rig.get(:spec)).to eq orig_value

      new_value = "b"*(options[:max_length])
      rig.store(:spec, new_value)
      expect(rig.get(:spec)).to eq new_value
    end

    it "should overwrite a previously generated value" do
      rig.get(:spec)

      new_value = "a"*(options[:max_length])
      rig.store(:spec, new_value)
      expect(rig.get(:spec)).to eq new_value
    end

  end

  describe "#to_h" do
    it "should return a Hash" do
      expect(rig.to_h).to be_kind_of(Hash)
    end
    it "should return expected key-value pairs" do
      expected_keys = [:var_foo, :var_bar]
      expected_keys.shuffle.each do |key|
        rig.init_var(key)
      end
      expect(rig.to_h.size).to eq(expected_keys.size)
      expect(rig.to_h.keys).to include(*expected_keys)
      expect(rig.to_h.values.map {|v| v.class}.uniq).to eq([String])
    end
  end

end
