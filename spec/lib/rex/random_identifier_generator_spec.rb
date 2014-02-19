require 'spec_helper'
require 'rex/random_identifier_generator'

describe Rex::RandomIdentifierGenerator do
  let(:options) do
    { :min_length => 10, :max_length => 20 }
  end

  subject(:rig) { described_class.new(options) }

  it { should respond_to(:generate) }
  it { should respond_to(:[]) }
  it { should respond_to(:get) }
  it { should respond_to(:store) }
  it { should respond_to(:to_h) }

  describe "#generate" do
    it "should respect :min_length" do
      1000.times do
        rig.generate.length.should >= options[:min_length]
      end
    end

    it "should respect :max_length" do
      1000.times do
        rig.generate.length.should <= options[:max_length]
      end
    end

    it "should allow mangling in a block" do
      ident = rig.generate { |identifier| identifier.upcase }
      ident.should match(/\A[A-Z0-9_]*\Z/)

      ident = subject.generate { |identifier| identifier.downcase }
      ident.should match(/\A[a-z0-9_]*\Z/)

      ident = subject.generate { |identifier| identifier.gsub("A","B") }
      ident.should_not include("A")
    end
  end

  describe "#get" do
    let(:options) do
      { :min_length=>3, :max_length=>3 }
    end
    it "should return the same thing for subsequent calls" do
      rig.get(:rspec).should == rig.get(:rspec)
    end
    it "should not return the same for different names" do
      # Statistically...
      count = 1000
      a = Set.new
      count.times do |n|
        a.add rig.get(n)
      end
      a.size.should == count
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
      rig.get(:spec).should == value
    end

    it "should allow bigger than maximum length" do
      value = "a"*(options[:max_length]+1)
      rig.store(:spec, value)
      rig.get(:spec).should == value
    end

    it "should raise if value is not unique" do
      value = "a"*(options[:max_length]+1)
      rig.store(:spec0, value)
      rig.get(:spec0).should == value
      expect { rig.store(:spec1, value) }.to raise_error
    end

    it "should overwrite a previously stored value" do
      orig_value = "a"*(options[:max_length])
      rig.store(:spec, orig_value)
      rig.get(:spec).should == orig_value

      new_value = "b"*(options[:max_length])
      rig.store(:spec, new_value)
      rig.get(:spec).should == new_value
    end

    it "should overwrite a previously generated value" do
      rig.get(:spec)

      new_value = "a"*(options[:max_length])
      rig.store(:spec, new_value)
      rig.get(:spec).should == new_value
    end

  end

  describe "#to_h" do
    it "should return a Hash" do
      rig.to_h.should be_kind_of(Hash)
    end
    it "should return expected key-value pairs" do
      expected_keys = [:var_foo, :var_bar]
      expected_keys.shuffle.each do |key|
        rig.init_var(key)
      end
      rig.to_h.size.should eq(expected_keys.size)
      rig.to_h.keys.should include(*expected_keys)
      rig.to_h.values.map {|v| v.class}.uniq.should eq([String])
    end
  end

end
