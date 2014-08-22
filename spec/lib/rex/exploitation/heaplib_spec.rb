# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/heaplib'

describe Rex::Exploitation::HeapLib do

  let(:custom_code) { "var test = 'metasploit';" }
  let(:plain_signature) { 'JavaScript Heap Exploitation library' }
  let(:signature) { 'function(maxAlloc, heapBase)' }
  let(:methods) {
    [
      'lookasideAddr',
      'lookaside',
      'flushOleaut32',
      'freeOleaut32',
      'allocOleaut32',
      'paddingStr',
      'debugBreak',
      'debugHeap'
    ]
  }

  subject(:heap_lib_class) do
    described_class.allocate
  end

  subject(:heap_lib) do
    described_class.new
  end

  describe "#initialize" do
    it "returns an String" do
      expect(heap_lib_class.send(:initialize)).to be_a(String)
    end

    it "returns the heap lib code" do
      expect(heap_lib_class.send(:initialize)).to include(signature)
    end

    it "obfuscates with ObfuscateJS by default" do
      methods.each do |m|
        expect(heap_lib_class.send(:initialize)).to_not include(m)
      end
    end

    it "allows to provide custom JS code as argument" do
      expect(heap_lib_class.send(:initialize, custom_code)).to include(custom_code)
    end

    it "allows to disable obfuscation" do
      expect(heap_lib_class.send(:initialize, '', {:noobfu => true})).to include(plain_signature)
    end

    it "allows to use JSObfu for obfuscation" do
      expect(heap_lib_class.send(:initialize, '', {:newobfu => true})).to_not include(plain_signature)
    end
  end

  describe "#to_s" do
    it "returns the heap lib js code" do
      expect(heap_lib.to_s).to include(signature)
    end
  end

end
