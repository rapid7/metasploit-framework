# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::CodeObjects do
  def silence_warnings
    origverb = $VERBOSE
    $VERBOSE = nil
    yield
    $VERBOSE = origverb
  end

  describe :CONSTANTMATCH do
    it "matches a constant" do
      expect("Constant"[CodeObjects::CONSTANTMATCH]).to eq "Constant"
      expect("identifier"[CodeObjects::CONSTANTMATCH]).to be nil
      expect("File.new"[CodeObjects::CONSTANTMATCH]).to eq "File"
    end
  end

  describe :CONSTANTSTART do
    it "matches a constant" do
      expect("Constant"[CodeObjects::CONSTANTSTART]).to eq "C"
      expect("identifier"[CodeObjects::CONSTANTSTART]).to be nil
      expect("File.new"[CodeObjects::CONSTANTSTART]).to eq "F"
    end
  end

  describe :NAMESPACEMATCH do
    it "matches a namespace (multiple constants with ::)" do
      expect("Constant"[CodeObjects::NAMESPACEMATCH]).to eq "Constant"
      expect("A::B::C.new"[CodeObjects::NAMESPACEMATCH]).to eq "A::B::C"
    end
  end

  describe :METHODNAMEMATCH do
    it "matches a method name" do
      expect("method"[CodeObjects::METHODNAMEMATCH]).to eq "method"
      expect("[]()"[CodeObjects::METHODNAMEMATCH]).to eq "[]"
      expect("-@"[CodeObjects::METHODNAMEMATCH]).to eq "-@"
      expect("method?"[CodeObjects::METHODNAMEMATCH]).to eq "method?"
      expect("method!!"[CodeObjects::METHODNAMEMATCH]).to eq "method!"
    end
  end

  describe :METHODMATCH do
    it "matches a full class method path" do
      expect("method"[CodeObjects::METHODMATCH]).to eq "method"
      expect("A::B::C.method?"[CodeObjects::METHODMATCH]).to eq "A::B::C.method?"
      expect("A::B::C :: method"[CodeObjects::METHODMATCH]).to eq "A::B::C :: method"
      expect("SomeClass . method"[CodeObjects::METHODMATCH]).to eq "SomeClass . method"
    end

    it "matches self.method" do
      expect("self :: method!"[CodeObjects::METHODMATCH]).to eq "self :: method!"
      expect("self.is_a?"[CodeObjects::METHODMATCH]).to eq "self.is_a?"
    end
  end

  describe :BUILTIN_EXCEPTIONS do
    it "includes all base exceptions" do
      bad_names = []
      silence_warnings do
        YARD::CodeObjects::BUILTIN_EXCEPTIONS.each do |name|
          begin
            bad_names << name unless eval(name) <= Exception
          rescue NameError
            nil # noop
          end
        end
      end
      expect(bad_names).to be_empty
    end
  end

  describe :BUILTIN_CLASSES do
    it "includes all base classes" do
      bad_names = []
      silence_warnings do
        YARD::CodeObjects::BUILTIN_CLASSES.each do |name|
          begin
            bad_names << name unless eval(name).is_a?(Class)
          rescue NameError
            nil # noop
          end
        end
      end
      expect(bad_names).to be_empty
    end

    it "includes all exceptions" do
      YARD::CodeObjects::BUILTIN_EXCEPTIONS.each do |name|
        expect(YARD::CodeObjects::BUILTIN_CLASSES).to include(name)
      end
    end
  end

  describe :BUILTIN_ALL do
    it "includes classes, modules, and exceptions" do
      a = YARD::CodeObjects::BUILTIN_ALL
      b = YARD::CodeObjects::BUILTIN_CLASSES
      c = YARD::CodeObjects::BUILTIN_MODULES
      expect(a).to eq b + c
    end
  end

  describe :BUILTIN_MODULES do
    it "includes all base modules" do
      silence_warnings do
        YARD::CodeObjects::BUILTIN_MODULES.each do |name|
          next if YARD.ruby19? && ["Precision"].include?(name)
          expect(eval(name)).to be_instance_of(Module)
        end
      end
    end
  end
end
