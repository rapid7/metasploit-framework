#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

describe BinData::Base, "when defining" do
  it "fails if #initialize is overridden" do
    class BaseWithInitialize < BinData::Base
      def initialize(params = {}, parent = nil)
        super
      end
    end

    lambda {
      BaseWithInitialize.new
    }.must_raise RuntimeError
  end

  it "handles if #initialize is naively renamed to #initialize_instance" do
    class BaseWithInitializeInstance < BinData::Base
      def initialize_instance(params = {}, parent = nil)
        super
      end
    end

    lambda {
      BaseWithInitializeInstance.new
    }.must_raise RuntimeError
  end
end
