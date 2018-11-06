#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))


describe BinData::Base, "parameters" do
  it "fails when parameter name is invalid" do
    lambda {
      class InvalidParameterNameBase < BinData::Base
        optional_parameter :eval # i.e. Kernel#eval
      end
    }.must_raise NameError
  end

  it "fails when parameter has nil value" do
    lambda { BinData::Base.new(a: nil) }.must_raise ArgumentError
  end
end

describe BinData::Base, "#has_parameter?" do
  it "true for existing parameters" do
    obj = BinData::Base.new(a: 3)
    assert obj.has_parameter?(:a)
  end

  it "false for non-existing parameters" do
    obj = BinData::Base.new
    refute obj.has_parameter?(:a)
  end
end

describe BinData::Base, "#get_parameter" do
  it "retrieves parameter values" do
    obj = BinData::Base.new(a: 3)
    obj.get_parameter(:a).must_equal 3
  end

  it "retrieves parameter values with string keys" do
    obj = BinData::Base.new('a' => 3)
    obj.get_parameter(:a).must_equal 3
  end

  it "returns nil for non existing parameters" do
    obj = BinData::Base.new
    obj.get_parameter(:a).must_be_nil
  end

  it "wont eval parameters" do
    obj = BinData::Base.new(a: -> { 3 })
    assert_kind_of Proc, obj.get_parameter(:a)
  end
end

describe BinData::Base, "#eval_parameter" do
  it "evals the parameter" do
    obj = BinData::Base.new(a: -> { 3 })
    obj.eval_parameter(:a).must_equal 3
  end

  it "returns nil for a non existing parameter" do
    obj = BinData::Base.new
    obj.eval_parameter(:a).must_be_nil
  end
end

describe BinData::Base, ".mandatory_parameters" do
  class MandatoryBase < BinData::Base
    mandatory_parameter :p1
    mandatory_parameter :p2
  end

  it "fails when not all mandatory parameters are present" do
    params = {p1: "a", xx: "b" }
    lambda { MandatoryBase.new(params) }.must_raise ArgumentError
  end

  it "fails when no mandatory parameters are present" do
    lambda { MandatoryBase.new() }.must_raise ArgumentError
  end
end

describe BinData::Base, ".default_parameters" do
  class DefaultBase < BinData::Base
    default_parameter p1: "a"
  end

  it "uses default parameters when not specified" do
    obj = DefaultBase.new
    obj.eval_parameter(:p1).must_equal "a"
  end

  it "can override default parameters" do
    obj = DefaultBase.new(p1: "b")
    obj.eval_parameter(:p1).must_equal "b"
  end
end

describe BinData::Base, ".mutually_exclusive_parameters" do
  class MutexParamBase < BinData::Base
    optional_parameters :p1, :p2, :p3
    mutually_exclusive_parameters :p1, :p2, :p3
  end

  it "fails when any two of those parameters are present" do
    lambda { MutexParamBase.new(p1: "a", p2: "b") }.must_raise ArgumentError
    lambda { MutexParamBase.new(p1: "a", p3: "c") }.must_raise ArgumentError
    lambda { MutexParamBase.new(p2: "b", p3: "c") }.must_raise ArgumentError
  end
end

describe BinData::Base, "subclassing" do
  class ParamLevel1Base < BinData::Base
    optional_parameter :p1
  end

  class ParamLevel2Base < ParamLevel1Base
    optional_parameter :p2
  end

  it "inherits parameters" do
    accepted = ParamLevel2Base.accepted_parameters.all
    accepted.must_include :p1
    accepted.must_include :p2
  end
end

describe BinData::Base, "subclassing when skipping a level" do
  class ParamLevel1Base < BinData::Base
    optional_parameter :p1
  end

  class ParamLevel2Base < ParamLevel1Base
  end

  class ParamLevel3Base < ParamLevel2Base
    optional_parameter :p2
  end

  it "inherits parameters" do
    accepted = ParamLevel3Base.accepted_parameters.all
    accepted.must_include :p1
    accepted.must_include :p2
  end
end
