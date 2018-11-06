#!/usr/bin/env ruby

require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class Chooser
  attr_accessor :choice
end

class BinData::Choice
  def set_chooser(chooser)
    @chooser = chooser
  end
  def choice=(s)
    @chooser.choice = s
  end
end

def create_choice(choices, options = {})
  chooser = Chooser.new
  params = {choices: choices, selection: -> { chooser.choice } }.merge(options)
  choice = BinData::Choice.new(params)
  choice.set_chooser(chooser)
  choice
end

describe BinData::Choice, "when instantiating" do
  it "ensures mandatory parameters are supplied" do
    args = {}
    lambda { BinData::Choice.new(args) }.must_raise ArgumentError

    args = {selection: 1}
    lambda { BinData::Choice.new(args) }.must_raise ArgumentError

    args = {choices: []}
    lambda { BinData::Choice.new(args) }.must_raise ArgumentError
  end

  it "fails when a given type is unknown" do
    args = {choices: [:does_not_exist], selection: 0}
    lambda { BinData::Choice.new(args) }.must_raise BinData::UnRegisteredTypeError
  end

  it "fails when a given type is unknown" do
    args = {choices: {0 => :does_not_exist}, selection: 0}
    lambda { BinData::Choice.new(args) }.must_raise BinData::UnRegisteredTypeError
  end

  it "fails when :choices Hash has a symbol as key" do
    args = {choices: {a: :uint8}, selection: 0}
    lambda { BinData::Choice.new(args) }.must_raise ArgumentError
  end

  it "fails when :choices Hash has a nil key" do
    args = {choices: {nil => :uint8}, selection: 0}
    lambda { BinData::Choice.new(args) }.must_raise ArgumentError
  end
end

module ChoiceInitializedWithArrayOrHash
  def test_can_select_the_choice
    obj.choice = 3
    obj.must_equal 30
  end

  def test_shows_the_current_selection
    obj.choice = 3
    obj.selection.must_equal 3
  end

  def test_forwards_snapshot
    obj.choice = 3
    obj.snapshot.must_equal 30
  end

  def test_can_change_the_choice
    obj.choice = 3

    obj.choice = 7
    obj.must_equal 70
  end

  def test_fails_if_no_choice_has_been_set
    lambda { obj.to_s }.must_raise IndexError
  end

  def test_wont_select_an_invalid_choice
    obj.choice = 99
    lambda { obj.to_s }.must_raise IndexError
  end

  def test_wont_select_a_nil_choice
    obj.choice = 1
    lambda { obj.to_s }.must_raise IndexError
  end

  def test_handles_missing_methods_correctly
    obj.choice = 3

    obj.must_respond_to :value
    obj.wont_respond_to :does_not_exist
    lambda { obj.does_not_exist }.must_raise NoMethodError
  end

  def test_delegates_methods_to_the_selected_single_choice
    obj.choice = 5
    obj.num_bytes.must_equal 1
  end
end

describe BinData::Choice, "with sparse choices array" do
  include ChoiceInitializedWithArrayOrHash

  let(:obj) {
    choices = [nil, nil, nil,
               [:uint8, {value: 30}], nil,
               [:uint8, {value: 50}], nil,
               [:uint8, {value: 70}]]
    create_choice(choices)
  }
end

describe BinData::Choice, "with choices hash" do
  include ChoiceInitializedWithArrayOrHash

  let(:obj) {
    choices = {3 => [:uint8, {value: 30}],
               5 => [:uint8, {value: 50}],
               7 => [:uint8, {value: 70}]}
    create_choice(choices)
  }
end

describe BinData::Choice, "with single values" do
  let(:obj) {
    create_choice({3 => :uint8, 5 => :uint8, 7 => :uint8})
  }

  it "assigns raw values" do
    obj.choice = 3
    obj.assign(254)
    obj.must_equal 254
  end

  it "assigns BinData values" do
    data = BinData::Uint8.new(11)

    obj.choice = 3
    obj.assign(data)
    obj.must_equal 11
  end

  it "clears" do
    obj.choice = 3
    obj.assign(254)

    obj.clear
    obj.must_equal 0
  end

  it "clears all possible choices" do
    obj.choice = 3
    obj.assign(10)
    obj.choice = 5
    obj.assign(11)

    obj.clear

    obj.choice = 3
    obj.must_equal 0
  end

  it "is clear on initialisation" do
    obj.choice = 3

    assert obj.clear?
  end

  it "is not clear after assignment" do
    obj.choice = 3
    obj.assign(254)

    refute obj.clear?
  end

  it "does not copy value when changing selection" do
    obj.choice = 3
    obj.assign(254)

    obj.choice = 7
    obj.wont_equal 254
  end

  it "behaves as value" do
    obj.choice = 3
    obj.assign(5)

    (obj + 1).must_equal 6
    (1 + obj).must_equal 6
  end
end

describe BinData::Choice, "with copy_on_change => true" do
  let(:obj) {
    choices = {3 => :uint8, 5 => :uint8, 7 => :uint8}
    create_choice(choices, copy_on_change: true)
  }

  it "copies value when changing selection" do
    obj.choice = 3
    obj.assign(254)

    obj.choice = 7
    obj.must_equal 254
  end
end

describe BinData::Choice, "with :default" do
  let(:choices) { { "a" => :int8, default: :int16be } }

  it "selects for existing case" do
    obj = BinData::Choice.new(selection: "a", choices: choices)
    obj.num_bytes.must_equal 1
  end

  it "selects for default case" do
    obj = BinData::Choice.new(selection: "other", choices: choices)
    obj.num_bytes.must_equal 2
  end
end

describe BinData::Choice, "subclassed with default parameters" do
  class DerivedChoice < BinData::Choice
    endian :big
    default_parameter selection: 'a'

    uint16 'a'
    uint32 'b'
    uint64 :default
  end

  it "sets initial selection" do
    obj = DerivedChoice.new
    obj.num_bytes.must_equal 2
  end

  it "overides default parameter" do
    obj = DerivedChoice.new(selection: 'b')
    obj.num_bytes.must_equal 4
  end

  it "selects default selection" do
    obj = DerivedChoice.new(selection: 'z')
    obj.num_bytes.must_equal 8
  end
end
