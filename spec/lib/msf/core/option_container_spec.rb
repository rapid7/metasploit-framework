# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptionContainer do
  it "should create new options for it's args" do
    foo_inst = mock("foo_inst")
    foo_inst.stub(:advanced=)
    foo_inst.stub(:evasion=)
    foo_inst.stub(:owner=)

    foo_class = mock("opt_class")
    foo_class.should_receive(:new).and_return(foo_inst)

    foo_inst.should_receive(:name).and_return("thing")

    subject = described_class.new({
      'thing' => [ foo_class, true, nil, false ]
    })
    subject["thing"].should == foo_inst

  end


end
