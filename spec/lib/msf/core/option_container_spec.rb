# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

RSpec.describe Msf::OptionContainer do
  it "should create new options for it's args" do
    foo_inst = double("foo_inst")
    foo_inst.stub(:advanced=)
    foo_inst.stub(:evasion=)
    foo_inst.stub(:owner=)

    foo_class = double("opt_class")
    expect(foo_class).to receive(:new).and_return(foo_inst)

    expect(foo_inst).to receive(:name).and_return("thing")

    subject = described_class.new({
      'thing' => [ foo_class, true, nil, false ]
    })
    expect(subject["thing"]).to eq foo_inst

  end


end
