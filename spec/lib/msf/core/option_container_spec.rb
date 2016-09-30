# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

RSpec.describe Msf::OptionContainer do
  it "should create new options for it's args" do
    foo_inst = double(
      "foo_inst",
      :'advanced=' => nil,
      :'evasion=' => nil,
      :'owner=' => nil
    )
    allow(foo_inst).to receive(:name).and_return("thing")
    foo_class = double 'opt_class',
                       name: 'thing',
                       new: foo_inst

    subject = described_class.new({
      'thing' => [ foo_class, true, nil, false ]
    })
    expect(subject["thing"]).to eq foo_inst

  end


end
