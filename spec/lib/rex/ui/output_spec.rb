require 'spec_helper'

describe Rex::Ui::Output do
  subject(:output) do
    described_class.new
  end

  context '#width' do
    subject(:width) do
      output.width
    end

    it { should == 80 }
  end
end