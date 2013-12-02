require 'spec_helper'

describe Metasploit::Framework::NullProgressBar do
  subject(:null_progress_bar) do
    described_class.new
  end

  it { should be_a MetasploitDataModels::NullProgressBar }

  context '#title=' do
    let(:title) do
      double('title')
    end

    specify {
      expect {
        null_progress_bar.title = title
      }.not_to raise_error
    }
  end
end
