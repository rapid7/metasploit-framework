require 'spec_helper'

require Metasploit::Framework.root.join('tools/dev/msftidy.rb').to_path

RSpec.describe Msftidy do
  let(:file) { File.expand_path('modules/auxiliary/auxiliary_rubocopped.rb', FILE_FIXTURES_PATH) }

  before(:each) do
    allow_any_instance_of(MsftidyRunner).to receive(:run_checks)
    allow_any_instance_of(MsftidyRunner).to receive(:status).and_return(msftidy_runner_status_code)
    allow_any_instance_of(RuboCopRunner).to receive(:run).and_return(rubocop_runner_status_code)
  end

  context 'when there are no errors' do
    let(:msftidy_runner_status_code) { MsftidyRunner::OK }
    let(:rubocop_runner_status_code) { RuboCop::CLI::STATUS_SUCCESS }

    it { expect(subject.run([file])).to eql MsftidyRunner::OK }
  end

  context 'when there are msftidy errors' do
    let(:msftidy_runner_status_code) { MsftidyRunner::WARNING }
    let(:rubocop_runner_status_code) { RuboCop::CLI::STATUS_SUCCESS }

    it { expect(subject.run([file])).to eql MsftidyRunner::WARNING }
  end

  context 'when there are rubcop errors' do
    let(:msftidy_runner_status_code) { MsftidyRunner::WARNING }
    let(:rubocop_runner_status_code) { RuboCop::CLI::STATUS_ERROR }

    it { expect(subject.run([file])).to eql MsftidyRunner::ERROR }
  end
end
