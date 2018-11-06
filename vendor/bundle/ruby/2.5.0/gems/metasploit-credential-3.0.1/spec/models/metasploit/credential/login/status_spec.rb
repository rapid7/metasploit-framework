RSpec.describe Metasploit::Model::Login::Status, type: :model do
  context 'CONSTANTS' do
    context 'ALL' do
      subject(:all) do
        described_class::ALL
      end

      it { is_expected.to include described_class::DENIED_ACCESS }
      it { is_expected.to include described_class::DISABLED }
      it { is_expected.to include described_class::LOCKED_OUT }
      it { is_expected.to include described_class::SUCCESSFUL }
      it { is_expected.to include described_class::UNABLE_TO_CONNECT }
      it { is_expected.to include described_class::UNTRIED }
    end

    context 'DENIED_ACCESS' do
      subject(:denied_access) do
        described_class::DENIED_ACCESS
      end

      it { is_expected.to eq 'Denied Access' }
      it { is_expected.to be_in described_class::ALL }
    end

    context 'DISABLED' do
      subject(:disabled) do
        described_class::DISABLED
      end

      it { is_expected.to eq 'Disabled' }
      it { is_expected.to be_in described_class::ALL }
    end

    context 'LOCKED_OUT' do
      subject(:locked_out) do
        described_class::LOCKED_OUT
      end

      it { is_expected.to eq 'Locked Out' }
      it { is_expected.to be_in described_class::ALL }
    end

    context 'SUCCESSFUL' do
      subject(:successful) do
        described_class::SUCCESSFUL
      end

      it { is_expected.to eq 'Successful' }
      it { is_expected.to be_in described_class::ALL }
    end

    context 'UNABLE_TO_CONNECT' do
      subject(:unabled_to_connect) do
        described_class::UNABLE_TO_CONNECT
      end

      it { is_expected.to eq 'Unable to Connect' }
      it { is_expected.to be_in described_class::ALL }
    end

    context 'UNTRIED' do
      subject(:untried) do
        described_class::UNTRIED
      end

      it { is_expected.to eq 'Untried' }
      it { is_expected.to be_in described_class::ALL }
    end
  end
end