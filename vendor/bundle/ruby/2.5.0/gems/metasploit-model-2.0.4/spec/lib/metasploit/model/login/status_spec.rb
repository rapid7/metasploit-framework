RSpec.describe Metasploit::Model::Login::Status do
  context 'CONSTANTS' do
    context 'ALL' do
      subject(:all) {
        described_class::ALL
      }

      it { is_expected.to include('Denied Access') }
      it { is_expected.to include('Disabled') }
      it { is_expected.to include('Locked Out') }
      it { is_expected.to include('No Auth Required') }
      it { is_expected.to include('Successful') }
      it { is_expected.to include('Unable to Connect') }
      it { is_expected.to include('Untried') }
    end

    context 'DENIED_ACCESS' do
      subject(:denied_access) {
        described_class::DENIED_ACCESS
      }

      it { is_expected.to eq('Denied Access') }
    end

    context 'DISABLED' do
      subject(:disabled) {
        described_class::DISABLED
      }

      it { is_expected.to eq('Disabled') }
    end

    context 'INCORRECT' do
      subject(:incorrect) {
        described_class::INCORRECT
      }

      it { is_expected.to eq('Incorrect') }
    end

    context 'LOCKED_OUT' do
      subject(:locked_out) {
        described_class::LOCKED_OUT
      }

      it { is_expected.to eq('Locked Out') }
    end

    context 'NO_AUTH_REQUIRED' do
      subject(:no_auth_required) {
        described_class::NO_AUTH_REQUIRED
      }

      it { is_expected.to eq('No Auth Required') }
    end

    context 'SUCCESSFUL' do
      subject(:successful) {
        described_class::SUCCESSFUL
      }

      it { is_expected.to eq('Successful') }
    end

    context 'UNABLE_TO_CONNECT' do
      subject(:unable_to_connect) {
        described_class::UNABLE_TO_CONNECT
      }

      it { is_expected.to eq('Unable to Connect') }
    end

    context 'UNTRIED' do
      subject(:untried) {
        described_class::UNTRIED
      }

      it { is_expected.to eq('Untried') }
    end
  end
end