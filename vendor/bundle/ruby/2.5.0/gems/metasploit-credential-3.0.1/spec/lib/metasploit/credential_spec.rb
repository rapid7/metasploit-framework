RSpec.describe Metasploit::Credential do
  context 'CONSTANTS' do
    context 'VERSION' do
      subject(:version) {
        described_class::VERSION
      }

      it 'is Metasploit::Credential::Version.full' do
        expect(version).to eq(Metasploit::Credential::VERSION)
      end
    end
  end
end
