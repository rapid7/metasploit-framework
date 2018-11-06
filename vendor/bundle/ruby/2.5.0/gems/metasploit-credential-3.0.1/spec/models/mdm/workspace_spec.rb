RSpec.describe Mdm::Workspace, type: :model do
  context 'associations' do
    it { is_expected.to have_many(:core_credentials).class_name('Metasploit::Credential::Core').dependent(:destroy) }
  end
end