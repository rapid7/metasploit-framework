RSpec.describe Mdm::HostTag, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to belong_to(:host).class_name('Mdm::Host') }
    it { is_expected.to belong_to(:tag).class_name('Mdm::Tag') }
  end

  context 'database' do
    context 'columns' do
      it { is_expected.to have_db_column(:host_id).of_type(:integer) }
      it { is_expected.to have_db_column(:tag_id).of_type(:integer) }
    end
  end

  context 'factories' do
    context 'mdm_host_tag' do
      subject(:mdm_host_tag) do
        FactoryBot.build(:mdm_host_tag)
      end

      it { is_expected.to be_valid }
    end
  end

  context '#destroy' do
    let(:tag) do
      FactoryBot.create(
          :mdm_tag
      )
    end

    let!(:host_tag) do
      FactoryBot.create(
          :mdm_host_tag,
          :tag => tag
      )
    end

    it 'should delete 1 Mdm::HostTag' do
      expect {
        host_tag.destroy
      }.to change(Mdm::HostTag, :count).by(-1)
    end

    context 'with multiple Mdm::HostTags using same Mdm::Tag' do
      let!(:other_host_tag) do
        FactoryBot.create(
            :mdm_host_tag,
            :tag => tag
        )
      end

      it 'should not delete Mdm::Tag' do
        expect {
          host_tag.destroy
        }.to_not change(Mdm::Tag, :count)
      end
    end

    context 'with only one Mdm::HostTag using Mdm::Tag' do
      it 'should delete Mdm::Tag' do
        expect {
          host_tag.destroy
        }.to change(Mdm::Tag, :count).by(-1)
      end
    end
  end
end
