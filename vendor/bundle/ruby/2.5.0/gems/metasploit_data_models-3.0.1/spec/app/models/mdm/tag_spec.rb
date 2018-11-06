require 'securerandom'

RSpec.describe Mdm::Tag, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to have_many(:hosts_tags).class_name('Mdm::HostTag') }
    it { is_expected.to have_many(:hosts).class_name('Mdm::Host').through(:hosts_tags) }
    it { is_expected.to belong_to(:user).class_name('Mdm::User') }
  end

  context 'database' do

    context 'timestamps'do
      it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(:null => false) }
      it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(:null => false) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:user_id).of_type(:integer) }
      it { is_expected.to have_db_column(:name).of_type(:string) }
      it { is_expected.to have_db_column(:desc).of_type(:text) }
      it { is_expected.to have_db_column(:report_summary).of_type(:boolean).with_options(:null => false, :default =>false) }
      it { is_expected.to have_db_column(:report_detail).of_type(:boolean).with_options(:null => false, :default =>false) }
      it { is_expected.to have_db_column(:critical).of_type(:boolean).with_options(:null => false, :default =>false) }
    end
  end

  context 'validations' do
    context 'desc'  do
      it 'should not ba valid for a length over 8k' do
        desc = SecureRandom.hex(9001) #over 9000?!
        large_tag = FactoryBot.build(:mdm_tag, :desc => desc)
        expect(large_tag).not_to be_valid
        expect(large_tag.errors[:desc]).to include('desc must be less than 8k.')
      end
    end

    context 'name' do
      let(:error_msg) {I18n.t('activerecord.ancestors.mdm/tag.model.errors.messages.character')}
      it 'must be present' do
        nameless_tag = FactoryBot.build(:mdm_tag, :name => nil)
        expect(nameless_tag).not_to be_valid
        expect(nameless_tag.errors[:name]).to include("can't be blank")
      end

      it 'may only contain alphanumerics, dot, dashes, and underscores' do
        mytag = FactoryBot.build(:mdm_tag, :name => 'A.1-B_2')
        expect(mytag).to be_valid
        #Test for various bad inputs we should never allow
        mytag = FactoryBot.build(:mdm_tag, :name => "A'1")
        expect(mytag).not_to be_valid
        expect(mytag.errors[:name]).to include(error_msg)
        mytag = FactoryBot.build(:mdm_tag, :name => "A;1")
        expect(mytag).not_to be_valid
        expect(mytag.errors[:name]).to include(error_msg)
        mytag = FactoryBot.build(:mdm_tag, :name => "A%1")
        expect(mytag).not_to be_valid
        expect(mytag.errors[:name]).to include(error_msg)
        mytag = FactoryBot.build(:mdm_tag, :name => "A=1")
        expect(mytag).not_to be_valid
        expect(mytag.errors[:name]).to include(error_msg)
        mytag = FactoryBot.build(:mdm_tag, :name => "#A1")
        expect(mytag).not_to be_valid
        expect(mytag.errors[:name]).to include(error_msg)
      end
    end
  end

  context 'instance methods' do
    context '#to_s' do
      it 'should return the name of the tag as a string' do
        mytag = FactoryBot.build(:mdm_tag, :name => 'mytag')
        expect(mytag.to_s).to eq('mytag')
      end
    end
  end

  context 'factories' do
    context 'mdm_tag' do
      subject(:mdm_tag) do
        FactoryBot.build(:mdm_tag)
      end

      it { is_expected.to be_valid }
    end
  end

  context '#destroy' do
    let!(:tag) do
      FactoryBot.create(:mdm_tag)
    end

    it 'should successfully destroy the object' do
      expect {
        tag.destroy
      }.to change(Mdm::Tag, :count).by(-1)
    end
  end


  context 'search' do
    let(:base_class) {
      described_class
    }

    context 'attributes' do
      it_should_behave_like 'search_attribute',
                            :name,
                            type: :string
      it_should_behave_like 'search_attribute',
                            :desc,
                            type: :string
    end
  end
end
