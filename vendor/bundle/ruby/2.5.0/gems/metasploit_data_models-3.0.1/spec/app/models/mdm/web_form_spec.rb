RSpec.describe Mdm::WebForm, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'associations' do
    it { is_expected.to belong_to(:web_site).class_name('Mdm::WebSite') }
  end

  context 'database' do

    context 'timestamps'do
      it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(:null => false) }
      it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(:null => false) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:web_site_id).of_type(:integer).with_options(:null => false) }
      it { is_expected.to have_db_column(:path).of_type(:text) }
      it { is_expected.to have_db_column(:method).of_type(:string) }
      it { is_expected.to have_db_column(:params).of_type(:text) }
      it { is_expected.to have_db_column(:query).of_type(:text) }
    end

    context 'indices' do
      it { is_expected.to have_db_index(:path) }
    end
  end

  context 'factory' do
    it 'should be valid' do
      web_form = FactoryBot.build(:mdm_web_form)
      expect(web_form).to be_valid
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      web_form = FactoryBot.create(:mdm_web_form)
      expect {
        web_form.destroy
      }.to_not raise_error
      expect {
        web_form.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end
end
