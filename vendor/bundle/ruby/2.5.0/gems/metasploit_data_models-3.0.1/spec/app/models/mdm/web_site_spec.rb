RSpec.describe Mdm::WebSite, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'factory' do
    it 'should be valid' do
      web_site = FactoryBot.build(:mdm_web_site)
      expect(web_site).to be_valid
    end
  end

  context 'database' do

    context 'timestamps'do
      it { is_expected.to have_db_column(:created_at).of_type(:datetime).with_options(:null => false) }
      it { is_expected.to have_db_column(:updated_at).of_type(:datetime).with_options(:null => false) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:service_id).of_type(:integer).with_options(:null => false) }
      it { is_expected.to have_db_column(:vhost).of_type(:string) }
      it { is_expected.to have_db_column(:comments).of_type(:text) }
      it { is_expected.to have_db_column(:options).of_type(:text) }
    end

    context 'indices' do
      it { is_expected.to have_db_index(:comments) }
      it { is_expected.to have_db_index(:options) }
      it { is_expected.to have_db_index(:vhost) }
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      web_site = FactoryBot.create(:mdm_web_site)
      expect {
        web_site.destroy
      }.to_not raise_error
      expect {
        web_site.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end
  
  context 'associations' do
    it { is_expected.to belong_to(:service).class_name('Mdm::Service') }
    it { is_expected.to have_many(:web_forms).class_name('Mdm::WebForm').dependent(:destroy) }
    it { is_expected.to have_many(:web_pages).class_name('Mdm::WebPage').dependent(:destroy) }
    it { is_expected.to have_many(:web_vulns).class_name('Mdm::WebVuln').dependent(:destroy) }
  end

  context 'methods' do
    context '#form_count' do
      it 'should return an accurate count of associated Webforms' do
        mysite = FactoryBot.create(:mdm_web_site)
        FactoryBot.create(:mdm_web_form, :web_site => mysite)
        FactoryBot.create(:mdm_web_form, :web_site => mysite)
        expect(mysite.form_count).to eq(2)
        FactoryBot.create(:mdm_web_form, :web_site => mysite)
        expect(mysite.form_count).to eq(3)
      end
    end

    context '#page_count' do
      it 'should return an accurate count of associated Webpages' do
        mysite = FactoryBot.create(:mdm_web_site)
        FactoryBot.create(:mdm_web_page, :web_site => mysite)
        FactoryBot.create(:mdm_web_page, :web_site => mysite)
        expect(mysite.page_count).to eq(2)
        FactoryBot.create(:mdm_web_page, :web_site => mysite)
        expect(mysite.page_count).to eq(3)
      end
    end

    context '#vuln_count' do
      it 'should return an accurate count of associated Webvulns' do
        mysite = FactoryBot.create(:mdm_web_site)
        FactoryBot.create(:mdm_web_vuln, :web_site => mysite)
        FactoryBot.create(:mdm_web_vuln, :web_site => mysite)
        expect(mysite.vuln_count).to eq(2)
        FactoryBot.create(:mdm_web_vuln, :web_site => mysite)
        expect(mysite.vuln_count).to eq(3)
      end
    end
  end
end
