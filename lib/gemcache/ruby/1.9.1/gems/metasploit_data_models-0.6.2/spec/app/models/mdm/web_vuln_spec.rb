require 'spec_helper'

describe Mdm::WebVuln do
  let(:confidence_range) do
    0 .. 100
  end

  let(:default_params) do
    []
  end

  let(:methods) do
    [
        'GET',
        'POST',
        # XXX not sure why PATH is valid since it's not an HTTP method verb.
        'PATH'
    ]
  end

  let(:risk_range) do
    0 .. 5
  end

  subject(:web_vuln) do
    described_class.new
  end

  context 'associations' do
    it { should belong_to(:web_site).class_name('Mdm::WebSite') }
  end

  context 'CONSTANTS' do
    it 'should define CONFIDENCE_RANGE' do
      described_class::CONFIDENCE_RANGE.should == confidence_range
    end

    it 'should define METHODS in any order' do
      described_class::METHODS.should =~ methods
    end

    it 'should define RISK_RANGE' do
      described_class::RISK_RANGE.should == risk_range
    end
  end

  context 'database' do
    context 'columns' do
      it { should have_db_column(:blame).of_type(:text) }
      it { should have_db_column(:category).of_type(:text).with_options(:null => false) }
      it { should have_db_column(:confidence).of_type(:text).with_options(:null => false) }
      it { should have_db_column(:description).of_type(:text) }
      it { should have_db_column(:method).of_type(:string).with_options(:limit => 1024, :null => false) }
      it { should have_db_column(:name).of_type(:string).with_options(:limit => 1024, :null => false) }
      it { should have_db_column(:owner).of_type(:string) }
      it { should have_db_column(:params).of_type(:text).with_options(:null => false) }
      it { should have_db_column(:path).of_type(:text).with_options(:null => false) }
      it { should have_db_column(:payload).of_type(:text) }
      it { should have_db_column(:pname).of_type(:text).with_options(:null => false) }
      it { should have_db_column(:proof).of_type(:binary).with_options(:null => false) }
      it { should have_db_column(:query).of_type(:text) }
      it { should have_db_column(:request).of_type(:binary) }
      it { should have_db_column(:risk).of_type(:integer).with_options(:null => false) }
      it { should have_db_column(:web_site_id).of_type(:integer).with_options(:null => false) }

      context 'timestamps' do
        it { should have_db_column(:created_at).of_type(:datetime).with_options(:null => false) }
        it { should have_db_column(:updated_at).of_type(:datetime).with_options(:null => false) }
      end
    end

    context 'indices' do
      it { should have_db_index(:method) }
      it { should have_db_index(:name) }
      it { should have_db_index(:path) }
    end
  end

  context 'validations' do
    it { should validate_presence_of :category }
    it { should ensure_inclusion_of(:confidence).in_range(confidence_range) }
    it { should ensure_inclusion_of(:method).in_array(methods) }
    it { should validate_presence_of :name }
    it { should validate_presence_of :path }

    it 'should not validate presence of params because it default to [] and can never be nil' do
      web_vuln.should_not validate_presence_of(:params)
    end

    it { should validate_presence_of :pname }
    it { should validate_presence_of :proof }
    it { should ensure_inclusion_of(:risk).in_range(risk_range) }
    it { should validate_presence_of :web_site }
  end

  context 'serializations' do
    it { should serialize(:params).as_instance_of(MetasploitDataModels::Base64Serializer) }
  end

  context '#params' do
    let(:default) do
      []
    end

    let(:params) do
      web_vuln.params
    end

    it 'should default to []' do
      params.should == default
    end

    it 'should return default if set to nil' do
      web_vuln.params = nil
      web_vuln.params.should == default
    end

    it 'should return default if set to nil and saved' do
      web_vuln = FactoryGirl.build(:mdm_web_vuln)
      web_vuln.params = nil
      web_vuln.save!

      web_vuln.params.should == default
    end
  end
end