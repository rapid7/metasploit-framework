require 'spec_helper'
require 'metasploit/framework/credential'

RSpec.describe Metasploit::Framework::Credential do

  subject(:cred_detail) {
    described_class.new
  }

  let(:public) { "public" }
  let(:private) { "private" }
  let(:realm) { "realm" }
  let(:realm_type) { Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN }
  let(:private_type) { :password }

  it { is_expected.to respond_to :paired }
  it { is_expected.to respond_to :private }
  it { is_expected.to respond_to :private_type }
  it { is_expected.to respond_to :public }
  it { is_expected.to respond_to :realm }
  it { is_expected.to respond_to :realm_key }

  describe "#paired" do
    it "defaults to true" do
      expect(cred_detail.paired).to be_truthy
    end
  end

  context 'validations' do

    it 'is not valid without paired being set' do
      expect(cred_detail).to_not be_valid
    end

    context 'when not paired' do
      before(:example) do
        cred_detail.paired = false
      end

      it 'is invalid without at least a public or a private' do
        expect(cred_detail).to_not be_valid
      end

      it 'is valid with just a public' do
        cred_detail.public = 'root'
        expect(cred_detail).to be_valid
      end

      it 'is valid with just a private' do
        cred_detail.private = 'toor'
        expect(cred_detail).to be_valid
      end
    end

    context 'when paired' do
      before(:example) do
        cred_detail.paired = true
      end

      it 'is invalid with only a public' do
        cred_detail.public = 'root'
        expect(cred_detail).to_not be_valid
      end

      it 'is invalid with only a private' do
        cred_detail.private = 'toor'
        expect(cred_detail).to_not be_valid
      end

      it 'is invalid with empty string for public' do
        cred_detail.public = ''
        cred_detail.private = 'toor'
        expect(cred_detail).to_not be_valid
      end

      it 'is valid with empty string for private' do
        cred_detail.public = 'root'
        cred_detail.private = ''
        expect(cred_detail).to be_valid
      end
    end

  end

  describe "#to_credential" do
    subject(:cred_detail) do
      described_class.new(public: public, private: private, realm: realm)
    end
    it { is_expected.to respond_to :to_credential }
    it "should return self" do
      expect(cred_detail.to_credential).to eq(cred_detail)
    end
  end

  describe "#==" do
    let(:public) { "public" }
    let(:private) { "private" }
    let(:realm) { "realm" }
    subject(:cred_detail) do
      described_class.new(public: public, private: private, realm: realm)
    end

    context "when all attributes match" do
      let(:other) do
        described_class.new(public: public, private: private, realm: realm)
      end
      specify do
        expect(other).to eq(cred_detail)
      end
    end

    context "when realm does not match" do
      let(:other) do
        described_class.new(public: public, private: private, realm: "")
      end
      specify do
        expect(other).not_to eq(cred_detail)
      end
    end

    context "when private does not match" do
      let(:other) do
        described_class.new(public: public, private: "", realm: realm)
      end
      specify do
        expect(other).not_to eq(cred_detail)
      end
    end

    context "when public does not match" do
      let(:other) do
        described_class.new(public: "", private: private, realm: realm)
      end
      specify do
        expect(other).not_to eq(cred_detail)
      end
    end
    context "when comparing to a different object" do
      let(:other) {'a string'}
      specify do
        expect(other).not_to eq(cred_detail)
      end
    end
  end

  describe '#to_h' do
    subject(:cred_detail) do
      described_class.new(public: public, private: private, realm: realm, realm_key: realm_type, private_type: private_type)
    end
    it 'returns a hash in the format expect for create_credential' do
      cred_hash = {
          private_data: private,
          private_type: private_type,
          username: public,
          realm_key: realm_type,
          realm_value: realm
      }
      expect(cred_detail.to_h).to eq cred_hash
    end
  end
end
