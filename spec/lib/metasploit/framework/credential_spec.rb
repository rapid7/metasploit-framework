require 'spec_helper'
require 'metasploit/framework/credential'

describe Metasploit::Framework::Credential do

  subject(:cred_detail) {
    described_class.new
  }

  it { should respond_to :paired }
  it { should respond_to :private }
  it { should respond_to :private_type }
  it { should respond_to :public }
  it { should respond_to :realm }
  it { should respond_to :realm_key }

  describe "#paired" do
    it "defaults to true" do
      expect(cred_detail.paired).to be_true
    end
  end

  context 'validations' do

    it 'is not valid without paired being set' do
      expect(cred_detail).to_not be_valid
    end

    context 'when not paired' do
      before(:each) do
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
      before(:each) do
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

  describe ".to_credential" do
    let(:public) { "public" }
    let(:private) { "private" }
    let(:realm) { "realm" }
    subject(:cred_detail) do
      described_class.new(public: public, private: private, realm: realm)
    end
    it { should respond_to :to_credential }
    it "should return self" do
      cred_detail.to_credential.should eq(cred_detail)
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
end
