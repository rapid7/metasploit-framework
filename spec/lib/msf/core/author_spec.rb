require 'spec_helper'

RSpec.describe Msf::Author do

  context 'KNOWN' do
    subject(:known) {
      described_class::KNOWN
    }
    
    it { is_expected.to be_a Hash }
  end
  
  it { is_expected.to respond_to :== }
  it { is_expected.to respond_to :email }
  it { is_expected.to respond_to :email= }
  it { is_expected.to respond_to :from_s }
  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :name= }
  it { is_expected.to respond_to :to_s }
  
  describe 'class methods' do
    subject {
      described_class
    }

    it { is_expected.to respond_to :from_s }
    it { is_expected.to respond_to :transform }

    describe '.from_s' do
      subject { described_class.from_s(serialized) }

      context 'when given an empty string' do
        let(:serialized) { '' }
        it { is_expected.to be_nil }
      end

      context 'when given nil' do
        let(:serialized) { nil }
        it { is_expected.to be_nil }
      end

      context 'when given a valid name' do
        let(:name) { 'grover123' }
        let(:serialized) { name }

        it { is_expected.to be_present }

        it 'returns an instance with the correct #name' do
          expect(subject.name).to eq(name)
        end
      end

      context 'when given a valid name and email' do
        let(:email) { 'grover@sesame.co' }
        let(:name) { 'grover123' }
        let(:serialized) { "#{name} <#{email}>" }

        it { is_expected.to be_present }

        it 'returns an instance with the correct #name' do
          expect(subject.name).to eq(name)
        end

        it 'returns an instance with the correct #email' do
          expect(subject.email).to eq(email)
        end

        context 'when the email contains [at] instead of @' do
          let(:email) { 'grover[at]sesame.co' }
          let(:normalized_email) { 'grover@sesame.co' }

          it 'normalizes the [at] to an @' do
            expect(subject.email).to eq(normalized_email)
          end
        end
      end


    end
  end

  describe 'constructor' do
    subject { described_class.new(name, email) }

    context 'when given a name/email combination that is not in KNOWN' do
      let(:name) { 'blah' }
      let(:email) { 'blah' }

      describe '#name' do
        it 'is set to the "name" parameter' do
          expect(subject.name).to eq(name)
        end
      end

      describe '#email' do
        it 'is set to the "email" parameter' do
          expect(subject.email).to eq(email)
        end
      end
    end

    context 'when given a name that is in KNOWN' do
      let(:name) { described_class::KNOWN.keys.sample }
      let(:email) { 'blargulsberg' }

      describe '#name' do
        it 'is set to the "name" parameter' do
          expect(subject.name).to eq(name)
        end
      end

      describe '#email' do
        it 'is set to the "email" parameter' do
          expect(subject.email).to eq(email)
        end
      end
    end

    context 'when given a name that is in KNOWN and a nil email' do
      let(:name) { described_class::KNOWN.keys.sample }
      let(:email) { nil }

      describe '#name' do
        it 'is set to the "name" parameter' do
          expect(subject.name).to eq(name)
        end
      end

      describe '#email' do
        it 'is set to the email listed in KNOWN' do
          expect(subject.email).to eq(described_class::KNOWN[name])
        end
      end
    end
  end
end
