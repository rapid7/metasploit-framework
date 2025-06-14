require 'rspec'

RSpec.describe 'Metasploit Exceptions' do
  describe Msf::OptionValidateError do
    describe '#new' do
      it 'supports no options being provided' do
        subject = described_class.new
        expect(subject.options).to eq([])
        expect(subject.reasons).to eq({})
      end

      it 'supports a custom message' do
        subject = described_class.new(message: 'custom message')
        expect(subject.options).to eq([])
        expect(subject.reasons).to eq({})
        expect(subject.message).to eq 'custom message'
      end

      it 'supports a default message' do
        subject = described_class.new(['OptionName'])
        expect(subject.options).to eq(['OptionName'])
        expect(subject.reasons).to eq({})
        expect(subject.message).to eq 'The following options failed to validate: OptionName.'
      end

      it 'supports only options being provided' do
        subject = described_class.new(['RHOSTS'])
        expect(subject.options).to eq(['RHOSTS'])
        expect(subject.reasons).to eq({})
      end

      it 'supports a hash of options being provided, with associated string error reasons' do
        subject = described_class.new(
          {
            'RHOSTS' => 'Human readable description'
          }
        )
        expect(subject.options).to eq(['RHOSTS'])
        expect(subject.reasons).to eq(
          {
            'RHOSTS' => ['Human readable description']
          }
        )
      end

      it 'supports a hash of options being provided, with an array of string error reasons' do
        subject = described_class.new(
          {
            'RHOSTS' => [
              'Human readable description 1',
              'Human readable description 2',
            ]
          }
        )
        expect(subject.options).to eq(['RHOSTS'])
        expect(subject.reasons).to eq(
          {
            'RHOSTS' => [
              'Human readable description 1',
              'Human readable description 2',
            ]
          }
        )
      end

      it 'supports both options and error reasons being provided' do
        subject = described_class.new(
          [
            'RHOSTS',
            'RPORT'
          ],
          reasons: {
            'RHOSTS' => 'Human readable description'
          }
        )
        expect(subject.options).to eq(['RHOSTS', 'RPORT'])
        expect(subject.reasons).to eq(
          {
            'RHOSTS' => ['Human readable description']
          }
        )
      end
    end
  end
end
