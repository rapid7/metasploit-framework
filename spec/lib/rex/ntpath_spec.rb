# frozen_string_literal: true

require 'rspec'

RSpec.describe Rex::Ntpath do

  describe '#as_ntpath' do
    let(:valid_windows_path) { 'some\\path\\that\\is\\valid' }

    [
      'some\\path\\that\\is\\valid',
      'some/path/that/is/valid',
      'some/./path/that/./is/valid',
      'some/extra/../path/that/extra/../is/valid',
      '/some/path/that/is/valid'
    ].each do |path|
      context "when the path is #{path}" do
        it 'formats it as a valid ntpath' do
          formatted_path = described_class.as_ntpath(path)
          expect(formatted_path).to eq valid_windows_path
        end
      end
    end
  end
end
