require 'spec_helper'

RSpec.describe Msf::WebServices do
  describe '#search_modules' do
    it 'exists' do
      expect(described_class).to respond_to(:search_modules)
    end
  end
end
