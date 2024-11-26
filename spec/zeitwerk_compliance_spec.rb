# frozen_string_literal: true

require 'spec_helper'

# https://github.com/rails/rails/blob/0fec9536ca43e209064e60f48b0def6bfe539fe2/guides/source/classic_to_zeitwerk_howto.md#rspec
RSpec.describe 'ZeitwerkCompliance' do
  it 'loads all files without errors' do
    expect do
      # Ensure we've configured zeitwerk
      require 'msfenv'
      Zeitwerk::Loader.eager_load_all
    end.not_to raise_error
  end
end
