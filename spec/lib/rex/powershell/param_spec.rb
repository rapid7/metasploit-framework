# -*- coding:binary -*-
require 'spec_helper'

require 'rex/powershell'

RSpec.describe Rex::Powershell::Param do

  let(:param_name) do
    Rex::Text.rand_text_alpha(15)
  end

  let(:klass_name) do
    Rex::Text.rand_text_alpha(15)
  end

  describe "::initialize" do
    it 'should create a param' do
      param = Rex::Powershell::Param.new(klass_name, param_name)
      expect(param).to be
      expect(param.name).to eq param_name
      expect(param.klass).to eq klass_name
      expect(param.to_s.include?("[#{klass_name}]$#{param_name}")).to be_truthy
    end
  end

end

