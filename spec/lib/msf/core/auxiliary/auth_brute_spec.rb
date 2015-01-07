# -*- coding:binary -*-
require 'spec_helper'

require 'msf/core'
require 'msf/core/auxiliary/auth_brute'

describe Msf::Auxiliary::AuthBrute do
  include_context "Msf::Simple::Framework"

  subject do
    mod = Msf::Auxiliary.allocate
    mod.extend described_class
    mod.send(:initialize, {})
    mod.datastore['Verbose'] = true
    mod.stub(
      :framework => framework,
    )
    mod
  end

  describe '::setup' do
    it 'should create a useful-but-empty default password collection by default' do
      expect(subject.default_password_collection).not_to be_nil
      expect(subject.credentials).to be_empty
    end
  end
end
