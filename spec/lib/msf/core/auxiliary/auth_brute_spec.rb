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
      expect(subject.credentials).to be_empty
      expect(subject.default_password_collection.credentials).to be_empty
      expect(subject.credentials).to eq(subject.default_password_collection.credentials)
    end

    it 'should create a useful and non-empty default password collection when given a simple user/pass' do
      subject.datastore['USERNAME'] = 'foo'
      subject.datastore['PASSWORD'] = 'blah'
      expect(subject.credentials).not_to be_empty
      expect(subject.default_password_collection.credentials).not_to be_empty
      # TODO: the credentials used by the CredentialCollection (subject.default_password_collection.credentials)
      # are actual Credentials, whereas those returned by subject.credentials
      # are just user/pass pairs.  Either find a way to reliably compare them
      # here or simplify the mixin more.  The current approach is a hack but
      # proves the point.
      converted_collection_credentials = subject.default_password_collection.credentials.map { |c| [ c.public, c.private ] }
      expect(subject.credentials.sort).to eq(converted_collection_credentials.sort)
    end
  end
end
