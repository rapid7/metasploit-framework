# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'
require 'msf/kerberos/client'

describe Msf::Kerberos::Client::CacheCredential do
  subject do
    mod = ::Msf::Exploit.new
    mod.extend ::Msf::Kerberos::Client
    mod.send(:initialize)
    mod
  end

  describe "#create_cache_credential" do
    context "when no opts" do
      it "create a default Rex::Proto::Kerberos::CredentialCache::Credential" do

      end
    end

    context "when opts" do
      it "creates a Rex::Proto::Kerberos::CredentialCache::Credential according to options" do

      end
    end
  end

  describe "#create_cache" do
  end

  describe "#create_cache" do
  end

  describe "#create_cache" do
  end
  describe "#create_cache" do
  end

end

