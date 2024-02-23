# -*- coding:binary -*-
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::OptionalSession::MySQL do
  subject(:mod) do
    mod = ::Msf::Module.new
    mod.extend described_class
    mod
  end

  before(:each) do
    allow(Msf::FeatureManager.instance).to receive(:enabled?).and_call_original
    allow(Msf::FeatureManager.instance).to receive(:enabled?).with(Msf::FeatureManager::MYSQL_SESSION_TYPE).and_return(true)
  end

  it_behaves_like Msf::OptionalSession
end
