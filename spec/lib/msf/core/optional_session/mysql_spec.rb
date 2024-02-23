# -*- coding:binary -*-
# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::OptionalSession::MySQL do
  subject(:mod) do
    mod = ::Msf::Module.new
    mod.extend described_class
    mod
  end

  it_behaves_like Msf::OptionalSession
end
