# -*- coding: binary -*-
#
require 'spec_helper'
require 'msf/core/auxiliary/kademlia'

RSpec.describe Msf::Auxiliary::Kademlia do
  subject(:kad) do
    mod = Module.new
    mod.extend described_class
    mod
  end
end
