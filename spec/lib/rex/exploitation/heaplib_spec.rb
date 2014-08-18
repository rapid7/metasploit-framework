# -*- coding:binary -*-
require 'spec_helper'

require 'rex/exploitation/heaplib'

describe Rex::Exploitation::HeapLib do

  let(:custom_code) { "var test = 'metasploit';" }

  subject(:heap_lib) do
    described_class.allocate
  end

  describe '#initialize' do

  end

end
