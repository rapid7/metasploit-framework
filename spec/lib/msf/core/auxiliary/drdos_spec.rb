# -*- coding: binary -*-
require 'spec_helper'

require 'msf/core/auxiliary/drdos'

describe Msf::Auxiliary::DRDoS do
  subject do
    mod = Module.new
    mod.extend described_class
    mod
  end

  describe '#prove_amplification' do
    it 'should detect drdos when there is packet amplification only' do
      map = { 'foo' => [ 'a', 'b' ] }
      result, _ = subject.prove_amplification(map)
      result.should be true
    end

    it 'should detect drdos when there is bandwidth amplification only' do
      map = { 'foo' => [ 'foofoo' ] }
      result, _ = subject.prove_amplification(map)
      result.should be true
    end

    it 'should detect drdos when there is packet and bandwidth amplification' do
      map = { 'foo' => [ 'foofoo', 'a' ] }
      result, _ = subject.prove_amplification(map)
      result.should be true
    end

    it 'should not detect drdos when there is no packet and no bandwidth amplification' do
      map = { 'foo' => [ 'foo' ] }
      result, _ = subject.prove_amplification(map)
      result.should be false
    end
  end
end
