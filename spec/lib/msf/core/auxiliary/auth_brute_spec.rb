# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Msf::Auxiliary::AuthBrute do
  subject(:mod) do
    mod = Module.new
    mod.extend described_class
    mod.define_singleton_method(:tried_over_total) { |_ip, _port| nil }
    mod.define_singleton_method(:print_prefix) { @print_prefix.to_s }
    mod
  end

  def set_print_prefix(prefix)
    mod.instance_variable_set(:@print_prefix, prefix)
  end

  describe '#build_brute_message' do
    context 'when print_prefix does not contain the target' do
      before { set_print_prefix('') }

      it 'adds the ip:port prefix' do
        expect(mod.build_brute_message('127.0.0.1', 21, 'FTP', 'Failed: msf:wrong')).to eq('127.0.0.1:21          - Failed: msf:wrong')
      end
    end

    context 'when print_prefix already contains the target' do
      before { set_print_prefix('127.0.0.1:21          - ') }

      it 'does not repeat the ip:port prefix' do
        expect(mod.build_brute_message('127.0.0.1', 21, 'FTP', 'Failed: msf:wrong')).to eq('Failed: msf:wrong')
      end

      it 'does not repeat an IPv6 target' do
        set_print_prefix('[::1]:21              - ')
        expect(mod.build_brute_message('::1', 21, 'FTP', 'Failed: msf:wrong')).to eq('Failed: msf:wrong')
      end
    end

    context 'when print_prefix contains a different target' do
      before { set_print_prefix('127.0.0.1:2121        - ') }

      it 'adds the ip:port prefix' do
        expect(mod.build_brute_message('127.0.0.1', 21, 'FTP', 'Failed: msf:wrong')).to eq('127.0.0.1:21          - Failed: msf:wrong')
      end
    end
  end
end
