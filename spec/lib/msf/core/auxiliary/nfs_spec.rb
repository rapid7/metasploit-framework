# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Msf::Auxiliary::Nfs do
  subject do
    mod = Msf::Module.new
    mod.extend(Msf::Auxiliary::Nfs)
    mod.datastore['LHOST'] = '1.1.1.1'
    mod.datastore['HOSTNAME'] = 'my.hostname'
    mod.datastore['Mountable'] = true
    mod
  end

  context 'NFS mountability check' do
    it 'deals with astericks' do
      expect(subject.can_mount?(['*'])).to be true
    end

    it 'deals with empty' do
      expect(subject.can_mount?([''])).to be false
    end

    it 'deals with my IP' do
      expect(subject.can_mount?(['1.1.1.1'])).to be true
    end

    it 'deals with not my IP' do
      expect(subject.can_mount?(['2.2.2.2'])).to be false
    end

    it 'correctly handles lists' do
      expect(subject.can_mount?(['2.2.2.2/255.255.255.0', '1.1.1.1/255.255.255.0'])).to be true
    end

    it 'deals with my IP with subnet' do
      expect(subject.can_mount?(['1.1.1.1/255.255.255.0'])).to be true
    end

    it 'deals with not my IP with subnet' do
      expect(subject.can_mount?(['2.2.2.2/255.255.255.0'])).to be false
    end

    it 'deals with my IP with cidr' do
      expect(subject.can_mount?(['1.1.1.1/24'])).to be true
    end

    it 'deals with not my IP with cidr' do
      expect(subject.can_mount?(['2.2.2.2/24'])).to be false
    end

    it 'exact hostname' do
      expect(subject.can_mount?(['my.hostname'])).to be true
    end

    it 'bad hostname' do
      expect(subject.can_mount?(['not.my.hostname'])).to be false
    end

    it 'hostname with wildcard' do
      expect(subject.can_mount?(['*.hostname'])).to be true
    end

    it 'bad hostname with wildcard' do
      expect(subject.can_mount?(['*.not.my.hostname'])).to be false
    end
  end
end
