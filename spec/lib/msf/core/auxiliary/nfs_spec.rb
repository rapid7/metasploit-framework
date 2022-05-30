# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Msf::Auxiliary::Nfs do
  subject do
    mod = Msf::Module.new
    mod.extend(Msf::Auxiliary::Nfs)
    mod
  end

  context '#can_mount?' do
    it 'deals with astericks' do
      expect(subject.can_mount?(['*'], true, 'my.hostname', '1.1.1.1')).to be true
    end

    it 'deals with empty' do
      expect(subject.can_mount?([''], true, 'my.hostname', '1.1.1.1')).to be false
    end

    it 'deals with my IP' do
      expect(subject.can_mount?(['1.1.1.1'], true, 'my.hostname', '1.1.1.1')).to be true
    end

    it 'deals with not my IP' do
      expect(subject.can_mount?(['2.2.2.2'], true, 'my.hostname', '1.1.1.1')).to be false
    end

    it 'correctly handles lists' do
      expect(subject.can_mount?(['2.2.2.2/255.255.255.0', '1.1.1.1/255.255.255.0'], true, 'my.hostname', '1.1.1.1')).to be true
    end

    it 'deals with my IP with subnet' do
      expect(subject.can_mount?(['1.1.1.1/255.255.255.0'], true, 'my.hostname', '1.1.1.1')).to be true
    end

    it 'deals with not my IP with subnet' do
      expect(subject.can_mount?(['2.2.2.2/255.255.255.0'], true, 'my.hostname', '1.1.1.1')).to be false
    end

    it 'deals with my IP with cidr' do
      expect(subject.can_mount?(['1.1.1.1/24'], true, 'my.hostname', '1.1.1.1')).to be true
    end

    it 'deals with not my IP with cidr' do
      expect(subject.can_mount?(['2.2.2.2/24'], true, 'my.hostname', '1.1.1.1')).to be false
    end

    it 'exact hostname' do
      expect(subject.can_mount?(['my.hostname'], true, 'my.hostname', '1.1.1.1')).to be true
    end

    it 'bad hostname' do
      expect(subject.can_mount?(['not.my.hostname'], true, 'foo.bar', '1.1.1.1')).to be false
    end

    it 'hostname with wildcard' do
      expect(subject.can_mount?(['*.hostname'], true, 'my.hostname', '1.1.1.1')).to be true
    end

    it 'bad hostname with wildcard' do
      expect(subject.can_mount?(['*.not.my.hostname'], true, 'foo.bar', '1.1.1.1')).to be false
    end
  end
end
