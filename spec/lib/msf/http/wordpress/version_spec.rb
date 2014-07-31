# -*- coding:binary -*-
require 'spec_helper'

require 'msf/core'
require 'msf/core/exploit'
require 'rex/proto/http/response'
require 'msf/http/wordpress'

describe Msf::HTTP::Wordpress::Version do
  subject do
    mod = ::Msf::Exploit.new
    mod.extend ::Msf::HTTP::Wordpress
    mod.send(:initialize)
    mod
  end

  describe '#wordpress_version' do
    before :each do
      allow(subject).to receive(:send_request_cgi) do |opts|
        res = Rex::Proto::Http::Response.new
        res.code = 200
        res.body = wp_body
        res
      end
    end

    let(:wp_version) {
      r = Random.new
      "#{r.rand(10)}.#{r.rand(10)}.#{r.rand(10)}"
    }

    context 'when version from generator' do
      let(:wp_body) { '<meta name="generator" content="WordPress ' << wp_version << '" />' }
      it { expect(subject.wordpress_version).to eq(wp_version) }
    end

    context 'when version from readme' do
      let(:wp_body) { " <br /> Version #{wp_version}" }
      it { expect(subject.wordpress_version).to eq(wp_version) }
    end

    context 'when version from rss' do
      let(:wp_body) { "<generator>http://wordpress.org/?v=#{wp_version}</generator>" }
      it { expect(subject.wordpress_version).to eq(wp_version) }
    end

    context 'when version from rdf' do
      let(:wp_body) { '<admin:generatorAgent rdf:resource="http://wordpress.org/?v=' << wp_version << '" />' }
      it { expect(subject.wordpress_version).to eq(wp_version) }
    end

    context 'when version from atom' do
      let(:wp_body) { '<generator uri="http://wordpress.org/" version="' << wp_version << '">WordPress</generator>' }
      it { expect(subject.wordpress_version).to eq(wp_version) }
    end

    context 'when version from sitemap' do
      let(:wp_body) { '<!--  generator="WordPress/' << wp_version << '"  -->' }
      it { expect(subject.wordpress_version).to eq(wp_version) }
    end

    context 'when version from opml' do
      let(:wp_body) { '<!--  generator="WordPress/' << wp_version << '"  -->' }
      it { expect(subject.wordpress_version).to eq(wp_version) }
    end

  end

  describe '#check_version_from_readme' do
    before :each do
      allow(subject).to receive(:send_request_cgi) do |opts|
        res = Rex::Proto::Http::Response.new
        res.code = wp_code
        res.body = wp_body
        res
      end
    end

    let(:wp_code) { 200 }
    let(:wp_body) { nil }
    let(:wp_fixed_version) { nil }

    context 'when no readme is found' do
      let(:wp_code) { 404 }
      it { expect(subject.send(:check_version_from_readme, :plugin, 'name', wp_fixed_version)).to be(Msf::Exploit::CheckCode::Unknown) }
    end

    context 'when no version can be extracted from readme' do
      let(:wp_code) { 200 }
      let(:wp_body) { 'invalid content' }
      it { expect(subject.send(:check_version_from_readme, :plugin, 'name', wp_fixed_version)).to be(Msf::Exploit::CheckCode::Detected) }
    end

    context 'when installed version is vulnerable' do
      let(:wp_code) { 200 }
      let(:wp_fixed_version) { '1.0.1' }
      let(:wp_body) { 'stable tag: 1.0.0' }
      it { expect(subject.send(:check_version_from_readme, :plugin, 'name', wp_fixed_version)).to be(Msf::Exploit::CheckCode::Appears) }
    end

    context 'when installed version is not vulnerable' do
      let(:wp_code) { 200 }
      let(:wp_fixed_version) { '1.0.1' }
      let(:wp_body) { 'stable tag: 1.0.2' }
      it { expect(subject.send(:check_version_from_readme, :plugin, 'name', wp_fixed_version)).to be(Msf::Exploit::CheckCode::Safe) }
    end

    context 'when installed version is vulnerable (version range)' do
      let(:wp_code) { 200 }
      let(:wp_fixed_version) { '1.0.2' }
      let(:wp_introd_version) { '1.0.0' }
      let(:wp_body) { 'stable tag: 1.0.1' }
      it { expect(subject.send(:check_version_from_readme, :plugin, 'name', wp_fixed_version, wp_introd_version)).to be(Msf::Exploit::CheckCode::Appears) }
    end

    context 'when installed version is older (version range)' do
      let(:wp_code) { 200 }
      let(:wp_fixed_version) { '1.0.1' }
      let(:wp_introd_version) { '1.0.0' }
      let(:wp_body) { 'stable tag: 0.0.9' }
      it { expect(subject.send(:check_version_from_readme, :plugin, 'name', wp_fixed_version, wp_introd_version)).to be(Msf::Exploit::CheckCode::Safe) }
    end

    context 'when installed version is newer (version range)' do
      let(:wp_code) { 200 }
      let(:wp_fixed_version) { '1.0.1' }
      let(:wp_introd_version) { '1.0.0' }
      let(:wp_body) { 'stable tag: 1.0.2' }
      it { expect(subject.send(:check_version_from_readme, :plugin, 'name', wp_fixed_version, wp_introd_version)).to be(Msf::Exploit::CheckCode::Safe) }
    end

  end

end
