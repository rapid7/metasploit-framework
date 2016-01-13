#-*- coding:binary -*-
require 'spec_helper'

require 'msf/core'
require 'msf/core/exploit/http/jboss'

RSpec.describe Msf::Exploit::Remote::HTTP::JBoss::BeanShell do

  subject do
    mod = ::Msf::Exploit.new
    mod.extend Msf::Exploit::Remote::HTTP::JBoss
    mod.send(:initialize)
    mod
  end

  before :example do
    allow(subject).to receive(:send_request_cgi) do
      case res_code
      when nil
        res = nil
      when 401
        res = Rex::Proto::Http::Response.new(401, "Authentication required")
      when 404
        res = Rex::Proto::Http::Response::E404.new
      when 200
        res = Rex::Proto::Http::Response::OK.new
      else
        res = Rex::Proto::Http::Response.new
        res.code = res_code
      end

      res
    end
  end

  let (:package) do
    'deployer'
  end

  let (:bsh_script) do
    'String jboss_home = System.getProperty("jboss.server.home.dir");'
  end

  describe '#deploy_bsh' do
    context 'when deploy_package fails' do
      let (:res_code) { 404 }
      it { expect(subject.deploy_bsh(:bsh_script)).to be_nil }
    end

    context 'when deploy_package successes' do
      let (:res_code) { 200 }
      it { expect(subject.deploy_bsh(:bsh_script)).to be_kind_of(String) }
    end
  end

  describe '#deploy_package' do
    context 'when invoke_bsh_script returns a 200 response' do
      let (:res_code) { 200 }
      it { expect(subject.deploy_package(:bsh_script, :package)).to be_truthy }
    end

    context 'when invoke_bsh_script returns a 404 response' do
      let (:res_code) { 404 }
      it { expect(subject.deploy_package(:bsh_script, :package)).to be_falsey }
    end

    context 'when invoke_bsh_script returns a 401 response' do
      let (:res_code) { 401 }
      it { expect(subject.deploy_package(:bsh_script, :package)).to be_falsey }
    end

    context 'when invoke_bsh_script returns nil' do
      let (:res_code) { nil }
      it { expect(subject.deploy_package(:bsh_script, :package)).to be_falsey }
    end
  end

  describe "#invoke_bsh_script" do
    context 'when server timeouts' do
      let (:res_code) { nil }
      it { expect(subject.invoke_bsh_script(:bsh_script, :package)).to be_nil }
    end

    context 'when server returns a 200 response' do
      let (:res_code) { 200 }
      it { expect(subject.invoke_bsh_script(:bsh_script, :package)).to be_kind_of Rex::Proto::Http::Response }
    end

    context 'when server returns a 404 response' do
      let (:res_code) { 404 }
      it { expect(subject.invoke_bsh_script(:bsh_script, :package)).to be_kind_of Rex::Proto::Http::Response }
    end

    context 'when server returns a 401 response' do
      let (:res_code) { 401 }
      it { expect(subject.invoke_bsh_script(:bsh_script, :package)).to be_kind_of Rex::Proto::Http::Response }
    end
  end

end
