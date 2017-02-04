#-*- coding:binary -*-
require 'spec_helper'

require 'msf/core'
require 'msf/core/exploit/http/jboss'

RSpec.describe Msf::Exploit::Remote::HTTP::JBoss::DeploymentFileRepository do
  subject do
    mod = ::Msf::Exploit.new
    mod.extend Msf::Exploit::Remote::HTTP::JBoss
    mod.send(:initialize)
    mod
  end

  let (:base_name) do
    'dir_blah'
  end

  let (:jsp_name) do
    'file_blah'
  end

  let (:content) do
    '<%@page import="java.io.*%>'
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

  describe "#upload_file" do
    context 'when server timeouts' do
      let (:res_code) { nil }
      it { expect(subject.upload_file(base_name, jsp_name, content)).to be_nil }
    end

    context 'when server returns a 200 response' do
      let (:res_code) { 200 }
      it { expect(subject.upload_file(base_name, jsp_name, content)).to be_kind_of Rex::Proto::Http::Response }
    end

    context 'when server returns a 404 response' do
      let (:res_code) { 404 }
      it { expect(subject.upload_file(base_name, jsp_name, content)).to be_kind_of Rex::Proto::Http::Response }
    end

    context 'when server returns a 401 response' do
      let (:res_code) { 401 }
      it { expect(subject.upload_file(base_name, jsp_name, content)).to be_kind_of Rex::Proto::Http::Response }
    end
  end

  describe "#delete_file" do
    context 'when server timeouts' do
      let (:res_code) { nil }
      it { expect(subject.delete_file(base_name, jsp_name, content)).to be_nil }
    end

    context 'when server returns a 200 response' do
      let (:res_code) { 200 }
      it { expect(subject.delete_file(base_name, jsp_name, content)).to be_kind_of Rex::Proto::Http::Response }
    end

    context 'when server returns a 404 response' do
      let (:res_code) { 404 }
      it { expect(subject.delete_file(base_name, jsp_name, content)).to be_kind_of Rex::Proto::Http::Response }
    end

    context 'when server returns a 401 response' do
      let (:res_code) { 401 }
      it { expect(subject.delete_file(base_name, jsp_name, content)).to be_kind_of Rex::Proto::Http::Response }
    end
  end
end
