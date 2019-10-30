# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'
require 'msf/core/exploit/kerberos/client'

RSpec.describe Msf::Exploit::Remote::Kerberos::Client::AsRequest do
  subject do
    mod = ::Msf::Exploit.new
    mod.extend ::Msf::Exploit::Remote::Kerberos::Client
    mod.send(:initialize)
    mod
  end

  let(:body_opts) do
    {
      :realm => 'DOMAIN'
    }
  end

  let(:time_opts) do
    {
      :pausec => 123456
    }
  end

  describe "#build_as_request_body" do
    context "when no opts" do
      it "creates a Rex::Proto::Kerberos::Model::KdcRequestBody" do
        expect(subject.build_as_request_body).to be_a(Rex::Proto::Kerberos::Model::KdcRequestBody)
      end

      it "initializes the KdcRequestBody with default values" do
        expect(subject.build_as_request_body.realm).to eq('')
      end
    end

    context "when opts" do
      it "creates a Rex::Proto::Kerberos::Model::KdcRequestBody" do
        expect(subject.build_as_request_body(body_opts)).to be_a(Rex::Proto::Kerberos::Model::KdcRequestBody)
      end

      it "initializes the KdcRequestBody with opts when available" do
        expect(subject.build_as_request_body(body_opts).realm).to eq('DOMAIN')
      end
    end
  end

  describe "#build_as_pa_time_stamp" do
    it "creates a Rex::Proto::Kerberos::Model::PreAuthData" do
      expect(subject.build_as_pa_time_stamp).to be_a(Rex::Proto::Kerberos::Model::PreAuthData)
    end

    it "creates a PA_ENC_TIMESTAMP PreAuthData" do
      expect(subject.build_as_pa_time_stamp.type).to eq(Rex::Proto::Kerberos::Model::PA_ENC_TIMESTAMP)
    end
  end

  describe "#build_as_request" do
    context "when no opts" do
      it "creates a Rex::Proto::Kerberos::Model::KdcRequest" do
        expect(subject.build_as_request).to be_a(Rex::Proto::Kerberos::Model::KdcRequest)
      end

      it "initializes the KdcRequest with default values" do
        expect(subject.build_as_request.req_body.realm).to eq('')
      end
    end

    context "when opts" do
      it "creates a Rex::Proto::Kerberos::Model::KdcRequest" do
        body = subject.build_as_request_body(body_opts)
        expect(subject.build_as_request(body: body)).to be_a(Rex::Proto::Kerberos::Model::KdcRequest)
      end

      it "initializes the KdcRequest with opts when available" do
        body = subject.build_as_request_body(body_opts)
        expect(subject.build_as_request(body: body).req_body.realm).to eq('DOMAIN')
      end
    end
  end

end

