#-*- coding:binary -*-
require 'spec_helper'

require 'msf/core'
require 'msf/http/jboss'

describe Msf::HTTP::JBoss do
  subject do
    mod = ::Msf::Module.new
    mod.extend described_class
    mod
  end

  let (:package) do
    "deployer"
  end

  let (:bsh_script) do
    "String jboss_home = System.getProperty(\"jboss.server.home.dir\");\n"
  end

  describe '#deploy_bsh' do
    it 'return a package when deployment is successful' do
      allow(subject).to receive(:deploy_package) do
        success = true 
      end
      expect(subject.deploy_bsh(:bsh_script)).to be_kind_of(String)
    end

    it 'return nil when deployment fail' do
      allow(subject).to receive(:deploy_package) do
        success = false 
      end
      expect(subject.deploy_bsh(:bsh_script)).to be_nil
    end
  end  

  describe '#deploy_package' do
    it 'return true when bsh script get deployed' do
      allow(subject).to receive(:invoke_bsh_script) do
        res = Rex::Proto::Http::Response::OK.new
      end
      expect(subject.deploy_package(:bsh_script, :package)).to eq true
    end

    it 'return false when authentication is required' do
      allow(subject).to receive(:invoke_bsh_script) do
        res = Rex::Proto::Http::Response.new(401, "Authentication required")
      end
      expect(subject.deploy_package(:bsh_script, :package)).to eq false
    end

    it 'return false when invalid http response' do
      allow(subject).to receive(:invoke_bsh_script) do
        res = Rex::Proto::Http::Response::E404.new
      end
      expect(subject.deploy_package(:bsh_script, :package)).to eq false
    end

    it 'return false when unabled to reach BSHDeployer' do
      allow(subject).to receive(:invoke_bsh_script) do
        res = nil
      end
      expect(subject.deploy_package(:bsh_script, :package)).to eq false
    end
  end
end
