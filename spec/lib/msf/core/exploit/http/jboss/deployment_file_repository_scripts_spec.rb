#-*- coding:binary -*-
require 'spec_helper'

require 'msf/core'
require 'msf/core/exploit/http/jboss'

RSpec.describe Msf::Exploit::Remote::HTTP::JBoss::DeploymentFileRepositoryScripts do
  subject do
    mod = ::Msf::Exploit.new
    mod.extend Msf::Exploit::Remote::HTTP::JBoss
    mod.send(:initialize)
    mod
  end

  describe "#stager_jsp_with_payload" do
    it "returns the JSP stager" do
      expect(subject.stager_jsp_with_payload('metasploit', 'payload')).to include('System.getProperty("jboss.server.home.dir");')
    end

    it "uses the provided application name" do
      expect(subject.stager_jsp_with_payload('metasploit', 'payload')).to include('"/deploy/management/" + "metasploit.war";')
    end

    it "uses the provided payload" do
      expect(subject.stager_jsp_with_payload('metasploit', 'payload')).to include('"payload";')
    end
  end

  describe "#head_stager_jsp" do
    it "returns the head JSP stager" do
      expect(subject.head_stager_jsp('stager_base', 'jsp_name')).to include('System.getProperty("jboss.server.home.dir");')
    end

    it "uses the provided base name" do
      expect(subject.head_stager_jsp('stager_base', 'jsp_name')).to include('"/deploy/management/" + "stager_base.war/"')
    end
  end

end
