#-*- coding:binary -*-
require 'spec_helper'

require 'msf/core'
require 'msf/core/exploit/http/jboss'

RSpec.describe Msf::Exploit::Remote::HTTP::JBoss::BeanShellScripts do
  subject do
    mod = ::Msf::Exploit.new
    mod.extend Msf::Exploit::Remote::HTTP::JBoss
    mod.send(:initialize)
    mod
  end

  describe "#generate_bsh" do
    context "when :create type is used" do
      it { expect(subject.generate_bsh(:create, {})).to include('String jboss_home = System.getProperty("jboss.server.home.dir");') }
    end

    context "when :delete type is used" do
      it { expect(subject.generate_bsh(:delete, {})).to include('String jboss_home = System.getProperty("jboss.server.home.dir");') }
    end

    context "when invalid type is used" do
      it { expect(subject.generate_bsh(:invalid, {})).to be_nil }
    end
  end

  describe "#stager_jsp" do
    it "returns the JSP stager" do
      expect(subject.stager_jsp('metasploit')).to include('System.getProperty("jboss.server.home.dir");')
    end

    it "uses the provided application name" do
      expect(subject.stager_jsp('metasploit')).to include('"/deploy/" + "metasploit.war";')
    end
  end

  describe "#create_file_bsh" do
    it "returns the Bean Shell script" do
      expect(subject.create_file_bsh({})).to include('String jboss_home = System.getProperty("jboss.server.home.dir");')
    end

    context "when options are provided" do
      let(:opts) do
        {
          :file     => 'file',
          :dir      => 'dir',
          :contents => 'contents'
        }
      end

      it { expect(subject.create_file_bsh(opts)).to include('String location = jboss_home + "/deploy/file";')}
      it { expect(subject.create_file_bsh(opts)).to include('"/deploy/dir").mkdir()')}
      it { expect(subject.create_file_bsh(opts)).to include('String val = "contents";')}
    end
  end

  describe "#delete_files_bsh" do
    it "returns the Bean Shell script" do
      expect(subject.delete_files_bsh({})).to include('String jboss_home = System.getProperty("jboss.server.home.dir");')
    end

    context "when filenames are provided" do
      let(:opts) do
        {
          'one' => '/tmp/one',
          'two' => '/tmp/two'
        }
      end

      it { expect(subject.delete_files_bsh(opts)).to include('new File(jboss_home + "/deploy//tmp/one").delete();')}
      it { expect(subject.delete_files_bsh(opts)).to include('new File(jboss_home + "/deploy//tmp/two").delete();')}
    end
  end

end
