# -*- coding:binary -*-

require 'spec_helper'

describe Msf::Util::EXE do
  include_context 'Msf::Simple::Framework'

  subject(:exe) do
    described_class
  end

  describe '.win32_rwx_exec' do
    it "should contain the shellcode" do
      bin = exe.win32_rwx_exec("asdfjklASDFJKL")
      bin.should include("asdfjklASDFJKL")
    end
  end

  pending 'Msf::Util::EXE.to_executable_fmt compatibility with new ModuleSet API' do
    describe '.to_executable_fmt' do
      it "should output nil when given a bogus format" do
        bin = exe.to_executable_fmt(framework, "", "", "", "does not exist", {})

        bin.should == nil
      end

      include_context 'Msf::Util::Exe'

      @platform_format_map.each do |plat, formats|
        context "with platform=#{plat}" do
          let(:platform) do
            Msf::Module::PlatformList.transform(plat)
          end

          it "should output nil when given bogus format" do
            bin = exe.to_executable_fmt(framework, formats.first[:arch], platform, "\xcc", "asdf", {})
            bin.should == nil
          end
          it "should output nil when given bogus arch" do
            bin = exe.to_executable_fmt(framework, "asdf", platform, "\xcc", formats.first[:format], {})
            bin.should == nil
          end
          [ ARCH_X86, ARCH_X86_64, ARCH_PPC, ARCH_MIPSLE, ARCH_MIPSBE, ARCH_ARMLE ].each do |arch|
            it "returns nil when given bogus format for arch=#{arch}" do
              bin = exe.to_executable_fmt(framework, arch, platform, "\xcc", "asdf", {})
            end
          end

          formats.each do |format_hash|
            fmt   = format_hash[:format]
            arch  = format_hash[:arch]

            if format_hash[:pending]
              pending "returns an executable when given arch=#{arch}, fmt=#{fmt}"
              next
            end

            it "returns an executable when given arch=#{arch}, fmt=#{fmt}" do
              bin = exe.to_executable_fmt(framework, arch, platform, "\xcc", fmt, {})
              bin.should be_a String

              verify_bin_fingerprint(format_hash, bin)
            end

          end

        end
      end

    end
  end
end

