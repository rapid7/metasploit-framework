# -*- coding:binary -*-

require 'msf/core'
require 'msf/base/simple'

describe Msf::Util::EXE do

  subject do
    described_class
  end

  $framework = Msf::Simple::Framework.create(
    :module_types => [ Msf::MODULE_NOP ],
    'DisableDatabase' => true
  )

  context '.to_executable_fmt' do
    it "should output nil when given a bogus format" do
      bin = subject.to_executable_fmt($framework, "", "", "", "does not exist", {})

      bin.should == nil
    end

    platform_format_map = {
      "windows" => [
        { :format => "dll",       :arch => "x86", :file_fp => /PE32 .*DLL/  },
        { :format => "dll",       :arch => "x64", :file_fp => /PE32\+.*DLL/ },
        { :format => "exe",       :arch => "x86", :file_fp => /PE32 /  },
        { :format => "exe",       :arch => "x64", :file_fp => /PE32\+/ },
        { :format => "exe-service",       :arch => "x86", :file_fp => /PE32 /  },
        { :format => "exe-service",       :arch => "x64", :file_fp => /PE32\+/ },
        { :format => "exe-small", :arch => "x86", :file_fp => /PE32 /  },
        # No template for 64-bit exe-small. That's fine, we probably
        # don't need one.
        #{ :format => "exe-small", :arch => "x64", :file_fp => /PE32\+/ },
      ],
      "linux" => [
        { :format => "elf", :arch => "x86",  :file_fp => /ELF 32.*SYSV/ },
        { :format => "elf", :arch => "x64",  :file_fp => /ELF 64.*SYSV/ },
        { :format => "elf", :arch => "armle",:file_fp => /ELF 32.*ARM/, :pending => true },
      ],
      "bsd" => [
        { :format => "elf", :arch => "x86", :file_fp => /ELF 32.*BSD/ },
      ],
      "solaris" => [
        { :format => "elf", :arch => "x86", :file_fp => /ELF 32/ },
      ],
      "osx" => [
        { :format => "macho", :arch => "x86",   :file_fp => /Mach-O.*i386/  },
        { :format => "macho", :arch => "x64",   :file_fp => /Mach-O 64/     },
        { :format => "macho", :arch => "armle", :file_fp => /Mach-O.*acorn/, :pending => true },
        { :format => "macho", :arch => "ppc",   :file_fp => /Mach-O.*ppc/,   :pending => true },
      ]
    }

    platform_format_map.each do |plat, formats|
      context "with platform=#{plat}" do
        let(:platform) do
          Msf::Module::PlatformList.transform(plat)
        end

        it "should output nil when given bogus format" do
          bin = subject.to_executable_fmt($framework, formats.first[:arch], platform, "\xcc", "asdf", {})
          bin.should == nil
        end
        it "should output nil when given bogus arch" do
          bin = subject.to_executable_fmt($framework, "asdf", platform, "\xcc", formats.first[:format], {})
          bin.should == nil
        end

        formats.each do |format_hash|
          fmt   = format_hash[:format]
          arch  = format_hash[:arch]

          if format_hash[:pending]
            pending "returns an executable when given arch=#{arch}, fmt=#{fmt}"
            next
          end

          it "returns an executable when given arch=#{arch}, fmt=#{fmt}" do
            bin = subject.to_executable_fmt($framework, arch, platform, "\xcc", fmt, {})
            bin.should be_a String

            f = IO.popen("file -","w+")
            f.write(bin)
            f.close_write
            fp = f.read
            f.close
            fp.should =~ format_hash[:file_fp] if format_hash[:file_fp]
          end

          it "returns nil when given bogus format for arch=#{arch}" do
            bin = subject.to_executable_fmt($framework, arch, platform, "\xcc", "asdf", {})
            bin.should == nil
          end

        end

      end
    end

  end

end

