

shared_context 'Msf::Util::Exe' do
  @platform_format_map = {
    "windows" => [
      { :format => "dll",       :arch => "x86", :file_fp => /PE32 .*DLL/  },
      { :format => "dll",       :arch => "x64", :file_fp => /PE32\+.*DLL/ },
      { :format => "exe",       :arch => "x86", :file_fp => /PE32 /  },
      { :format => "exe",       :arch => "x64", :file_fp => /PE32\+/ },
      { :format => "exe",       :arch => "x86_64", :file_fp => /PE32\+/ },
      { :format => "exe-small", :arch => "x86", :file_fp => /PE32 /  },
      # No template for 64-bit exe-small. That's fine, we probably
      # don't need one.
      #{ :format => "exe-small", :arch => "x64", :file_fp => /PE32\+/ },
      { :format => "exe-only",  :arch => "x86", :file_fp => /PE32 /  },
      { :format => "exe-only",  :arch => "x64", :file_fp => /PE32\+ /  },
      { :format => "exe-only",  :arch => "x86_64", :file_fp => /PE32\+ /  },
      { :format => "exe-service",  :arch => "x86", :file_fp => /PE32 /  },
      { :format => "exe-service",  :arch => "x64", :file_fp => /PE32\+ /  },
      { :format => "exe-service",  :arch => "x86_64", :file_fp => /PE32\+ /  },
    ],
    "linux" => [
      { :format => "elf", :arch => "x86",    :file_fp => /ELF 32.*SYSV/ },
      { :format => "elf", :arch => "x64",    :file_fp => /ELF 64.*SYSV/ },
      { :format => "elf", :arch => "armle",  :file_fp => /ELF 32.*ARM/ },
      { :format => "elf", :arch => "mipsbe", :file_fp => /ELF 32-bit MSB executable, MIPS/ },
      { :format => "elf", :arch => "mipsle", :file_fp => /ELF 32-bit LSB executable, MIPS/ },
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
      { :format => "macho", :arch => "armle", :file_fp => /Mach-O.*(acorn|arm)/ },
      { :format => "macho", :arch => "ppc",   :file_fp => /Mach-O.*ppc/   },
    ],
  }

  def verify_bin_fingerprint(format_hash, bin)
    bin.should be_a(String)
    fp = IO.popen("file -","w+") do |io|
      io.write(bin)
      io.close_write
      io.read
    end
    if format_hash[:file_fp]
      fp.should =~ format_hash[:file_fp]
    end
  end
end
