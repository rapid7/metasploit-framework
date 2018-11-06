# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.

    #
    # Converts a raw string into a ruby buffer
    #
    def self.to_ruby(str, wrap = DefaultWrap, name = "buf")
      return hexify(str, wrap, '"', '" +', "#{name} = \n", '"')
    end

    #
    # Creates a ruby-style comment
    #
    def self.to_ruby_comment(str, wrap = DefaultWrap)
      return wordwrap(str, 0, wrap, '', '# ')
    end

    #
    # Converts a raw string into a C buffer
    #
    def self.to_c(str, wrap = DefaultWrap, name = "buf")
      return hexify(str, wrap, '"', '"', "unsigned char #{name}[] = \n", '";')
    end

    def self.to_csharp(str, wrap = DefaultWrap, name = "buf")
      ret = "byte[] #{name} = new byte[#{str.length}] {"
      i = -1;
      while (i += 1) < str.length
        ret << "\n" if i%(wrap/4) == 0
        ret << "0x" << str[i].unpack("H*")[0] << ","
      end
      ret = ret[0..ret.length-2] #cut off last comma
      ret << " };\n"
    end

    #
    # Creates a c-style comment
    #
    def self.to_c_comment(str, wrap = DefaultWrap)
      return "/*\n" + wordwrap(str, 0, wrap, '', ' * ') + " */\n"
    end

    #
    # Creates a javascript-style comment
    #
    def self.to_js_comment(str, wrap = DefaultWrap)
      return wordwrap(str, 0, wrap, '', '// ')
    end

    #
    # Converts a raw string into a perl buffer
    #
    def self.to_perl(str, wrap = DefaultWrap, name = "buf")
      return hexify(str, wrap, '"', '" .', "my $#{name} = \n", '";')
    end

    #
    # Converts a raw string into a python buffer
    #
    def self.to_python(str, wrap = DefaultWrap, name = "buf")
      return hexify(str, wrap, "#{name} += \"", '"', "#{name} =  \"\"\n", '"')
    end

    #
    # Converts a raw string into a Bash buffer
    #
    def self.to_bash(str, wrap = DefaultWrap, name = "buf")
      return hexify(str, wrap, '$\'', '\'\\', "export #{name}=\\\n", '\'')
    end

    #
    # Converts a raw string into a java byte array
    #
    def self.to_java(str, name = "shell")
      buff = "byte #{name}[] = new byte[]\n{\n"
      cnt = 0
      max = 0
      str.unpack('C*').each do |c|
        buff << ", " if max > 0
        buff << "\t" if max == 0
        buff << sprintf('(byte) 0x%.2x', c)
        max +=1
        cnt +=1

        if (max > 7)
          buff << ",\n" if cnt != str.length
          max = 0
        end
      end
      buff << "\n};\n"
      return buff
    end

    #
    # Converts a raw string to a vbscript byte array
    #
    def self.to_vbscript(str, name = "buf")
      return "#{name}" if str.nil? or str.empty?

      code = str.unpack('C*')
      buff = "#{name}=Chr(#{code[0]})"
      1.upto(code.length-1) do |byte|
        if(byte % 100 == 0)
          buff << "\r\n#{name}=#{name}"
        end
        # exe is an Array of bytes, not a String, thanks to the unpack
        # above, so the following line is not subject to the different
        # treatments of String#[] between ruby 1.8 and 1.9
        buff << "&Chr(#{code[byte]})"
      end

      return buff
    end

    #
    # Converts a raw string into a vba buffer
    #
    def self.to_vbapplication(str, name = "buf")
      return "#{name} = Array()" if str.nil? or str.empty?

      code  = str.unpack('C*')
      buff = "#{name} = Array("
      maxbytes = 80

      1.upto(code.length) do |idx|
        buff << code[idx].to_s
        buff << "," if idx < code.length - 1
        buff << " _\r\n" if (idx > 1 and (idx % maxbytes) == 0)
      end

      buff << ")\r\n"

      return buff
    end

    #
    # Creates a perl-style comment
    #
    def self.to_perl_comment(str, wrap = DefaultWrap)
      return wordwrap(str, 0, wrap, '', '# ')
    end

    #
    # Creates a Bash-style comment
    #
    def self.to_bash_comment(str, wrap = DefaultWrap)
      return wordwrap(str, 0, wrap, '', '# ')
    end

  end
end
