require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Local System Shell',
			'Description'    => %q{
				Demonstration of executing a local command shell.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[

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

package Msf::Exploit::local_shell;
use base "Msf::Exploit";
use strict;
use IO::Socket;
use Fcntl qw/F_SETFD F_GETFD/;

my $advanced = { };

my $info =
{
	'Name'  => 'Local System Shell',
	'Version'  => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>', ],
	'Arch'  => [ ],
	'OS'    => [ ],
	'Priv'  => 0,
	'UserOpts'  => 
	{

	},

	'Payload' => 
	{
		'Space'     => 1024,
		'Keys'      => ['cmd_localshell'],                  
	},

	'Description'  => Pex::Text::Freeform(qq{
		Demonstration of executing a local command shell.
	}),

	'Refs'  =>  
	[  
	],

	'DefaultTarget'	=> 0,
	'Targets'	=> [['No Target Needed']],
	'Keys'	=> ['local'],
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
  return($self);
}


sub Exploit {
	my $self = shift;
	my $shellcode   = $self->GetVar('EncodedPayload')->RawPayload;
	my ($par, $chi);

	# Disable close-on-exec flags...
	$^F	= 1024;
	
	# Create the socket-pair to the forked child
	socketpair($par, $chi, AF_UNIX, SOCK_STREAM, PF_UNSPEC);

	$self->PrintLine("[*] Executing local command shell");
	my $child = fork();
	
	if (! $child) {

		close($par);		
		open( STDIN, "<&=", fileno($chi));
		open(STDOUT, ">&=", fileno($chi));
		open(STDERR, ">&=", fileno($chi));

		exec('sh', '-i') || exec('cmd.exe');
		exit(0);
	}
	
	close($chi);

	# Interact with the forked shell
	$self->Handler($par);
	return;
}


1;

=end


end
end	
