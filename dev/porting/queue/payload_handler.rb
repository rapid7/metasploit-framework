require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Metasploit Framework Payload Handler',
			'Description'    => %q{
				This module can be used to interact with a payload that was
				not directly injected by the Framework itself. This allows
				you to use payloads from the Metasploit Framework in an
				external program without having to rewrite it as an exploit
				module. This module an be used to interact with standalone
				executable payloads, such as those created by the 'X' action
				of the msfpayload utility.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[

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

package Msf::Exploit::payload_handler;
use base "Msf::Exploit";
use strict;

my $advanced = { };

my $info =
{
	'Name'     => 'Metasploit Framework Payload Handler',
	'Version'  => '$Revision$',
	'Authors'  => [ 'H D Moore <hdm [at] metasploit.com>', ],
	'Arch'     => [ ],
	'OS'       => [ ],
	'Priv'     => 1,
	'UserOpts' => { },
	'Payload'  => 
	{
		'Space'     => 8192,
		'Keys'      => ['+cmd', '+cmd_bash', '+ws2ord'],                  
	},

	'Description'  => Pex::Text::Freeform(qq{
		This module can be used to interact with a payload that was
	not directly injected by the Framework itself. This allows you 
	to use payloads from the Metasploit Framework in an external program
	without having to rewrite it as an exploit module. This module an be
	used to interact with standalone executable payloads, such as those
	created by the 'X' action of the msfpayload utility.
	}),

	'Refs'     =>  [   ],

	'DefaultTarget'	=> 0,
	'Targets'  => [ ['No Target Needed'] ],
	'Keys'     => [ 'framework' ],
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
  return($self);
}

sub Exploit {
	my $self = shift;
	$self->PrintLine("[*] Attempting to handle the selected payload...");
	while(1) { select(undef, undef, undef, 1) }
	return;
}


1;

=end


end
end	
