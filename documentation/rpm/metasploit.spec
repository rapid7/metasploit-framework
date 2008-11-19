%define name metasploit
%define version 3.2
%define release 1
%define prefix /opt
%define __spec_install_post :


BuildArch: noarch
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Group: Applications/System
License: BSD
Name: %{name}
Packager: Ramon de Carvalho Valle <ramon@risesecurity.org>
Release: %{release}
Requires: ruby
Source: %{name}-%{version}.tar.gz
Summary: The Metasploit Framework
URL: http://www.metasploit.com/framework/
Version: %{version}


%description
The Metasploit Framework is a development platform for creating security tools
and exploits. The framework is used by network security professionals to
perform penetration tests, system administrators to verify patch
installations, product vendors to perform regression testing, and security
researchers world-wide. The framework is written in the Ruby programming
language and includes components written in C and assembler.


%prep
%setup -q


%install
rm -rf %{buildroot}
cd ../
mkdir -p %{buildroot}%{prefix}
cp -r %{name}-%{version} %{buildroot}%{prefix}


%clean
rm -rf %{buildroot}


%post
ln -s %{prefix}/%{name}-%{version}/msfcli /usr/local/bin
ln -s %{prefix}/%{name}-%{version}/msfconsole /usr/local/bin
ln -s %{prefix}/%{name}-%{version}/msfd /usr/local/bin
ln -s %{prefix}/%{name}-%{version}/msfelfscan /usr/local/bin
ln -s %{prefix}/%{name}-%{version}/msfencode /usr/local/bin
ln -s %{prefix}/%{name}-%{version}/msfgui /usr/local/bin
ln -s %{prefix}/%{name}-%{version}/msfmachscan /usr/local/bin
ln -s %{prefix}/%{name}-%{version}/msfopcode /usr/local/bin
ln -s %{prefix}/%{name}-%{version}/msfpayload /usr/local/bin
ln -s %{prefix}/%{name}-%{version}/msfpescan /usr/local/bin
ln -s %{prefix}/%{name}-%{version}/msfweb /usr/local/bin


%postun
rm -f %{prefix}/%{name}-%{version}/msfcli
rm -f %{prefix}/%{name}-%{version}/msfconsole
rm -f %{prefix}/%{name}-%{version}/msfd
rm -f %{prefix}/%{name}-%{version}/msfelfscan
rm -f %{prefix}/%{name}-%{version}/msfencode
rm -f %{prefix}/%{name}-%{version}/msfgui
rm -f %{prefix}/%{name}-%{version}/msfmachscan
rm -f %{prefix}/%{name}-%{version}/msfopcode
rm -f %{prefix}/%{name}-%{version}/msfpayload
rm -f %{prefix}/%{name}-%{version}/msfpescan
rm -f %{prefix}/%{name}-%{version}/msfweb



%files
%defattr(-,root,root)
%{prefix}/%{name}-%{version}


%changelog
* Sun Nov 19 2008 Ramon de Carvalho Valle <ramon@risesecurity.org> - 3.2-1
- Changed name to metasploit
- Added post and postun scripts

* Sun Nov 9 2008 Ramon de Carvalho Valle <ramon@risesecurity.org> - 3.2-1
- Initial version

