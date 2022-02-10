Name:           python3-pywdns
Version:        0.10.1
Release:        2%{?dist}
Summary:        low-level DNS library (Python3 bindings)

License:        Apache-2.0
URL:            https://github.com/farsightsec/pywdns/
Source0:        https://dl.farsightsecurity.com/dist/pywdns/pywdns-%{version}.tar.gz

#BuildArch:
BuildRequires:  wdns-devel
BuildRequires:  python3-devel python36-Cython
Requires:	wdns

%description
wdns is a low-level DNS library. It contains a fast DNS message parser
and various utility functions for manipulating wire-format DNS data.

This package contains the Python3 extension module for libwdns.


%prep
%setup -q -n pywdns-%{version}


%build
%py3_build


%install
rm -rf $RPM_BUILD_ROOT
%py3_install


%files
%doc
# For arch-specific packages: sitearch
%{python3_sitearch}/*


%changelog
