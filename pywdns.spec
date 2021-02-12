# sitelib for noarch packages, sitearch for others (remove the unneeded one)
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python_sitearch: %global python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}

Name:           python-pywdns
Version:        0.10.0
Release:        1%{?dist}
Summary:        low-level DNS library (Python bindings)

License:        Apache-2.0
URL:            https://github.com/farsightsec/pywdns/
Source0:        https://dl.farsightsecurity.com/dist/pywdns/pywdns-%{version}.tar.gz

#BuildArch:
BuildRequires:  python-devel wdns-devel Cython
Requires:	wdns

%description
wdns is a low-level DNS library. It contains a fast DNS message parser
and various utility functions for manipulating wire-format DNS data.

This package contains the Python extension module for libwdns.


%prep
%setup -q -n pywdns-%{version}


%build
# Remove CFLAGS=... for noarch packages (unneeded)
CFLAGS="$RPM_OPT_FLAGS" %{__python} setup.py build


%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT


%files
%doc
# For arch-specific packages: sitearch
%{python_sitearch}/*


%changelog
