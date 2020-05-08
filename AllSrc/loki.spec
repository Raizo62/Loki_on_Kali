Name:           loki
Version:        0.2.7
Release:        1%{?dist}
Summary:        loki

License:        BSD
URL:            http://codecafe.de
Source0:        http://codecafe.de/loki/loki-0.2.7.tar.gz

BuildRequires:  automake autoconf python-devel libpcap-devel libdnet-devel openssl-devel
Requires:       python pylibpcap libdnet-python python-IPy python-dpkt pygtk2 openssl pygtk2-libglade python-urwid

%description


%prep
%setup -q
autoreconf -fvi -I m4
sed -i "s/+ e/+ str(e)/g" setup.py.in

%build
./configure --prefix=/usr --with-gtk --with-urwid
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%files
%doc
%{python2_sitearch}/*
%{python2_sitelib}/*
/usr/bin/loki_gtk.py
/usr/bin/loki_urw.py
/usr/bin/mpls_tunnel
/usr/bin/pppoe_tunnel
/usr/share/loki/*



%changelog
