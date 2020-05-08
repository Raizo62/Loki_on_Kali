# Copyright 1999-2009 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/dev-libs/libdnet/libdnet-1.11-r1.ebuild,v 1.10 2009/05/09 14:50:51 klausman Exp $

#WANT_AUTOMAKE=1.6
inherit eutils autotools

DESCRIPTION="simplified, portable interface to several low-level networking routines"
HOMEPAGE="http://libdnet.sourceforge.net/"
SRC_URI="mirror://sourceforge/libdnet/${P}.tar.gz"

LICENSE="LGPL-2"
SLOT="0"
KEYWORDS="alpha amd64 hppa ia64 ppc ppc64 sparc x86"
IUSE="python"
DEPEND="=net-firewall/iptables-1.4.3.2"

src_unpack() {
	unpack ${A}
	cd "${S}"
	sed -i 's/suite_free(s);//' test/check/*.c || die "sed failed"
	epatch "${FILESDIR}"/${PN}-1.11-py26.diff
	epatch "${FILESDIR}"/${PN}-1.11-iptables.diff
	AT_M4DIR="config"
	eautoreconf
}

src_compile () {
	econf $(use_with python) || die "econf failed"
	emake || die "emake failed"
}

src_test() {
	einfo "self test fails with permission problems"
}

src_install () {
	emake DESTDIR="${D}" install || die "make install failed"
	dodoc README THANKS TODO
}
