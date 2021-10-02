#!/usr/bin/perl
# HoneySpy -- advanced honeypot environment
# Copyright (C) 2005  Robert Nowotniak
# Copyright (C) 2005  Michal Wysokinski
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

package Commons;

use Storable qw(nstore_fd freeze thaw);
use Log::Log4perl (':easy');
use Switch;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(
	sendDataToSocket
	validateData
);

my $logger = get_logger();

#
# sendDataToSocket - Metoda statyczna, wysy³a dane na $sock
#
sub sendDataToSocket {
	eval {
		my ($sock, $serialized) = ($_[0], freeze $_[1]);
		print $sock pack('N', length($serialized));
		print $sock $serialized;
	};
	if ($@) {
		$logger->error("Couldn't sent data to a socket");
	}
}


#
# Metoda oceniaj±ca ³añcuch. Czy wystepuje w nim co¶,
# co wskazuje, ¿e jest to jaki¶ atak, exploit itp.
# Zwraca warto¶æ 0..1 -- prawdopodobieñstwo ¿e jest to atak
#
sub validateData {
	my ($data) = @_;
	return 0 unless $data;

	switch ($data) {
		# directory traversal
		case m'\.\./\.\./\.\./'                 { return 0.8; }
		# format string
		case m'(%s.*){2,}'                      { return 0.8; }
		case m'%n'                              { return 1.0; }
		# shell
		case m'bin/sh'                          { return 1.0; }
		case m'bin/\w+sh'                       { return 1.0; }
		# SQL Injection
		case m"'\s*OR (SELECT|UPDATE|INSERT)"   { return 0.8; }
		# unescaped metacharacters
		case m'(;|\|).*wget'                    { return 0.5; }
		# passwd file
		case m'etc\/passwd'                     { return 0.6; }
		# buffer overflow?
		case { length($_[0]) > 256 }            { return 0.5; }
	}

	return 0;
}

