#!/bin/bash
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

#
# Skrypt do przygotowywania certyfikatow i kluczy
# dla projektu HoneySpy
#

DAYS=365
COUNTRY=PL

readkey() {
	local yn
	while :; do
		echo "$1 [y/n]"
		read -n 1 -s yn
		[ "$yn" = y -o "$yn" = n ] && break
	done
	[ $yn = y ];
}

echo -n '' > demoCA/index.txt

if [ "$1" = 'clean' ]; then
	if readkey 'Delete ALL keys and certificates?'; then
		rm *.enc *.pem *.csr && echo "Done";
		exit 0;
	fi
	exit 1;
fi

if [ "$1" = 'master' ]; then
	echo 'Creating keys and certificate for master server.'
	echo 'Certificate will be used for this network certification authority as well'
	echo

	openssl genrsa -des3 -out master-key.enc 1024
	openssl rsa -in master-key.enc -out master-key.pem
	openssl req -subj '/C='$COUNTRY'/O=HoneySpy network/OU=Master Server/CN=Master' -new -x509 -days $DAYS -key master-key.pem -out master-cert.pem

	echo
	readkey 'Show certificate?' && \
		openssl x509 -noout -text -in master-cert.pem

	exit 0
fi

if [ "$1" = 'sensor' ]; then
	echo "Creating keys and certificate for sensor"

	echo "Sensor's name: "
	read name
	[ "$name" ] || exit 1

	openssl genrsa -des3 -out "$name-key.enc" 1024
	openssl rsa -in "$name-key.enc" -out "$name-key.pem"
	openssl req -subj "/C=$COUNTRY/O=HoneySpy network/OU=$1/CN=$name" -new -key "$name-key.pem" -out "$name.csr"

	exit 0;
fi

if [ "$1" = 'sign' ]; then
	echo 'Signing node'\''s certificate'
	echo

	if [ ! -f master-key.pem -o ! -f master-cert.pem ]; then
		echo "Error: There is no master's key nor certificate"
		echo "Please use ,,$0 master'' first"
		echo
		exit 1
	fi

	echo "Signature request file (.csr):";
	read csr
	[ -z "$csr" ] && exit 1

	if [ ! -f "$csr" ]; then
		echo "No such file: $csr"
		exit 1
	fi

	echo "Certificate (output) file name:"
	read result
	[ -z "$result" ] && exit 1

	openssl ca -policy policy_anything -keyfile master-key.pem \
		-cert master-cert.pem -in "$csr" -out "$result"

	echo
	readkey 'Show certificate?' && \
		openssl x509 -noout -text -in "$result"

	exit 0
fi

if [ "$1" = 'admin' ]; then
	echo "Creating keys and certificate for admin"
	echo 

	name='admin'
	if [ -e "$name-key.pem" -o -e "$name-cert.pem" ]; then
		echo "Admin's key or certificate already exists";
		exit 1
	fi

	openssl genrsa -des3 -out "$name-key.enc" 1024
	openssl rsa -in "$name-key.enc" -out "$name-key.pem"
	openssl req -subj "/C=$COUNTRY/O=HoneySpy network/OU=$1/CN=$name" -new -key "$name-key.pem" -out "$name.csr"

	exit 0
fi


echo -e "Usage:\n\t$0 clean|master|sensor|admin|sign";

