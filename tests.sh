#!/bin/bash

URL=ftp://ftp.rs.internic.net/domain/root.zone

if [ ! -e root.zone ]
then
    echo Downloading $URL
    if   which curl >/dev/null
    then
        curl --output root.zone $URL
    elif which wget >/dev/null
    then
        wget  $URL
    elif which fetch >/dev/null
    then
        fetch $URL
    else
        echo Or not. >&2
        exit 1
    fi
fi

nameservers=`
        expand root.zone    |
        grep -E ' IN +A+ +' |
        awk '{print $1}'    |
        uniq -i
    `

./tsig-timechecker.pl $nameservers
