#!/usr/bin/perl -w
#
# (c) 20180127 Robert Martin-Legene
#

use strict;
use warnings;
use Net::DNS::Packet;
use Net::DNS::Resolver;
use Data::Dumper;
our %SIG;
my  $debugpacket;
use Getopt::Long        qw( GetOptionsFromArray );
my  $label          =   qr/[A-Za-z\d](?:[A-Za-z\d\-]{0,61}[A-Za-z\d])?/o;
my  $fqdn           =   qr/^${label}(?:\.${label})*\.?$/o;
my  $ipv4           =   qr/^(?:\d+\.){3}\d+$/o;
my  $ipv6           =   qr/^[\dA-Fa-f:]+$/o;
my  $keyname        =   'timetest';
# md5 of empty string - (can be anything, really)
my  $key            =   'd41d8cd98f00b204e9800998ecf8427e';
my  $quiet          =   0;
my  $verbose        =   0;
my  $longest_name   =   1;
my  $normal_length;
my  $already_tested;

sub usage
{
    my  $error  =   shift;
    printf STDERR "%s\n", $error if defined $error;
    printf STDERR "%s [--verbose] [--quiet] [--tolerance <number-of-seconds>] <nameserver> [... <nameserver>]\n", $0;
    exit 1;
}

sub niceprint
{
    my ($ip, $name) = @_;
    my $format = "[%15s] %-${longest_name}s";
    $normal_length = length sprintf($format, '','') unless defined $normal_length;
    my $txt = sprintf $format, $ip, $name;
    # Strip off leading spaces if we are "too long"
    # (eg if we printed an IPv6 address)
    1 while length $txt > $normal_length and $txt =~ s/ $//;
    return $txt;
}

sub when
{
    my ($packet) = @_;
    my @rrs;
    $debugpacket = $packet;
    if ( $verbose > 2 )
    {
        local $SIG{__WARN__} = sub
        {
            print shift, Dumper($debugpacket);
        };
    }
    # CommunityDNS generates truncated packets, it seems
    #local $SIG{__WARN__} = sub {};
    eval {
        @rrs = $packet->additional;
    };
    foreach my $rr (@rrs)
    {
        next unless $rr->type eq 'TSIG';
        return $rr->time_signed;
    }
    return;
}

sub main
{
    my  $ns         =   '';
    my  $domain     =   '.';
    my  $rrtype     =   'NS';
    my  $tolerance  =   10;
    GetOptionsFromArray(
        \@_,
        'verbose|v'     =>  sub { $verbose++ },
        'quiet'         =>  \$quiet,
        'domain=s'      =>  \$domain,
        'rrtype=s'      =>  \$rrtype,
        'tolerance=i'   =>  \$tolerance,
    );
    die 'You can not specify verbose and quiet at the same time, stopped'
        if $verbose and $quiet;
    my  @servers        =   @_;
    ($longest_name)     =   reverse sort {$a<=>$b} (map { length } @servers);
    usage('No name server specified.') unless @servers;
    for my $ns ( @servers )
    {
        ns_check( $ns, $domain, $rrtype );
    }
}

sub addresses
{
    my      $ns     =   shift;
    printf qq/# Looking up addresses for name server "%s"\n/, $ns if $verbose > 1;
    return ($ns) if $ns =~ $ipv4 or $ns =~ $ipv6;
    my      $res    = Net::DNS::Resolver->new(recurse => 1);
    my      @ip;
    for my $type ( 'A', 'AAAA' )
    {
        my $response   =   $res->query($ns, $type);
        if ( $response )
        {
            if ( $verbose > 2 )
            {
                print qq/# Got address reply for "%s".\n/, $ns;
                $response->print;
            }
            for my $ip ($response->answer)
            {
                next if $ip->type ne $type;
                push @ip, $ip->address;
            }
        }
    }
#print Dumper( @ip );
    return @ip if @ip;
    printf
        STDERR
        qq/Can not find the address of the name server called "%s".\n/,
        $ns;
    return;
}

sub ns_check
{
    my  ( $ns, $domain, $rrtype )   =   @_;
    return if exists $already_tested->{$ns};
    $already_tested->{$ns} = 1;
    if ( $ns !~ $fqdn )
    {
        printf STDERR qq/Name server "$ns" not found./;
        return;
    }
    my  @ip         =   addresses( $ns );
    return unless @ip;
    my  $res        =   Net::DNS::Resolver->new(
        recurse         =>  0,
        retrans         =>  1,
        retry           =>  1,
    );
    my  $response;
    my  $when_out;
    foreach my $addr ( @ip )
    {
        $res->nameservers( $addr );
        my  $packet     =   Net::DNS::Packet->new($domain, $rrtype);
        $packet->sign_tsig($keyname, $key);
        $when_out       =   when($packet);
        printf "# Sending to %s\n", nicename($addr, $ns) if $verbose;
        $response       =   $res->send($packet);
        if ( defined $response )
        {
            last;
        }
        else
        {
            printf STDERR qq/%s did not respond.\n/, niceprint($addr,$ns);
        }
    }
    return unless defined $response;

    # The next line makes sure the response packet will actually
    # get parsed by Net::DNS
    $response->header;

    my  $when_in    =   when($response);
    my  $when_diff  =   $when_in - $when_out if defined $when_in;
    if    ( not defined $when_diff )
    {
        printf STDERR qq/%s answered without a TSIG.\n/,
            niceprint( $response->answerfrom, $ns );
    }
    elsif ( not $quiet )
    {
        my $direction   =   $when_diff < 0 ? 'behind' : 'ahead of';
        my $plural      =   abs($when_diff)==1 ? '' : 's';
        printf
            "%s is %2d second%1s %s us.\n",
            niceprint( $response->answerfrom, $ns ),
            abs( $when_diff ),
            $plural,
            $direction;
    }
    $response->print if $verbose > 1;
}

main( @ARGV ) ;
