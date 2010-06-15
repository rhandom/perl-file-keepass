#!/usr/bin/perl

=head1 NAME

File::KeePass - Interface to KeePass V1 database files

=cut

File::KeePass->new->run,exit if $0 eq __FILE__;

package File::KeePass;

use strict;
use warnings;
use CGI::Ex::Dump qw(debug);
use Carp qw(croak);
use Crypt::Rijndael;
use Digest::SHA qw(sha256);

use constant DB_HEADER_SIZE    => 124;
use constant PWM_DBSIG_1       => 0x9AA2D903;
use constant PWM_DBSIG_2       => 0xB54BFB65;
use constant PWM_DBVER_DW      => 0x00030002;
use constant PWM_FLAG_SHA2     => 1;
use constant PWM_FLAG_RIJNDAEL => 2;
use constant PWM_FLAG_ARCFOUR  => 4;
use constant PWM_FLAG_TWOFISH  => 8;

sub new {
    my $class = shift;
    return bless {}, $class;
}

sub run {
    my $self = shift;
    my $file = shift || shift(@ARGV) || croak "Usage: $0 file.kdb\n";
    my $pass = shift || shift(@ARGV) || do { require IO::Prompt; ''.IO::Prompt::prompt("Enter your master key: ", -e => '*') };
    my $groups = $self->load_db($file, $pass);
    $self->dump_groups($_) for @$groups;
}

sub load_db {
    my $self = shift;
    my $file = shift || croak "Missing file";
    my $pass = shift || croak "Missing pass";

    open(my $fh, '<', $file) || croak "Couldn't open $file: $!";
    my $total_size = -s $file;
    read($fh, my $buffer, $total_size);
    close $fh;
    croak "Couldn't read entire file" if length($buffer) != $total_size;
    croak "Unexpected file size ($total_size < ".DB_HEADER_SIZE().")" if $total_size < DB_HEADER_SIZE;

    return $self->parse_db($buffer, $pass);
}

sub parse_db {
    my ($self, $buffer, $pass) = @_;

    # read in the headers
    my $sig1       = unpack 'L', substr($buffer,   0, 4);    # memcpyFromLEnd32(&sig1,buffer);
    my $sig2       = unpack 'L', substr($buffer,   4, 4);    # memcpyFromLEnd32(&sig2,buffer+4);
    my $flags      = unpack 'L', substr($buffer,   8, 4);    # memcpyFromLEnd32(&Flags,buffer+8);
    my $ver        = unpack 'L', substr($buffer,  12, 4);    # memcpyFromLEnd32(&Version,buffer+12);
    my $seed_rand  = substr($buffer,  16, 16);   # memcpy(FinalRandomSeed,buffer+16,16);
    my $enc_iv     = substr($buffer,  32, 16);   # memcpy(EncryptionIV,buffer+32,16);
    my $n_groups   = unpack 'L', substr($buffer,  48, 4);    # memcpyFromLEnd32(&NumGroups,buffer+48);
    my $n_entries  = unpack 'L', substr($buffer,  52, 4);    # memcpyFromLEnd32(&NumEntries,buffer+52);
    my $checksum   = substr($buffer,  56, 32);   # memcpy(ContentsHash,buffer+56,32);
    my $seed_key   = substr($buffer,  88, 32);   # memcpy(TransfRandomSeed,buffer+88,32);
    my $seed_rot_n = unpack 'L', substr($buffer, 120, 4);    # memcpyFromLEnd32(&KeyTransfRounds,buffer+120);
    die "Wrong sig1 ($sig1 != ".PWM_DBSIG_1().")\n" if $sig1 != PWM_DBSIG_1;
    die "Wrong sig2 ($sig2 != ".PWM_DBSIG_2().")\n" if $sig2 != PWM_DBSIG_2;
    die "Unsupported File version ($ver).\n" if $ver & 0xFFFFFF00 != PWM_DBVER_DW & 0xFFFFFF00;
    my $enc_type = ($flags & PWM_FLAG_RIJNDAEL) ? 'Rijndael_Cipher'
                 : ($flags & PWM_FLAG_TWOFISH)  ? 'Twofish_Cipher'
                 : die "Unknown Encryption Algorithm.";

    # use the headers to generate our encryption key in conjunction with the password
    my $key = sha256($pass);
    my $cipher = Crypt::Rijndael->new($seed_key, Crypt::Rijndael::MODE_ECB());
    $key = $cipher->encrypt($key) for 1 .. $seed_rot_n;
    $key = sha256($key);
    $key = sha256($seed_rand, $key);

    # decrypt the buffer
    my $crypto_size;
    if ($enc_type eq 'Rijndael_Cipher') {
        my $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());
        $cipher->set_iv($enc_iv);
        my $orig_size = length($buffer);
        $buffer = $cipher->decrypt(substr($buffer,DB_HEADER_SIZE));
        my $extra = ord(substr $buffer, -1, 1);
        $crypto_size = $orig_size - DB_HEADER_SIZE - $extra;
        $buffer = substr($buffer, 0, $crypto_size);
    } else {
        die "Unimplemented enc_type $enc_type";
    }
    die "Decryption failed.\nThe key is wrong or the file is damaged."
        if $crypto_size > 2147483446 || (!$crypto_size && $n_groups);
    die "Hash test failed.\nThe key is wrong or the file is damaged (or we need to implement utf8 input a bit better)"
        if $checksum ne sha256($buffer);

    # read the db
    my ($groups, $gmap, $pos) = $self->parse_groups($buffer, $n_groups);
    $self->parse_entries($buffer, $n_entries, $pos, $gmap, $groups);
    return $groups;
}

sub parse_groups {
    my ($self, $buffer, $n_groups) = @_;
    my $pos = 0;

    my %gmap; # allow entries to find their groups (group map)
    my @groups;
    my @gref = (\@groups);
    my $previous_level = 0;
    my $group = {};
    while ($n_groups) {
        my $type = unpack 'S', substr($buffer, $pos, 2);
        $pos += 2;
        die "Unexpected error: Offset is out of range. ($pos)" if $pos >= length($buffer);

        my $size = unpack 'L', substr($buffer, $pos, 4);
        $pos += 4;
        die "Unexpected error: Offset is out of range. ($pos, $size)" if $pos + $size > length($buffer);

        if ($type == 1) {
            $group->{'id'} = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 2) {
            $group->{'title'} = substr($buffer, $pos, $size);
            $group->{'title'} =~ s/\0$//;
        } elsif ($type == 7) {
            $group->{'image'} = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 8) {
            $group->{'level'} = unpack 'S', substr($buffer, $pos, 2);
        } elsif ($type == 0xFFFF) {
            $n_groups--;
            $gmap{$group->{'id'}} = $group;
            my $level = $group->{'level'} || 0;
            if ($previous_level > $level) {
                splice @gref, $previous_level, $previous_level - $level, ();
            } elsif ($previous_level < $level) {
                push @gref, ($gref[-1]->[-1]->{'groups'} = []);
            }
            $previous_level = $level;
            push @{ $gref[-1] }, $group;
            $group = {};
        }
        $pos += $size;
    }

    return (\@groups, \%gmap, $pos);
}

sub parse_entries {
    my ($self, $buffer, $n_entries, $pos, $gmap, $groups) = @_;

    my $entry = {};
    while ($n_entries) {
        my $type = unpack 'S', substr($buffer, $pos, 2);
        $pos += 2;
        die "Unexpected error: Offset is out of range. ($pos)" if $pos >= length($buffer);

        my $size = unpack 'L', substr($buffer, $pos, 4);
        $pos += 4;
        die "Unexpected error: Offset is out of range. ($pos, ".length($buffer).", $size)" if $pos + $size > length($buffer);

        if ($type == 1) {
            $entry->{'uuid'} = 1 #KpxUuid(pData);
        } elsif ($type == 2) {
            $entry->{'group_id'} = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 3) {
            $entry->{'image'} = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 4) {
            $entry->{'title'} = substr($buffer, $pos, $size);
            $entry->{'title'} =~ s/\0$//;
        } elsif ($type == 5) {
            $entry->{'url'} = substr($buffer, $pos, $size);
            $entry->{'url'} =~ s/\0$//;
        } elsif ($type == 6) {
            $entry->{'username'} = substr($buffer, $pos, $size);
            $entry->{'username'} =~ s/\0$//;
        } elsif ($type == 7) {
            $entry->{'password'} = substr($buffer, $pos, $size);
            $entry->{'password'} =~ s/\0$//;
        } elsif ($type == 8) {
            $entry->{'comment'} = substr($buffer, $pos, $size);
            $entry->{'comment'} =~ s/\0$//;
	#case 0x0009:	entry->Creation=dateFromPackedStruct5(pData);
	#case 0x000A:	entry->LastMod=dateFromPackedStruct5(pData);
	#case 0x000B:	entry->LastAccess=dateFromPackedStruct5(pData);
	#case 0x000C:	entry->Expire=dateFromPackedStruct5(pData);
	} elsif ($type == 0x000D) {
            $entry->{'binary_desc'} = substr($buffer, $pos, $size);
	} elsif ($type == 0x000E) {
            $entry->{'binary'} = substr($buffer, $pos, $size);
        } elsif ($type == 0xFFFF) {
            $n_entries--;
            my $gid = delete $entry->{'group_id'};
            my $ref = $gmap->{$gid};
            if (!$ref) { # orphaned nodes go in special group
                $ref = $gmap->{0} = {id => 0, title => '*Orphaned*', image => 0};
                push @$groups, $ref;
            }

            if (     $entry->{'comment'} && $entry->{'comment'} eq 'KPX_CUSTOM_ICONS_4') {
            } elsif ($entry->{'comment'} && $entry->{'comment'} eq 'KPX_GROUP_TREE_STATE') {
                if (!defined($entry->{'binary'}) || length($entry->{'binary'}) < 4) {
                    warn "Discarded metastream KPX_GROUP_TREE_STATE because of a parsing error."
                } else {
                    my $n = unpack 'L', substr($entry->{'binary'}, 0, 4);
                    if ($n * 5 != length($entry->{'binary'}) - 4) {
                        warn "Discarded metastream KPX_GROUP_TREE_STATE because of a parsing error.";
                    } else {
                        for (my $i = 0; $i < $n; $i++) {
                            my $group_id    = unpack 'L', substr($entry->{'binary'}, 4 + $i * 5, 4);
                            my $is_expanded = unpack 'C', substr($entry->{'binary'}, 8 + $i * 5, 1);
                            $gmap->{$group_id}->{'expanded'} = $is_expanded;
                        }
                    }
            }
            } else {
                push @{ $ref->{'entries'} }, $entry;
            }
            $entry = {};
        }
        $pos += $size;
    }
}

sub dump_groups {
    my ($self, $g, $indent) = @_;
    $indent = '' if ! $indent;
    print $indent.($g->{'expanded'} ? '-' : '+')."  $g->{'title'} ($g->{'id'}) $g->{'level'}\n";
    $self->dump_groups($_, "$indent    ") for @{ $g->{'groups'} || [] };
    for my $e (@{ $g->{'entries'} || [] }) {
        print "$indent    > $e->{'title'} ($e->{'username'})\n";
    }
}

1;
