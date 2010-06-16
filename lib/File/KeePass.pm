#!/usr/bin/perl

=head1 NAME

File::KeePass - Interface to KeePass V1 database files

=cut

File::KeePass::run(),exit if $0 eq __FILE__;

package File::KeePass;

use strict;
use warnings;
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

our $VERSION = '0.01';

sub new {
    my $class = shift;
    return bless {}, $class;
}

sub run {
    my $self = ref($_[0]) ? shift() : __PACKAGE__->new;
    my $file = shift || shift(@ARGV) || croak "Usage: $0 file.kdb\n";
    my $pass = shift || shift(@ARGV) || do { require IO::Prompt; ''.IO::Prompt::prompt("Enter your master key: ", -e => '*') };
    my $groups = $self->load_db($file, $pass);
    $self->dump_groups($_) for @$groups;
}

sub load_db {
    my $self = shift;
    my $file = shift || croak "Missing file\n";
    my $pass = shift || croak "Missing pass\n";

    open(my $fh, '<', $file) || croak "Couldn't open $file: $!\n";
    my $total_size = -s $file;
    read($fh, my $buffer, $total_size);
    close $fh;
    croak "Couldn't read entire file contents.\n" if length($buffer) != $total_size;
    croak "File was smaller than db header ($total_size < ".DB_HEADER_SIZE().")\n" if $total_size < DB_HEADER_SIZE;

    return $self->parse_db($buffer, $pass);
}

sub parse_db {
    my ($self, $buffer, $pass) = @_;

    my $head = $self->parse_header($buffer);
    my $gen = $self->gen_header($head);

    die "Wrong sig1 ($head->{'sig1'} != ".PWM_DBSIG_1().")\n" if $head->{'sig1'} != PWM_DBSIG_1;
    die "Wrong sig2 ($head->{'sig2'} != ".PWM_DBSIG_2().")\n" if $head->{'sig2'} != PWM_DBSIG_2;
    die "Unsupported File version ($head->{'ver'}).\n" if $head->{'ver'} & 0xFFFFFF00 != PWM_DBVER_DW & 0xFFFFFF00;
    my $enc_type = ($head->{'flags'} & PWM_FLAG_RIJNDAEL) ? 'rijndael'
                 : ($head->{'flags'} & PWM_FLAG_TWOFISH)  ? 'twofish'
                 : die "Unknown Encryption Algorithm.";

    # use the headers to generate our encryption key in conjunction with the password
    my $key = sha256($pass);
    my $cipher = Crypt::Rijndael->new($head->{'seed_key'}, Crypt::Rijndael::MODE_ECB());
    $key = $cipher->encrypt($key) for 1 .. $head->{'seed_rot_n'};
    $key = sha256($key);
    $key = sha256($head->{'seed_rand'}, $key);

    # decrypt the buffer
    my $crypto_size;
    if ($enc_type eq 'rijndael') {
        my $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());
        $cipher->set_iv($head->{'enc_iv'});
        my $orig_size = length($buffer);
        $buffer = $cipher->decrypt(substr($buffer,DB_HEADER_SIZE));
        my $extra = ord(substr $buffer, -1, 1);
        $crypto_size = $orig_size - DB_HEADER_SIZE - $extra;
        $buffer = substr($buffer, 0, $crypto_size);
    } else {
        die "Unimplemented enc_type $enc_type";
    }
    die "Decryption failed.\nThe key is wrong or the file is damaged."
        if $crypto_size > 2147483446 || (!$crypto_size && $head->{'n_groups'});
    die "Hash test failed.\nThe key is wrong or the file is damaged (or we need to implement utf8 input a bit better)"
        if $head->{'checksum'} ne sha256($buffer);

    # read the db
    my ($groups, $gmap, $pos) = $self->parse_groups($buffer, $head->{'n_groups'});
    $self->parse_entries($buffer, $head->{'n_entries'}, $pos, $gmap, $groups);

    if (!defined(wantarray)) {
        $self->{'header'} = $head;
        $self->{'groups'} = $groups;
        return 1;
    }
    return $groups;
}

sub parse_header {
    my ($self, $buffer) = @_;
    return {
        sig1       => unpack('L', substr($buffer,   0, 4)),
        sig2       => unpack('L', substr($buffer,   4, 4)),
        flags      => unpack('L', substr($buffer,   8, 4)),
        ver        => unpack('L', substr($buffer,  12, 4)),
        seed_rand  => substr($buffer, 16, 16),
        enc_iv     => substr($buffer, 32, 16),
        n_groups   => unpack('L', substr($buffer,  48, 4)),
        n_entries  => unpack('L', substr($buffer,  52, 4)),
        checksum   => substr($buffer, 56, 32),
        seed_key   => substr($buffer, 88, 32),
        seed_rot_n => unpack('L', substr($buffer, 120, 4)),
    };
}

sub parse_groups {
    my ($self, $buffer, $n_groups) = @_;
    my $pos = 0;

    my @groups;
    my %gmap; # allow entries to find their groups (group map)
    my @gref = (\@groups); # group ref pointer stack - let levels nest safely
    my $previous_level = 0;
    my $group = {};
    while ($n_groups) {
        my $type = unpack 'S', substr($buffer, $pos, 2);
        $pos += 2;
        die "Group header offset is out of range. ($pos)" if $pos >= length($buffer);

        my $size = unpack 'L', substr($buffer, $pos, 4);
        $pos += 4;
        die "Group header offset is out of range. ($pos, $size)" if $pos + $size > length($buffer);

        if ($type == 1) {
            $group->{'id'} = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 2) {
            $group->{'title'} = substr($buffer, $pos, $size);
            $group->{'title'} =~ s/\0$//;
        } elsif ($type == 7) {
            $group->{'icon'} = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 8) {
            $group->{'level'} = unpack 'S', substr($buffer, $pos, 2);
        } elsif ($type == 0xFFFF) {
            $n_groups--;
            $gmap{$group->{'id'}} = $group;
            my $level = $group->{'level'} || 0;
            if ($previous_level > $level) {
                splice @gref, $previous_level, $previous_level - $level, ();
                push @gref, \@groups if !@gref;
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
        die "Entry header offset is out of range. ($pos)" if $pos >= length($buffer);

        my $size = unpack 'L', substr($buffer, $pos, 4);
        $pos += 4;
        die "Entry header offset is out of range. ($pos, ".length($buffer).", $size)" if $pos + $size > length($buffer);

        if ($type == 1) {
            $entry->{'uuid'} = 1 #KpxUuid(pData);
        } elsif ($type == 2) {
            $entry->{'group_id'} = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 3) {
            $entry->{'icon'} = unpack 'L', substr($buffer, $pos, 4);
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
                $ref = $gmap->{0} = {id => 0, title => '*Orphaned*', icon => 0};
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

###----------------------------------------------------------------###

sub gen_db {
    my $self = shift;
    my $pass = shift;
    croak "Missing pass\n" if ! defined($pass);
    my $groups = shift || $self->groups;

    my $seed_rand; $seed_rand .= chr(int(255 * rand())) for 1..16;
    my $enc_iv;    $enc_iv    .= chr(int(255 * rand())) for 1..16;
    my $seed_key   = sha256(rand());
    my $seed_rot_n = 50_000;

    # use the headers to generate our encryption key in conjunction with the password
    my $key = sha256($pass);
    my $cipher = Crypt::Rijndael->new($seed_key, Crypt::Rijndael::MODE_ECB());
    $key = $cipher->encrypt($key) for 1 .. $seed_rot_n;
    $key = sha256($key);
    $key = sha256($seed_rand, $key);

    my $buffer = '';
    my $n_groups = 0;
    my $n_entries = 0;
    my @entries;
    foreach my $g ($self->flat_groups($groups)) {
        $buffer .= pack('S', 1) . pack('L', 4) . pack('L', $g->{'id'});
        $buffer .= pack('S', 2) . pack('L', length($g->{'title'})+1) . "$g->{'title'}\0";
        $buffer .= pack('S', 7) . pack('L', 4) . pack('L', $g->{'icon'}  || 0);
        $buffer .= pack('S', 8) . pack('L', 2) . pack('S', $g->{'level'} || 0);
        $buffer .= pack('S', 0xFFFF) . pack('L', 0);
        push @entries, @{ $g->{'entries'} } if $g->{'entries'};
    }
    foreach my $e (@entries) {
    # TODO - flatten out the data into $buffer
    }

    my $checksum = sha256($buffer);
    $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());
    $cipher->set_iv($enc_iv);
    my $crypto_size = length($buffer);
    my $extra = 16 - ((1+length($buffer)) % 16);
    $buffer .= "\0"x$extra;
    $buffer .= chr($extra);

    my $header = $self->gen_header({
        sig1       => PWM_DBSIG_1(),
        sig2       => PWM_DBSIG_2(),
        flags      => PWM_FLAG_RIJNDAEL(),
        ver        => PWM_DBVER_DW(),
        seed_rand  => $seed_rand,
        enc_iv     => $enc_iv,
        n_groups   => $n_groups,
        n_entries  => $n_entries,
        checksum   => $checksum,
        seed_key   => $seed_key,
        seed_rot_n => $seed_rot_n,
    });

    my $enc = $cipher->encrypt($buffer);

    return $header.$enc;
}

sub gen_header {
    my ($self, $args) = @_;
    my $header = ''
        .pack('L', $args->{'sig1'})
        .pack('L', $args->{'sig2'})
        .pack('L', $args->{'flags'})
        .pack('L', $args->{'ver'})
        .$args->{'seed_rand'}
        .$args->{'enc_iv'}
        .pack('L', $args->{'n_groups'})
        .pack('L', $args->{'n_entries'})
        .$args->{'checksum'}
        .$args->{'seed_key'}
        .pack('L', $args->{'seed_rot_n'});
    die "Invalid generated header\n" if length($header) != DB_HEADER_SIZE;
    return $header;
}

###----------------------------------------------------------------###

sub dump_groups {
    my ($self, $g, $indent) = @_;
    $indent = '' if ! $indent;
    print $indent.($g->{'expanded'} ? '-' : '+')."  $g->{'title'} ($g->{'id'}) $g->{'level'}\n";
    $self->dump_groups($_, "$indent    ") for @{ $g->{'groups'} || [] };
    for my $e (@{ $g->{'entries'} || [] }) {
        print "$indent    > $e->{'title'} ($e->{'username'})\n";
    }
}

sub groups { shift->{'groups'} || croak "No groups loaded yet\n" }

sub add_group {
    my $self = shift;
    my $args = shift;
    my $groups;
    my $level;
    if (defined(my $pid = $args->{'parent_id'})) {
        if (my $group = $self->find_group({id => $pid})) {
            $groups = $group->{'groups'} ||= [];
            $level  = $group->{'level'} || 0;
            $level++;
        }
    }
    $groups ||= $self->{'groups'} ||= [];
    $level  ||= 0;

    my $gid;
    $gid = int((2**32-1) * rand()) while !$gid || $self->find_group({id => $gid});

    push @$groups, {
        title => defined($args->{'title'}) ? $args->{'title'} : '',
        icon  => $args->{'icon'} || 0,
        id    => $gid,
    };

    return $gid;
}

sub find_group {
    my $self = shift;
    my $args = shift;
    die "Must specify one of id, title or icon" if !grep {defined $args->{$_}} qw(id title icon);
    my $groups = shift || $self->groups;
    for my $g (@$groups) {
        if (   (!defined $args->{'id'}    || $g->{'id'}    eq $args->{'id'})
            && (!defined $args->{'title'} || $g->{'title'} eq $args->{'title'})
            && (!defined $args->{'icon'}  || $g->{'icon'}  eq $args->{'icon'})) {
            return $g;
        }
        next if ! $g->{'groups'};
        my $found = $self->find_group($args, $g->{'groups'});
        return $found if $found;
    }
    return;
}

sub flat_groups {
    my $self = shift;
    my $groups = shift || $self->groups;
    my @GROUPS;
    for my $g (@$groups) {
        push @GROUPS, $g;
        push @GROUPS, $self->flat_groups($g->{'groups'}) if $g->{'groups'};
    }
    return @GROUPS;
}

###----------------------------------------------------------------###

1;

__END__

=head1 SYNOPSIS

=cut
