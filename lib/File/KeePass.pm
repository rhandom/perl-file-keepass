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
use CGI::Ex::Dump qw(debug);

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
    $self->load_db($file, $pass);
    debug $self->groups;
    exit;
#    my $gen = $self->gen_db($pass, $self->groups, $self->header);
    $self->dump_groups($_) for @{ $self->groups };
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

    # parse and verify headers
    my $head = $self->parse_header($buffer);
    die "Wrong sig1 ($head->{'sig1'} != ".PWM_DBSIG_1().")\n" if $head->{'sig1'} != PWM_DBSIG_1;
    die "Wrong sig2 ($head->{'sig2'} != ".PWM_DBSIG_2().")\n" if $head->{'sig2'} != PWM_DBSIG_2;
    die "Unsupported File version ($head->{'ver'}).\n" if $head->{'ver'} & 0xFFFFFF00 != PWM_DBVER_DW & 0xFFFFFF00;
    my $enc_type = ($head->{'flags'} & PWM_FLAG_RIJNDAEL) ? 'rijndael'
                 : ($head->{'flags'} & PWM_FLAG_TWOFISH)  ? 'twofish'
                 : die "Unknown encryption type\n";

    # use the headers to generate our encryption key in conjunction with the password
    my $key = sha256($pass);
    my $cipher = Crypt::Rijndael->new($head->{'seed_key'}, Crypt::Rijndael::MODE_ECB());
    $key = $cipher->encrypt($key) for 1 .. $head->{'seed_rot_n'};
    $key = sha256($key);
    $key = sha256($head->{'seed_rand'}, $key);

    # decrypt the buffer
    my $crypto_size;
    my $orig_buffer;
    if ($enc_type eq 'rijndael') {
        my $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());
        $cipher->set_iv($head->{'enc_iv'});
        my $orig_size = length($buffer);
        $buffer = $cipher->decrypt(substr($buffer,DB_HEADER_SIZE));
        $orig_buffer = $buffer;
        my $extra = ord(substr $buffer, -1, 1);
        $crypto_size = $orig_size - DB_HEADER_SIZE - $extra;
        substr($buffer, $crypto_size, $orig_size-$crypto_size, ''); #$buffer = substr($buffer, 0, $crypto_size);
    } else {
        die "Unimplemented enc_type $enc_type";
    }
    die "Decryption failed.\nThe key is wrong or the file is damaged."
        if $crypto_size > 2**31 || (!$crypto_size && $head->{'n_groups'});
    die "Checksum did not match.\nThe key is wrong or the file is damaged (or we need to implement utf8 input a bit better)"
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
        } else {
            $group->{'unknown'}->{$type} = substr($buffer, $pos, $size);
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
            $entry->{'group_id'}  = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 3) {
            $entry->{'icon'}      = unpack 'L', substr($buffer, $pos, 4);
        } elsif ($type == 4) {
            ($entry->{'title'}    = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 5) {
            ($entry->{'url'}      = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 6) {
            ($entry->{'username'} = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 7) {
            ($entry->{'password'} = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 8) {
            ($entry->{'comment'}  = substr($buffer, $pos, $size)) =~ s/\0$//;
        } elsif ($type == 9) {
            $entry->{'created'}   = $self->parse_date(substr($buffer, $pos, $size));
        } elsif ($type == 0xA) {
            $entry->{'modified'}  = $self->parse_date(substr($buffer, $pos, $size));
        } elsif ($type == 0xB) {
            $entry->{'accessed'}  = $self->parse_date(substr($buffer, $pos, $size));
        } elsif ($type == 0xC) {
            $entry->{'expires'}   = $self->parse_date(substr($buffer, $pos, $size));
	} elsif ($type == 0xD) {
            ($entry->{'bin_desc'} = substr($buffer, $pos, $size)) =~ s/\0$//;
	} elsif ($type == 0xE) {
            $entry->{'binary'}    = substr($buffer, $pos, $size);
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
        } else {
            $entry->{'unknown'}->{$type} = substr($buffer, $pos, $size);
        }
        $pos += $size;
    }
}

sub parse_date {
    my ($self, $packed) = @_;
    my @b = unpack('C*', $packed);
    my $year = ($b[0] << 6) | ($b[1] >> 2);
    my $mon  = (($b[1] & 0b11)     << 2) | ($b[2] >> 6);
    my $day  = (($b[2] & 0b111111) >> 1);
    my $hour = (($b[2] & 0b1)      << 4) | ($b[3] >> 4);
    my $min  = (($b[3] & 0b1111)   << 2) | ($b[4] >> 6);
    my $sec  = (($b[4] & 0b111111));
    return sprintf "%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $day, $hour, $min, $sec;
}

sub gen_date {
    my ($self, $date) = @_;
    my ($year, $mon, $day, $hour, $min, $sec) = $date =~ /^(\d\d\d\d)-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)$/ ? ($1,$2,$3,$4,$5,$6) : die "Invalid date ($date)";
    return pack('C*',
                ($year >> 6) & 0b111111,
                (($year & 0b111111) << 2) | (($mon >> 2) & 0b11),
                (($mon & 0b11) << 6) | (($day & 0b11111) << 1) | (($hour >> 4) & 0b1),
                (($hour & 0b1111) << 4) | (($min >> 2) & 0b1111),
                (($min & 0b11) << 6) | ($sec & 0b111111),
               );
}

###----------------------------------------------------------------###

sub gen_db {
    my $self = shift;
    my $pass = shift;
    croak "Missing pass\n" if ! defined($pass);
    my $groups = shift || $self->groups;
    my $head   = shift || {};

    foreach my $key (qw(seed_rand enc_iv)) {
        next if defined $head->{$key};
        $head->{$key} = '';
        $head->{$key} .= chr(int(255 * rand())) for 1..16;
    }
    $head->{'seed_key'}   = sha256(rand()) if ! defined $head->{'seed_key'};
    $head->{'seed_rot_n'} = 50_000         if ! defined $head->{'seed_rot_n'};

    # use the headers to generate our encryption key in conjunction with the password
    my $key = sha256($pass);
    my $cipher = Crypt::Rijndael->new($head->{'seed_key'}, Crypt::Rijndael::MODE_ECB());
    $key = $cipher->encrypt($key) for 1 .. $head->{'seed_rot_n'};
    $key = sha256($key);
    $key = sha256($head->{'seed_rand'}, $key);

    my $buffer = '';
    my @entries;
    foreach my $g ($self->flat_groups($groups)) {
        $head->{'n_groups'}++;
        $buffer .= pack('S', 1) . pack('L', 4) . pack('L', $g->{'id'});
        $buffer .= pack('S', 2) . pack('L', length($g->{'title'})+1) . "$g->{'title'}\0";
        $buffer .= pack('S', 7) . pack('L', 4) . pack('L', $g->{'icon'}  || 0);
        $buffer .= pack('S', 8) . pack('L', 2) . pack('S', $g->{'level'} || 0);
        $buffer .= pack('S', 0xFFFF) . pack('L', 0);
        push @entries, @{ $g->{'entries'} } if $g->{'entries'};
    }
    foreach my $e (@entries) {
        $head->{'n_entries'}++;
    # TODO - flatten out the data into $buffer
    }

    $head->{'checksum'} = sha256($buffer);
    $cipher = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_CBC());
    $cipher->set_iv($head->{'enc_iv'});
    my $extra = (16 - length($buffer) % 16) || 16; # always pad so we can always trim
    $buffer .= chr($extra) for 1 .. $extra;

    local $head->{'sig1'}  = PWM_DBSIG_1();
    local $head->{'sig2'}  = PWM_DBSIG_2();
    local $head->{'flags'} = PWM_FLAG_RIJNDAEL();
    local $head->{'ver'}   = PWM_DBVER_DW();
    my $header = $self->gen_header($head);
    my $enc    = $cipher->encrypt($buffer);

    return $header.$enc;
}

sub gen_header {
    my ($self, $args) = @_;
    my $header = ''
        .pack('L4', @{ $args }{qw(sig1 sig2 flags ver)})
        .$args->{'seed_rand'}
        .$args->{'enc_iv'}
        .pack('L2', @{ $args }{qw(n_groups n_entries)})
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

sub header { shift->{'header'} || croak "No header loaded yet\n" }

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
