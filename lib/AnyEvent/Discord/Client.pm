package AnyEvent::Discord::Client;
use warnings;
use strict;

our $VERSION = '0.000003';
$VERSION = eval $VERSION;

use AnyEvent::WebSocket::Client;
use LWP::UserAgent;
use JSON;
use URI;
use HTTP::Request;
use HTTP::Headers;
use AnyEvent::HTTP;
use Data::Dumper;
use POSIX qw/strftime/;

sub new {
  my ($class, %args) = @_;

  my $self = {
    token => delete($args{token}),
    api_root => delete($args{api_root}) // 'https://discordapp.com/api',
    prefix => delete($args{prefix}) // "!",
    commands => delete($args{commands}) // {},
    callbacks => delete($args{callbacks}) // {},
    intents => delete($args{intents}) // {},
    debug => delete($args{debug}) // 3,

    ua => LWP::UserAgent->new(),
    api_useragent => "DiscordBot (https://github.com/topaz/perl-AnyEvent-Discord-Client, 0)",

    user => undef,
    guilds => {},
    channels => {},
    roles => {},

    gateway => undef,
    conn => undef,
    websocket => undef,
    heartbeat_timer => undef,
    last_seq => undef,
    reconnect_delay => 1,
  };
  
  if($self->{debug} < 0 || $self->{debug} > 5) {
    $self->{debug} = 3;
    $self->logger(3, "Invalid debug level set, defaulting to level 3");
  }

  unless(defined $self->{token}){
    $self->logger(1, "cannot construct new $class without a token parameter");
    die();
  }
  
  if(%args){
    $self->logger(1, "unrecognized extra parameters were given to $class->new");
    die();
  }

  return bless $self, $class;
}

sub commands  { $_[0]{commands}  }
sub callbacks { $_[0]{callbacks} }
sub user      { $_[0]{user}      }
sub guilds    { $_[0]{guilds}    }
sub channels  { $_[0]{channels}  }
sub roles     { $_[0]{roles}     }
sub members   { $_[0]{members}   }

my %event_handler = (
  READY => sub {
    my ($self, $d) = @_;
    $self->{user} = $d->{user};
    $self->logger(4, "logged in as $self->{user}{username}.");
    $self->{callbacks}{READY}($self, $d) if exists $self->{callbacks}{READY};
  },
  GUILD_CREATE => sub {
    my ($self, $d) = @_;
    $self->{guilds}{$d->{id}} = $d;
    $self->{channels}{$_->{id}} = {%$_, guild_id=>$d->{id}} for @{$d->{channels}};
    $self->{roles}{$_->{id}}    = {%$_, guild_id=>$d->{id}} for @{$d->{roles}};
    $self->{members}{$_->{user}{id}} = {%$_, guild_id=>$d->{id}, status=>"offline"} for @{$d->{members}};
    
    foreach(@{$d->{presences}}){ #initial presences are sent separate from initial member records
        $self->{members}{$_->{user}{id}}{status} = $_->{status};
    }
    
    $self->logger(4, "created guild $d->{id} ($d->{name})");
    $self->{callbacks}{GUILD_CREATE}($self, $d) if exists $self->{callbacks}{GUILD_CREATE};
  },
  CHANNEL_CREATE => sub {
    my ($self, $d) = @_;
    $self->{channels}{$d->{id}} = $d;
    push @{$self->{guilds}{$d->{guild_id}}{channels}}, $d if $d->{guild_id};
    $self->logger(4, "created channel $d->{id} ($d->{name}) of guild $d->{guild_id} ($self->{guilds}{$d->{guild_id}}{name})");
    $self->{callbacks}{CHANNEL_CREATE}($self, $d) if exists $self->{callbacks}{CHANNEL_CREATE};
  },
  CHANNEL_UPDATE => sub {
    my ($self, $d) = @_;
    %{$self->{channels}{$d->{id}}} = %$d;
    $self->logger(4, "updated channel $d->{id} ($d->{name}) of guild $d->{guild_id} ($self->{guilds}{$d->{guild_id}}{name})");
    $self->{callbacks}{CHANNEL_UPDATE}($self, $d) if exists $self->{callbacks}{CHANNEL_UPDATE};
  },
  CHANNEL_DELETE => sub {
    my ($self, $d) = @_;
    @{$self->{guilds}{$d->{guild_id}}{channels}} = grep {$_->{id} != $d->{id}} @{$self->{guilds}{$d->{guild_id}}{channels}} if $d->{guild_id};
    delete $self->{channels}{$d->{id}};
    $self->logger(4, "deleted channel $d->{id} ($d->{name}) of guild $d->{guild_id} ($self->{guilds}{$d->{guild_id}}{name})");
    $self->{callbacks}{CHANNEL_DELETE}($self, $d) if exists $self->{callbacks}{CHANNEL_DELETE};
  },
  GUILD_ROLE_CREATE => sub {
    my ($self, $d) = @_;
    $self->{roles}{$d->{role}{id}} = $d->{role};
    push @{$self->{guilds}{$d->{guild_id}}{roles}}, $d->{role} if $d->{guild_id};
    $self->logger(4, "created role $d->{role}{id} ($d->{role}{name}) of guild $d->{guild_id} ($self->{guilds}{$d->{guild_id}}{name})");
    $self->{callbacks}{GUILD_ROLE_CREATE}($self, $d) if exists $self->{callbacks}{GUILD_ROLE_CREATE};
  },
  GUILD_ROLE_UPDATE => sub {
    my ($self, $d) = @_;
    %{$self->{roles}{$d->{role}{id}}} = %{$d->{role}};
    $self->logger(4, "updated role $d->{role}{id} ($d->{role}{name}) of guild $d->{guild_id} ($self->{guilds}{$d->{guild_id}}{name})");
    $self->{callbacks}{GUILD_ROLE_UPDATE}($self, $d) if exists $self->{callbacks}{GUILD_ROLE_UPDATE};
  },
  GUILD_ROLE_DELETE => sub {
    my ($self, $d) = @_;
    @{$self->{guilds}{$d->{guild_id}}{roles}} = grep {$_->{role}{id} != $d->{role}{id}} @{$self->{guilds}{$d->{guild_id}}{roles}} if $d->{guild_id};
    delete $self->{roles}{$d->{role}{id}};
    $self->logger(4, "deleted role $d->{role}{id} ($d->{role}{name}) of guild $d->{guild_id} ($self->{guilds}{$d->{guild_id}}{name})");
    $self->{callbacks}{GUILD_ROLE_DELETE}($self, $d) if exists $self->{callbacks}{GUILD_ROLE_DELETE};
  },
  TYPING_START => sub {
    my ($self, $d) = @_;
    $self->{callbacks}{TYPING_START}($self, $d) if exists $self->{callbacks}{TYPING_START};
  },
  PRESENCE_UPDATE => sub {
    my ($self, $d) = @_;
    $self->{members}{$d->{user}{id}}{status} = $d->{status};
    $self->logger(4, "updated user $self->{members}{$d->{user}{id}}{user}{username} to $d->{status}");
    $self->{callbacks}{PRESENCE_UPDATE}($self, $d) if exists $self->{callbacks}{PRESENCE_UPDATE};
  },
  MESSAGE_CREATE => sub {
    my ($self, $msg) = @_;
    my $channel = $self->{channels}{$msg->{channel_id}};
    my $guild = $self->{guilds}{$channel->{guild_id}};

    #(my $hrcontent = $msg->{content) =~ s/[\x00-\x
    $self->logger(4, "[$guild->{name} ($guild->{id}) / $channel->{name} ($channel->{id})] <$msg->{author}{username}> $msg->{content}");
    #warn STDERR join(",",unpack("U*", $msg->{content}))."\n";
    return if $msg->{author}{id} == $self->{user}{id};

    if ($msg->{content} =~ /^\Q$self->{prefix}\E(\S+)(?:\s+(.*?))?\s*$/) {
      my ($cmd, $args) = (lc $1, defined $2 ? $2 : "");
      if (exists $self->{commands}{$cmd}) {
        $self->{commands}{$cmd}($self, $args, $msg, $channel, $guild);
      }
    } else{
      $self->{callbacks}{CHAT_MESSAGE}($self, $msg) if exists $self->{callbacks}{CHAT_MESSAGE};
    }
    
    $self->{callbacks}{MESSAGE_CREATE}($self, $msg) if exists $self->{callbacks}{MESSAGE_CREATE};
  },
);

my %intents = (
  GUILDS => 1 << 0,
  GUILD_MEMBERS => 1 << 1,
  GUILD_BANS => 1 << 2,
  GUILD_EMOJIS => 1 << 3,
  GUILD_INTEGRATIONS => 1 << 4,
  GUILD_WEBHOOKS => 1 << 5,
  GUILD_INVITES => 1 << 6,
  GUILD_VOICE_STATES => 1 << 7,
  GUILD_PRESENCES => 1 << 8,
  GUILD_MESSAGES => 1 << 9,
  GUILD_MESSAGE_REACTIONS => 1 << 10,
  GUILD_MESSAGE_TYPING => 1 << 11,
  DIRECT_MESSAGES => 1 << 12,
  DIRECT_MESSAGE_REACTIONS => 1 << 13,
  DIRECT_MESSAGE_TYPING => 1 << 14,
);

sub connect {
  my ($self) = @_;

  if (!defined $self->{gateway}) {
    # look up gateway url
    my $gateway_data = $self->api_sync(GET => "/gateway");
    my $gateway = $gateway_data->{url};
    unless($gateway =~ /^wss\:\/\//){
      $self->logger(1, "invalid gateway: $gateway");
      die();
    }
    $gateway = new URI($gateway);
    $gateway->path("/") unless length $gateway->path;
    $gateway->query_form(v=>8, encoding=>"json");
    $self->{gateway} = "$gateway";
  }

  $self->logger(3, "Connecting to $self->{gateway}...");

  $self->{reconnect_delay} *= 2;
  $self->{reconnect_delay} = 5*60 if $self->{reconnect_delay} > 5*60;

  $self->{websocket} = AnyEvent::WebSocket::Client->new(max_payload_size => 1024*1024);
  $self->{websocket}->connect($self->{gateway})->cb(sub {
    $self->{conn} = eval { shift->recv };
    if($@) {
      $self->logger(4, "$@");
      return;
    }

    $self->logger(3, "websocket connected to $self->{gateway}.");
    $self->{reconnect_delay} = 1;
    
    #Calculate intents value
    my $intents = 0;
    if(ref($self->{intents}) eq "ARRAY"){
      foreach (@{$self->{intents}}){
        $intents += $intents{uc($_)};
      }
    }

    # send "identify" op
    $self->websocket_send(2, {
      token => $self->{token},
      intents => $intents,
      properties => {
        '$os' => "linux",
        '$browser' => "zenbotta",
        '$device' => "zenbotta",
        '$referrer' => "",
        '$referring_domain' => ""
      },
      compress => JSON::false,
      large_threshold => 250,
      shard => [0, 1],
    });

    $self->{conn}->on(each_message => sub {
      my($connection, $message) = @_;
      my $msg = decode_json($message->{body});
      unless(ref $msg eq 'HASH' && defined $msg->{op}){
        $self->logger(2, "invalid message:\n" . Dumper($message));
        return;
      }

      $self->{last_seq} = 0+$msg->{s} if defined $msg->{s};

      if ($msg->{op} == 0) { #dispatch
        $self->logger(5, "\e[1;30mdispatch event $msg->{t}:".Dumper($msg->{d})."\e[0m");
        $event_handler{$msg->{t}}($self, $msg->{d}) if $event_handler{$msg->{t}};
      } elsif ($msg->{op} == 10) { #hello
        $self->{heartbeat_timer} = AnyEvent->timer(
          after => $msg->{d}{heartbeat_interval}/1e3,
          interval => $msg->{d}{heartbeat_interval}/1e3,
          cb => sub {
            $self->websocket_send(1, $self->{last_seq});
          },
        );
      } elsif ($msg->{op} == 11) { #heartbeat ack
        # ignore for now; eventually, notice missing ack and reconnect
      } else {
        $self->logger(5, "\e[1;30mnon-event message op=$msg->{op}:".Dumper($msg)."\e[0m");
      }
    });

    $self->{conn}->on(parse_error => sub {
      my ($connection, $error) = @_;
      $self->logger(2, "parse_error: $error");
    });

    $self->{conn}->on(finish => sub {
      my($connection) = @_;
      $self->logger(3, "Disconnected! Reconnecting in five seconds...");
      my $reconnect_timer; $reconnect_timer = AnyEvent->timer(
        after => $self->{reconnect_delay},
        cb => sub {
          $self->connect();
          $reconnect_timer = undef;
        },
      );
    });
  });
}

sub add_commands {
  my ($self, %commands) = @_;
  $self->{commands}{$_} = $commands{$_} for keys %commands;
}

sub add_callbacks {
  my ($self, %callbacks) = @_;
  $self->{callbacks}{uc($_)} = $callbacks{$_} for keys %callbacks;
}

sub api_sync {
  my ($self, $method, $path, $data) = @_;

  my $resp = $self->{ua}->request(HTTP::Request->new(
    uc($method),
    $self->{api_root} . $path,
    HTTP::Headers->new(
      Authorization => "Bot $self->{token}",
      User_Agent => $self->{api_useragent},
      ($data ? (Content_Type => "application/json") : ()),
      (
          !defined $data ? ()
        : ref $data ? ("Content_Type" => "application/json")
        : ("Content_Type" => "application/x-www-form-urlencoded")
      ),
    ),
    (
        !defined $data ? undef
      : ref $data ? encode_json($data)
      : $data
    ),
  ));

  if (!$resp->is_success) {
    return undef;
  }
  if ($resp->header("Content-Type") eq 'application/json') {
    return JSON::decode_json($resp->decoded_content);
  } else {
    return 1;
  }
}

sub websocket_send {
  my ($self, $op, $d) = @_;
  
  unless($self->{conn}){
    $self->logger(1, "no websocket connection!");
    die();
  }

  $self->{conn}->send(encode_json({op=>$op, d=>$d}));
}

sub say {
  my ($self, $channel_id, $message) = @_;
  $self->api(POST => "/channels/$channel_id/messages", {content => $message});
}

sub dm {
  my($self, $user_id, $message) = @_;
  $self->api(POST => "/users/\@me/channels", {recipient_id => $user_id}, sub { my($data, $hdr) = @_; $self->say($data->{id}, $message); });
}

sub typing {
  my ($self, $channel) = @_;
  return AnyEvent->timer(
    after => 0,
    interval => 5,
    cb => sub {
      $self->api(POST => "/channels/$channel->{id}/typing", '');
    },
  );
}

sub get_role_id {
  my ($self, $guild, $role) = @_;

  if(lc($role) eq "everyone" || lc($role) eq "\@everyone"){
    return $guild; #The @everyone role is always the same as the guild ID
  }

  foreach( @{$self->{guilds}{$guild}{roles}} ){
    if($_->{name} eq $role){
      return($_->{id});
    }
  }

  return undef; #If we get this far, the role wasn't found
}

sub tick {
  my ($self, $interval, $sub) = @_;
  return AnyEvent->timer(
    after => $interval,
    interval => $interval,
    cb => $sub,
  );
}

sub api {
  my ($self, $method, $path, $data, $cb) = @_;
  http_request(
    uc($method) => $self->{api_root} . $path,
    timeout => 5,
    recurse => 0,
    headers => {
      referer => undef,
      authorization => "Bot $self->{token}",
      "user-agent" => $self->{api_useragent},
      (
          !defined $data ? ()
        : ref $data ? ("content-type" => "application/json")
        : ("content-type" => "application/x-www-form-urlencoded")
      ),
    },
    (
        !defined $data ? ()
      : ref $data ? (body => encode_json($data))
      : (body => $data)
    ),
    sub {
      my ($body, $hdr) = @_;
      return unless $cb;
      $cb->(!defined $body ? undef : defined $hdr->{"content-type"} && $hdr->{"content-type"} eq 'application/json' ? decode_json($body) : 1, $hdr);
    },
  );
}

sub logger {
  my ($self, $level, $message) = @_;

  if($level <= $self->{debug}){
    warn $level . " - " . strftime("%Y-%m-%d %H:%M:%S", localtime) . " - " . $message . "\n"; #\n to suppress line number
  }

  #0 = OFF
  #1 = FATAL
  #2 = ERROR
  #3 = WARN
  #4 = INFO
  #5 = DEBUG
}

1;

__END__
=head1 NAME

AnyEvent::Discord::Client - A Discord client library for the AnyEvent framework.

=head1 SYNOPSIS

    use AnyEvent::Discord::Client;

    my $token = 'NjI5NTQ4Mjg3NTMxMjg2......';
    
    my $bot = new AnyEvent::Discord::Client(
      token => $token,
      intents => [ 'guilds', 'guild_messages', 'direct_messages' ],
      debug => 3,
      commands => {
        'commands' => sub {
          my ($bot, $args, $msg, $channel, $guild) = @_;
          $bot->say($channel->{id}, join("   ", map {"`$_`"} sort grep {!$commands_hidden{$_}} keys %{$bot->commands}));
        },
      },
    );
    
    $bot->add_commands(
      'hello' => sub {
        my ($bot, $args, $msg, $channel, $guild) = @_;
    
        $bot->say($channel->{id}, "hi, $msg->{author}{username}!");
      },
    );
    
    $bot->connect();
    AnyEvent->condvar->recv;

After adding this bot to a channel in a Discord Guild, type '!hello' in chat to run the example command.

=head1 DESCRIPTION

This module provides the functionality required to create a simple Discord
client or bot using the REST and WebSocket interfaces to Discord.

=head1 CONSTRUCTION

=over

=item C<< AnyEvent::Discord::Client->new(I<%opts>) >>

    AnyEvent::Discord::Client->new(token => $token)

Creates a new C<AnyEvent::Discord::Client> with the given configuration.
Takes the following parameters:

=over

=item C<token>

A Discord Bot token as given by the "Bot" section of a L<Discord Developer Portal application|https://discordapp.com/developers/applications/>. Required.

=item C<intents>

Array of intents your bot needs, see L<Discord Developer Portal|https://discord.com/developers/docs/topics/gateway#gateway-intents>.

=item C<debug>

Debug level to control how verbose the bots logging is.  Each debug level includes all levels above it, i.e. setting debug to 3 will output all warning, error, and fatal messages.

0: Off, 1: Fatal, 2: Errors, 3: Warnings, 4: Info, 5: Debug

=item C<api_root>

The Discord API root to use. Default C<https://discordapp.com/api>.

=item C<prefix>

The command prefix to use when looking for registered commands in chat. Default C<!>.

=item C<commands>

A hashref of commands to begin with as if the hash were passed to C<add_commands()>.

=item C<callbacks>

A hashref of callbacks to begin with as if the hash were passed to C<add_callbacks()>.

=back

=back

=head1 METHODS

=over

=item C<commands()>

Returns a hashref of the currently registered commands.

=item C<callbacks()>

Returns a hashref of the currently registered callbacks.

=item C<user()>

Returns a hashref representing a L<Discord User object|https://discordapp.com/developers/docs/resources/user> for the currently logged-in user.

=item C<guilds()>

Returns a hashref of guild IDs to hashrefs representing L<Discord Guild objects|https://discordapp.com/developers/docs/resources/guild> for any Guilds the client has seen.

=item C<channels()>

Returns a hashref of channel IDs to hashrefs representing L<Discord Channel objects|https://discordapp.com/developers/docs/resources/channel> for any Channels the client has seen.

=item C<roles()>

Returns a hashref of role IDs to hashrefs representing L<Discord Role objects|https://discordapp.com/developers/docs/topics/permissions#role-object> for any Roles the client has seen.

=item C<members()>

Returns a hashref of member IDs to hashrefs representing L<Discord Guild Member objects|https://discord.com/developers/docs/resources/guild#guild-member-object>, with the addition of their current presence status (online, offline, etc), for any Guild Memebers the client has seen.

=item C<connect()>

Causes the client to connect to Discord.  Will automatically attempt to reconnect if disconnected.  Returns nothing and immediately; to wait forever and prevent the program from exiting, follow this call with:

    AnyEvent->condvar->recv;

=item C<say(I<$channel_id>, I<$message>)>

Sends the given C<$message> text to the given C<$channel_id>.

=item C<dm(I<$user_id>, I<$message>)>

Sends the given C<$message> text over direct message to the given C<$user_id>.

=item C<typing(I<$channel>)>

Displays a typing indicator in the given channel.  Discord automatically removes the indicator after a few seconds; to keep it longer, this method returns an L<AnyEvent watcher|https://metacpan.org/pod/AnyEvent#WATCHERS> that you can keep in scope until you're done with your operation, then set it to C<undef> after.  For example:

    my $typing_watcher = $bot->typing($channel);
    
    # Now, do a potentially very slow operation, like calling an API.
    
    # Once the API responds, even asynchronously, disable the watcher:
    undef $typing_watcher;

=item C<add_commands(I<%commands>)>

Installs new commands - chat messages that begin with the C<prefix> given during construction and any key from the given hash.  When seen as a chat message, the corresponding subref of the registered command will be invoked.  The subref is passed a reference to the C<AnyEvent::Discord::Client> object, the text after the command, and hashrefs representing the relevant Discord L<Message|https://discordapp.com/developers/docs/resources/channel#message-object>, L<Channel|https://discordapp.com/developers/docs/resources/channel>, and L<Guild|https://discordapp.com/developers/docs/resources/guild> objects.  For example:

    $bot->add_commands(
      # register "!hello" command
      'hello' => sub {
        my ($bot, $args, $msg, $channel, $guild) = @_;
    
        $bot->say($channel->{id}, "hi, $msg->{author}{username}!");
      },
    );
    
=item C<add_callbacks(I<%callbacks>)>

Installs new callback functions to be invoked by the event handler, for example:

    $bot->add_callbacks(
      # register "CHANNEL_CREATE" callback
      'CHANNEL_CREATE' => sub {
        my ($bot, $d) = @_;
        
        #Announce our arrival!
        $bot->say($d->{id}, "hi $d->{name}, $bot->{user}{username} is here to save the day!");
      },
    );
    
Note that a callback to C<MESSAGE_CREATE> will fire whether the message is a command or not, however you can catch C<CHAT_MESSAGE> if you want only messages.

=item C<get_role_id(I<$guild_id>, I<$role>)>

Returns C<role_id> or C<undef> if not found.

=item C<tick(I<$interval>, I<$sub>)>

Creates a new timer that runs C<$sub> every C<$interval> seconds, for example:

    #accounce the current time every 60 seconds
    $ticker = tick(60, sub {
      $bot->say($channel->{id}, "The current time is $time");
    });

To cancel a timer call C<undef $ticker;>.  You can also use this method to fire a one-off event in the future, such as:

    #announce the current time once after 60 seconds
    $ticker = tick(60, sub {
      $bot->say($channel->{id}, "The current time is $time");
      undef $ticker;
    });

=item C<api(I<$method>, I<$path>, I<$data>, I<$cb>)>

Invokes the Discord API asynchronously and returns immediately.  C<$method> is the HTTP method to use; C<$path> is the endpoint to call.  If C<$data> is a reference, it is sent as JSON; otherwise, if it is defined, it is sent as a C<x-www-form-urlencoded> body. Calls C<$cb> with C<undef> on failure. On success, calls C<$cb> with the decoded JSON result if the response type is C<application/json> or C<1> otherwise.

=item C<api_sync(I<$method>, I<$path>, I<$data>)>

Invokes the Discord API synchronously and returns the result of the call.  C<$method> is the HTTP method to use; C<$path> is the endpoint to call.  If C<$data> is a reference, it is sent as JSON; otherwise, if it is defined, it is sent as a C<x-www-form-urlencoded> body. Returns C<undef> on failure. On success, returns the decoded JSON result if the response type is C<application/json> or C<1> otherwise.

=item C<websocket_send(I<$op>, I<$d>)>

Sends a raw WebSocket payload as per the L<Discord Gateway|https://discordapp.com/developers/docs/topics/gateway> documentation.

=item C<logger(I<$level>, I<$message>)>

The bots debug method, if you wish to use it to log your own messages.  If C<$level> is less than or equal to C<$bot->{debug}> it will log C<$message>.

=back

=head1 AUTHOR

Eric Wastl, C<< <topaz at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-anyevent-discord-client at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=AnyEvent-Discord-Client>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc AnyEvent::Discord::Client


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=AnyEvent-Discord-Client>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/AnyEvent-Discord-Client>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/AnyEvent-Discord-Client>

=item * Search CPAN

L<http://search.cpan.org/dist/AnyEvent-Discord-Client/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2019 Eric Wastl.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut
