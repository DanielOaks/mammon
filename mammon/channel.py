#!/usr/bin/env python
# mammon - a useless ircd
#
# Copyright (c) 2015, William Pitcock <nenolod@dereferenced.org>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from ircreactor.envelope import RFC1459Message
from .utility import validate_chan, CaseInsensitiveDict

class ChannelManager(object):
    def __init__(self, ctx):
        self.ctx = ctx

    def get(self, name, create=False):
        if not validate_chan(name):
            return None
        ch = self.ctx.channels.get(name, None)
        if ch or not create:
            return ch
        ch = Channel(name)
        self.ctx.channels[name] = ch
        return ch

class ChannelMembership(object):
    def __init__(self, client, channel):
        self.client = client
        self.channel = channel
        self.props = CaseInsensitiveDict()

class Channel(object):
    def __init__(self, name):
        self.name = name
        self.members = []
        self.topic = None
        self.topic_setter = None
        self.topic_ts = 0
        self.props = CaseInsensitiveDict()

    def authorize(self, cli, ev_msg):
        if 'key' in self.props and self.props['key'] != ev_msg['params'][1]:
            cli.dump_numeric('474', [self.name, 'Cannot join channel (+k) - bad key'])
            return False
        return True

    def join(self, client):
        m = ChannelMembership(client, self)
        self.members.append(m)
        client.channels.append(m)

    def part(self, client):
        for m in filter(lambda x: x.client == client, self.members):
            self.members.remove(m)
            if m in client.channels:
                client.channels.remove(m)

    def has_member(self, client):
        matches = tuple(filter(lambda x: x.client == client, self.members))
        return len(matches) > 0

    def dump_message(self, msg, exclusion_list=None):
        if not exclusion_list:
            exclusion_list = list()
        [m.client.dump_message(msg) for m in self.members if m.client not in exclusion_list]

# --- rfc1459 channel management commands ---
from .events import eventmgr

@eventmgr.message('JOIN', min_params=1)
def m_JOIN(cli, ev_msg):
    if not validate_chan(ev_msg['params'][0]):
        cli.dump_numeric('479', [ev_msg['params'][0], 'Illegal channel name'])
        return

    ch = cli.ctx.chmgr.get(ev_msg['params'][0], create=True)
    if not ch.authorize(cli, ev_msg):
        return

    ch.join(cli)
    ch.dump_message(RFC1459Message.from_data('JOIN', source=cli.hostmask, params=[ch.name]))

@eventmgr.message('PART', min_params=1)
def m_PART(cli, ev_msg):
    if not validate_chan(ev_msg['params'][0]):
        cli.dump_numeric('479', [ev_msg['params'][0], 'Illegal channel name'])
        return

    ch = cli.ctx.chmgr.get(ev_msg['params'][0], create=False)
    if not ch:
        cli.dump_numeric('403', [ev_msg['params'][0], 'No such channel'])
        return

    if not ch.has_member(cli):
        cli.dump_numeric('442', [ch.name, "You're not on that channel"])
        return

    ch.dump_message(RFC1459Message.from_data('PART', source=cli.hostmask, params=ev_msg['params']))
    ch.part(cli)
