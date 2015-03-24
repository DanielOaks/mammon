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

import yaml
import asyncio
import logging
from .client import ClientProtocol
from .roles import Role

def load_extended_roles(ctx, k, roles, roles_extending):
    for kk, vv in roles_extending.get(k, {}).items():
        roles[kk] = Role(ctx, kk, roles=roles, **vv)
        roles = load_extended_roles(ctx, kk, roles, roles_extending)

    return roles

class ConfigHandler(object):
    config_st = {}
    ctx = None
    listener_protos = {
        'client': ClientProtocol,
    }

    def __init__(self, config_name, ctx):
        self.config_name = config_name
        self.ctx = ctx

        self.config_st = yaml.load(open(config_name, 'r'))

    def process(self):
        for k, v in self.config_st.items():
            setattr(self, k, v)

        for k, v in self.config_st['server'].items():
            setattr(self, k, v)

        for l in self.listeners:
            proto = l.get('proto', 'client')

            self.ctx.logger.info('opening listener at {0}:{1} [{2}]'.format(l['host'], l['port'], proto))
            lstn = self.ctx.eventloop.create_server(self.listener_protos[proto], l['host'], l['port'])
            self.ctx.listeners.append(lstn)

        if self.metadata.get('limit', None) is not None:
            try:
                self.metadata['limit'] = int(self.metadata['limit'])
            except:
                print('mammon: error: config key metadata.limit must be an integer or commented out')
                print('mammon: error: setting metadata.limit to default 20')
                self.metadata['limit'] = 20
        if self.metadata.get('restricted_keys', []) is None:
            self.metadata['restricted_keys'] = []

        roles = {}
        roles_extending = {
            None: {},
        }

        # get base list of which roles extend from which
        for k, v in self.roles.items():
            extends = v.get('extends', None)
            if extends not in roles_extending:
                roles_extending[extends] = {}
            roles_extending[extends][k] = v

        # load base roles, then roles that extend those
        base_roles = roles_extending[None]
        for k, v in base_roles.items():
            roles[k] = Role(self.ctx, k, roles=roles, **v)
            roles = load_extended_roles(self.ctx, k, roles, roles_extending)

        self.ctx.roles = roles
