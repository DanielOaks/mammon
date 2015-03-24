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

default_whois_format = 'is a {role}.'
default_vowel_whois_format = 'is an {role}.'

class Role:
    def __init__(self, ctx, name, roles=None, extends=None, **kwargs):
        self.ctx = ctx
        self.name = name

        # defaults
        self.capabilities = []
        self.title = ''
        self.whois_format = None

        for k, v in kwargs.items():
            setattr(self, k, v)

        # automatically choose a/an for whois message
        if self.whois_format is None:
            self.whois_format = default_whois_format
            for character in self.title:
                if character.isalpha() and character.lower() in ['a', 'e', 'i', 'o', 'u']:
                    self.whois_format = default_vowel_whois_format
                    break
                elif character.isalpha():
                    break

        self.whois_line = self.whois_format.format(role=self.title)

        # extending roles
        if roles is None:
            roles = self.ctx.roles

        if extends and extends in roles:
            for capability in roles.get(extends).capabilities:
                if capability not in self.capabilities:
                    self.capabilities.append(capability)
        elif extends:
            print('mammon: error: error in role', name, '- extending role', extends, 'does not exist')