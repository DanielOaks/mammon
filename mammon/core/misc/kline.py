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

import globre
import ipaddress
import time

from mammon.server import eventmgr_core, eventmgr_rfc1459, get_context

@eventmgr_rfc1459.message('KLINE', min_params=1, oper=True)
def m_KLINE(cli, ev_msg):
    if 'oper:kline' not in cli.role.capabilities:
        cli.dump_numeric('723', params=['kline', 'Insufficient oper privs'])
        return

    params = list(ev_msg['params'])

    try:
        duration_mins = int(params[0])
        params = params[1:]
    except ValueError:
        duration_mins = 0

    userhost = params.pop(0)
    if '@' in userhost:
        user, host = userhost.split('@', 1)
    else:
        user = '*'
        host = userhost

    dest_server = cli.servername
    if len(params) > 2 and params[0].upper() == 'ON':
        if 'oper:remote_ban' not in cli.role.capabilities:
            cli.dump_numeric('723', params=['remote_ban', 'Insufficient oper privs'])
            return
        dest_server = params[1]
        params = params[2:]

    reason = 'No Reason'
    oper_reason = 'No Reason'
    if len(params):
        if '|' in params[0]:
            reason, oper_reason = params[0].split('|', 1)
            reason = reason.rstrip()
            oper_reason = oper_reason.lstrip()
        else:
            reason = params[0]

    # work out mask and type
    try:
        # strict here just controls whether it validates host bits, so we ignore this
        network = ipaddress.ip_network(host, strict=False)

        host_type = network.version
        host = network.compressed
    except ValueError:
        host_type = 'mask'

    mask = user + '@' + host

    # dispatch
    if duration_mins:
        cli.dump_notice('Added temporary {mins} min. K-Line [{user}@{host}]'
                        ''.format(mins=duration_mins, user=user, host=host))
    else:
        cli.dump_notice('Added K-Line [{}@{}]'.format(user, host))

    eventmgr_core.dispatch('kline', {
        'source': cli,
        'server': dest_server,
        'mask': mask,
        'duration_mins': duration_mins,
        'set_at': time.time(),
        'expires_at': time.time() + (duration_mins * 60),
        'user': user,
        'host': host,
        'host_type': host_type,
        'reason': reason,
        'oper_reason': oper_reason,
    })

@eventmgr_core.handler('kline')
def m_kline_process(info):
    ctx = get_context()

    cli = info['source']

    kline_data = dict(info)
    kline_data['source'] = '{} on {}'.format(cli.hostmask, cli.servername)

    ctx.data.put('kline.{}_{}'.format(info['server'], info['mask']),
                 dict(kline_data))

    if globre.match(info['server'], ctx.conf.name):
        if info['host_type'] in (4, 6):
            kline_data['network'] = ipaddress.ip_network(info['host'], strict=False)
        ctx.klines[(info['server'], info['mask'])] = kline_data
