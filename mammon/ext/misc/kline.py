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

import ircmatch

from mammon.server import eventmgr_core, eventmgr_rfc1459, get_context

@eventmgr_core.handler('server start')
def m_kline_setup(info):
    ctx = info['server']

    ctx.logger.debug('loading klines')
    ctx.klines = {}
    for key in ctx.data.list_keys(prefix='kline.'):
        info = dict(ctx.data.get(key))

        # delete expired klines
        if info['duration_mins'] and info['expires_at'] < ctx.current_ts:
            ctx.data.delete(key)
            continue

        # only put klines that apply to us in our running list
        if globre.match(info['server'], ctx.conf.name):
            if info['host_type'] in (4, 6):
                info['network'] = ipaddress.ip_network(info['host'], strict=False)
            ctx.klines[(info['server'], info['mask'])] = info

    ctx.logger.debug('loading dlines')
    ctx.dlines = {}
    for key in ctx.data.list_keys(prefix='dline.'):
        info = dict(ctx.data.get(key))

        # delete expired dlines
        if info['duration_mins'] and info['expires_at'] < ctx.current_ts:
            ctx.data.delete(key)
            continue

        # only put dlines that apply to us in our running list
        if globre.match(info['server'], ctx.conf.name):
            info['network'] = ipaddress.ip_network(info['host'], strict=False)
            ctx.dlines[(info['server'], info['host'])] = info

# - - - CLIENT CHECKING AND HANDLING - - -

@eventmgr_core.handler('client prereg')
def m_kline_client_prereg(info):
    cli = info['client']
    ctx = cli.ctx
    cli.ipaddr = ipaddress.ip_address(cli.realaddr)

    # check dlines
    for key, info in list(ctx.dlines.items()):
        if info['duration_mins'] == 0 or ctx.current_ts < info['expires_at']:
            check_dline(cli, info)
        else:
            # dline has expired
            try:
                del ctx.dlines[key]
            except KeyError:
                pass
    if not cli.connected:
        ctx.logger.debug('new inbound connection from {} rejected (d-line)'.format(cli.peername))

@eventmgr_core.handler('client postreg')
def m_kline_client_postreg(info):
    cli = info['client']
    ctx = cli.ctx

    # check klines
    for key, info in list(ctx.klines.items()):
        if info['duration_mins'] == 0 or ctx.current_ts < info['expires_at']:
            check_kline(cli, info)
        else:
            # kline has expired
            try:
                del ctx.klines[key]
            except KeyError:
                pass
    if not cli.connected:
        ctx.logger.debug('new inbound connection from {}@{} rejected (k-line)'.format(cli.username, cli.peername))
        return

def check_dline(cli, info):
    if cli.ipaddr not in info['network']:
        return

    if cli.connected:
        reason = 'You are banned from this server ({})'.format(info['reason'])
        cli.dump_numeric('465', params=[reason])
        shown = 'D-Lined'
        if info['duration_mins']:
            shown += ' ({} mins)'.format(info['duration_mins'])
        cli.quit('Closed Connection', shown)

def check_kline(cli, info):
    if not ircmatch.match(ircmatch.ascii, info['user'], cli.username):
        return

    if info['host_type'] == 'mask':
        if not (ircmatch.match(ircmatch.ascii, info['host'], cli.hostname) or
                ircmatch.match(ircmatch.ascii, info['host'], cli.realaddr)):
            return

    elif info['host_type'] in (4, 6):
        if cli.ipaddr not in info['network']:
            return

    if cli.connected:
        reason = 'You are banned from this server ({})'.format(info['reason'])
        cli.dump_numeric('465', params=[reason])
        shown = 'K-Lined'
        if info['duration_mins']:
            shown += ' ({} mins)'.format(info['duration_mins'])
        cli.quit('Closed Connection', shown)

# - - - COMMANDS - - -

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
        cli.dump_notice('Added temporary {mins} min. K-Line [{mask}]'
                        ''.format(mins=duration_mins, mask=mask))
    else:
        cli.dump_notice('Added K-Line [{}]'.format(mask))

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

        # apply kline to matching clients on our server
        for client in list(ctx.clients.values()):
            check_kline(client, kline_data)

@eventmgr_rfc1459.message('UNKLINE', min_params=1, oper=True)
def m_UNKLINE(cli, ev_msg):
    if 'oper:unkline' not in cli.role.capabilities:
        cli.dump_numeric('723', params=['unkline', 'Insufficient oper privs'])
        return

    params = list(ev_msg['params'])

    userhost = params.pop(0)
    if '@' in userhost:
        user, host = userhost.split('@', 1)
    else:
        user = '*'
        host = userhost

    dest_server = cli.servername
    if len(params) > 1 and params[1].upper() == 'ON':
        if 'oper:remote_ban' not in cli.role.capabilities:
            cli.dump_numeric('723', params=['remote_ban', 'Insufficient oper privs'])
            return
        dest_server = params[1]
        params = params[2:]

    # work out mask and type
    try:
        # strict here just controls whether it validates host bits, so we ignore this
        network = ipaddress.ip_network(host, strict=False)

        host_type = network.version
        host = network.compressed
    except ValueError:
        host_type = 'mask'

    mask = user + '@' + host

    # confirm kline exists
    ctx = get_context()

    existing_kline = ctx.data.get('kline.{}_{}'.format(dest_server, mask))
    if existing_kline and (existing_kline['duration_mins'] == 0 or
                           existing_kline['expires_at'] > time.time()):
        cli.dump_notice('Removed K-Line [{}]'.format(mask))
    else:
        cli.dump_notice('No K-Line for [{}]'.format(mask))

    # dispatch
    eventmgr_core.dispatch('unkline', {
        'source': cli,
        'server': dest_server,
        'mask': mask,
        'user': user,
        'host': host,
        'host_type': host_type,
    })

@eventmgr_core.handler('unkline')
def m_unkline_process(info):
    ctx = get_context()

    ctx.data.delete('kline.{}_{}'.format(info['server'], info['mask']))

    if globre.match(info['server'], ctx.conf.name):
        try:
            del ctx.klines[(info['server'], info['mask'])]
        except KeyError:
            return

@eventmgr_rfc1459.message('DLINE', min_params=1, oper=True)
def m_DLINE(cli, ev_msg):
    if 'oper:kline' not in cli.role.capabilities:
        cli.dump_numeric('723', params=['kline', 'Insufficient oper privs'])
        return

    params = list(ev_msg['params'])

    try:
        duration_mins = int(params[0])
        params = params[1:]
    except ValueError:
        duration_mins = 0

    host = params.pop(0)

    dest_server = cli.servername
    if len(params) > 1 and params[1].upper() == 'ON':
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

    # strict here just controls whether it validates host bits, so we ignore this
    network = ipaddress.ip_network(host, strict=False)

    host_type = network.version
    host = network.compressed

    # dispatch
    if duration_mins:
        cli.dump_notice('Added temporary {mins} min. D-Line [{host}]'
                        ''.format(mins=duration_mins, host=host))
    else:
        cli.dump_notice('Added D-Line [{}]'.format(host))

    eventmgr_core.dispatch('dline', {
        'source': cli,
        'server': dest_server,
        'duration_mins': duration_mins,
        'set_at': time.time(),
        'expires_at': time.time() + (duration_mins * 60),
        'host': host,
        'host_type': host_type,
        'reason': reason,
        'oper_reason': oper_reason,
    })

@eventmgr_core.handler('dline')
def m_dline_process(info):
    ctx = get_context()

    cli = info['source']

    dline_data = dict(info)
    dline_data['source'] = '{} on {}'.format(cli.hostmask, cli.servername)

    ctx.data.put('dline.{}_{}'.format(info['server'], info['host']),
                 dict(dline_data))

    if globre.match(info['server'], ctx.conf.name):
        if info['host_type'] in (4, 6):
            dline_data['network'] = ipaddress.ip_network(info['host'], strict=False)
        ctx.dlines[(info['server'], info['host'])] = dline_data

        # apply kline to matching clients on our server
        for client in list(ctx.clients.values()):
            check_dline(client, dline_data)

@eventmgr_rfc1459.message('UNDLINE', min_params=1, oper=True)
def m_UNDLINE(cli, ev_msg):
    if 'oper:unkline' not in cli.role.capabilities:
        cli.dump_numeric('723', params=['unkline', 'Insufficient oper privs'])
        return

    params = list(ev_msg['params'])

    userhost = params.pop(0)
    if '@' in userhost:
        user, host = userhost.split('@', 1)
    else:
        user = '*'
        host = userhost

    dest_server = cli.servername
    if len(params) > 1 and params[1].upper() == 'ON':
        if 'oper:remote_ban' not in cli.role.capabilities:
            cli.dump_numeric('723', params=['remote_ban', 'Insufficient oper privs'])
            return
        dest_server = params[1]
        params = params[2:]

    # strict here just controls whether it validates host bits, so we ignore this
    network = ipaddress.ip_network(host, strict=False)

    host_type = network.version
    host = network.compressed

    # confirm dline exists
    ctx = get_context()

    existing_dline = ctx.data.get('dline.{}_{}'.format(dest_server, host))
    if existing_dline and (existing_dline['duration_mins'] == 0 or
                           existing_dline['expires_at'] > time.time()):
        cli.dump_notice('Removed D-Line [{}]'.format(host))
    else:
        cli.dump_notice('No D-Line for [{}]'.format(host))

    # dispatch
    eventmgr_core.dispatch('undline', {
        'source': cli,
        'server': dest_server,
        'user': user,
        'host': host,
        'host_type': host_type,
    })

@eventmgr_core.handler('undline')
def m_undline_process(info):
    ctx = get_context()

    ctx.data.delete('dline.{}_{}'.format(info['server'], info['host']))

    if globre.match(info['server'], ctx.conf.name):
        try:
            del ctx.dlines[(info['server'], info['host'])]
        except KeyError:
            return
