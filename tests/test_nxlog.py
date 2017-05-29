from unittest import TestCase
from nxapi import nxlog


class TestProcessing(TestCase):
    maxDiff = None

    def test_parse_nxlog(self):
        _nxlog = '2013/11/10 07:36:19 [error] 8278#0: *5932 NAXSI_FMT: ip=X.X.X.X&server=Y.Y.Y.Y&'
        _nxlog += 'uri=/phpMyAdmin-2.8.2/scripts/setup.php&learning=0&vers=0.52&total_processed=472&total_blocked=204&'
        _nxlog += 'block=0&cscore0=$UWA&score0=8&zone0=HEADERS&id0=42000227&var_name0=user-agent, client: X.X.X.X,'
        _nxlog += 'server: blog.memze.ro, request: "GET /phpMyAdmin-2.8.2/scripts/setup.php HTTP/1.1", host: "X.X.X.X"'
        errors, ret = nxlog.parse_nxlog(_nxlog)
        self.assertEqual(errors, list())
        self.assertEqual(ret, {'uri': '/phpMyAdmin-2.8.2/scripts/setup.php', 'block': '0',
                               'total_blocked': '204', 'ip': 'X.X.X.X', 'server': 'Y.Y.Y.Y',
                               'learning': '0', 'zone0': 'HEADERS', 'score0': '8',
                               'var_name0': 'user-agent', 'cscore0': '$UWA', 'id0': '42000227',
                               'total_processed': '472', 'vers': '0.52', 'date': '20131110T07:36:19'})

    def test_parse_date(self):
        _nxlog = list()
        _nxlog.append('2013/11/10 07:36:19 [error] 8278#0: *5932 NAXSI_FMT: ip=X.X.X.X&server=Y.Y.Y.Y&')
        _nxlog[0] += 'uri=/phpMyAdmin-2.8.2/scripts/setup.php&learning=0&vers=0.52&total_processed=472&total_blocked=204&'
        _nxlog[0] += 'block=0&cscore0=$UWA&score0=8&zone0=HEADERS&id0=42000227&var_name0=user-agent, client: X.X.X.X,'
        _nxlog[0] += 'server: blog.memze.ro, request: "GET /phpMyAdmin-2.8.2/scripts/setup.php HTTP/1.1", host: "X.X.X.X"'
        _nxlog.append('2013/3/10 14:36:19 [error] 8278#0: *5932 NAXSI_FMT: ip=X.X.X.X&server=Y.Y.Y.Y&')
        _nxlog[1] += 'uri=/phpMyAdmin-2.8.2/scripts/setup.php&learning=0&vers=0.52&total_processed=472&total_blocked=204&'
        _nxlog[1] += 'block=0&cscore0=$UWA&score0=8&zone0=HEADERS&id0=42000227&var_name0=user-agent, client: X.X.X.X,'
        _nxlog[1] += 'server: blog.memze.ro, request: "GET /phpMyAdmin-2.8.2/scripts/setup.php HTTP/1.1", host: "X.X.X.X"'
        _nxlog.append('2013-3-10 07:36:19 [error] 8278#0: *5932 NAXSI_FMT: ip=X.X.X.X&server=Y.Y.Y.Y&')
        _nxlog[2] += 'uri=/phpMyAdmin-2.8.2/scripts/setup.php&learning=0&vers=0.52&total_processed=472&total_blocked=204&'
        _nxlog[2] += 'block=0&cscore0=$UWA&score0=8&zone0=HEADERS&id0=42000227&var_name0=user-agent, client: X.X.X.X,'
        _nxlog[2] += 'server: blog.memze.ro, request: "GET /phpMyAdmin-2.8.2/scripts/setup.php HTTP/1.1", host: "X.X.X.X"'
        _nxlog.append('Feb   4 07:36:19 [error] 8278#0: *5932 NAXSI_FMT: ip=X.X.X.X&server=Y.Y.Y.Y&')
        _nxlog[3] += 'uri=/phpMyAdmin-2.8.2/scripts/setup.php&learning=0&vers=0.52&total_processed=472&total_blocked=204&'
        _nxlog[3] += 'block=0&cscore0=$UWA&score0=8&zone0=HEADERS&id0=42000227&var_name0=user-agent, client: X.X.X.X,'
        _nxlog[3] += 'server: blog.memze.ro, request: "GET /phpMyAdmin-2.8.2/scripts/setup.php HTTP/1.1", host: "X.X.X.X"'
        _nxlog.append('2017-02-20T10:59:03+01:00 example.com nginx: Feb   4 07:36:19 [error] 8278#0: *5932 NAXSI_FMT: ip=X.X.X.X&server=Y.Y.Y.Y&')
        _nxlog[4] += 'uri=/phpMyAdmin-2.8.2/scripts/setup.php&learning=0&vers=0.52&total_processed=472&total_blocked=204&'
        _nxlog[4] += 'block=0&cscore0=$UWA&score0=8&zone0=HEADERS&id0=42000227&var_name0=user-agent, client: X.X.X.X,'
        _nxlog[4] += 'server: blog.memze.ro, request: "GET /phpMyAdmin-2.8.2/scripts/setup.php HTTP/1.1", host: "X.X.X.X"'
        ret=list()
        for _line in _nxlog:
            ret.append(nxlog.parse_date(_line))
        self.assertEqual(ret, ['2013/11/10 07:36:19', '2013/3/10 14:36:19', '2013-3-10 07:36:19', 'Feb   4 07:36:19', 'Feb   4 07:36:19']) 

    def test_unify_date(self):
        _dates=['2013/11/10 07:36:19', '2013/3/10 14:36:19', '2013-3-10 07:36:19', 'Jul 07   07:36:19', 'Feb  4 07:36:19']
        ret=list()

        for _date in _dates:
            ret.append(nxlog.unify_date(_date))
        self.assertEqual(ret, ['20131110T07:36:19', '20130310T14:36:19', '20130310T07:36:19', '20170707T07:36:19', '20170204T07:36:19'])
        
    def test_coords(self):
        _ips=['198.41.0.4', '192.33.4.12', '192.5.5.241', '2001:500:9f::42', '2001:500:84::b' ]
        ret=list()
        for _ip in _ips:
            ret.append(nxlog.coords(_ip))
        self.assertEqual(ret, ['[38.959900, -77.342800]', '[37.751000, -97.822000]', '[37.751000, -97.822000]', None, None])                    
