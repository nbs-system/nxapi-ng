from unittest import TestCase
from nxapi import nxlog


class TestProcessing(TestCase):
    maxDiff = None

    def test_parse_nxlog(self):
        _nxlog = list()
        ret = list()
        _nxlog.append('2013/11/10 07:36:19 [error] 8278#0: *5932 NAXSI_FMT: ip=X.X.X.X&server=Y.Y.Y.Y&')
        _nxlog[0] += 'uri=/phpMyAdmin-2.8.2/scripts/setup.php&learning=0&vers=0.52&total_processed=472&total_blocked=204&'
        _nxlog[0] += 'block=0&cscore0=$UWA&score0=8&zone0=HEADERS&id0=42000227&var_name0=user-agent, client: X.X.X.X,'
        _nxlog[0] += 'server: blog.memze.ro, request: "GET /phpMyAdmin-2.8.2/scripts/setup.php HTTP/1.1", host: "X.X.X.X"'
        _nxlog.append('2017-02-20T10:59:03+01:00 xxxx nginx: 2017/02/20 10:59:03 [error] 31557#0: *40698245 NAXSI_FMT:')
        _nxlog[1] += 'ip=1.0.0.1&server=Y.Y.Y.Y&uri=/bidon&learning=1&vers=0.55.3&total_processed=11&total_blocked=11&'
        _nxlog[1] += 'block=1&cscore0=$SQL&score0=40&cscore1=$XSS&score1=64&zone0=HEADERS&id0=1005&var_name0=cookie&'
        _nxlog[1] += 'zone1=HEADERS&id1=1010&var_name1=cookie&zone2=HEADERS&id2=1011&var_name2=cookie&zone3=HEADERS&'
        _nxlog[1] += 'id3=1315&var_name3=cookie, client: 1.0.0.1, server: Y.Y.Y.Y, request: "GET /bidon HTTP/1.1", '
        _nxlog[1] += 'host: "Y.Y.Y.Y", referrer: "http://Y.Y.Y.X/"'
        t = list()
        for _line in _nxlog:
            errors, t = nxlog.parse_nxlog(_line)
            ret.extend(t)
        self.assertEqual(errors, list())
        self.assertEqual(ret, [{'uri': '/phpMyAdmin-2.8.2/scripts/setup.php', 'block': '0',
                                  'total_blocked': '204', 'ip': 'X.X.X.X', 'server': 'Y.Y.Y.Y',
                                'learning': '0', 'zone': 'HEADERS', 'score0': '8',
                                'var_name': 'user-agent', 'cscore0': '$UWA', 'id': '42000227',
                                'total_processed': '472', 'vers': '0.52', 'date': '20131110T07:36:19', 'coords': None},
                                {'total_processed': '11', 'vers': '0.55.3', 'learning': '1', 'cscore0': '$SQL',
                                'cscore1': '$XSS', 'ip': '1.0.0.1', 'uri': '/bidon', 'server': 'Y.Y.Y.Y',
                                'var_name': 'cookie', 'score0': '40', 'score1': '64', 'total_blocked': '11',
                                'date': '20170220T10:59:03', 'coords': '[-37.700000, 145.183300]',
                                'zone': 'HEADERS', 'id': '1005', 'block': '1'},
                                {'total_processed': '11', 'vers': '0.55.3', 'learning': '1', 'cscore0': '$SQL',
                                     'cscore1': '$XSS', 'ip': '1.0.0.1', 'uri': '/bidon', 'server': 'Y.Y.Y.Y',
                                'var_name': 'cookie', 'score0': '40', 'score1': '64', 'total_blocked': '11',
                                'date': '20170220T10:59:03', 'coords': '[-37.700000, 145.183300]', 'zone': 'HEADERS',
                                'id': '1010', 'block': '1'},
                                {'total_processed': '11', 'vers': '0.55.3', 'learning': '1', 'cscore0': '$SQL',
                                     'cscore1': '$XSS', 'ip': '1.0.0.1', 'uri': '/bidon', 'server': 'Y.Y.Y.Y',
                                'var_name': 'cookie', 'score0': '40', 'score1': '64', 'total_blocked': '11',
                                'date': '20170220T10:59:03', 'coords': '[-37.700000, 145.183300]', 'zone': 'HEADERS',
                                'id': '1011', 'block': '1'},
                                {'total_processed': '11', 'vers': '0.55.3', 'learning': '1', 'cscore0': '$SQL',
                                     'cscore1': '$XSS', 'ip': '1.0.0.1', 'uri': '/bidon', 'server': 'Y.Y.Y.Y',
                                'var_name': 'cookie', 'score0': '40', 'score1': '64', 'total_blocked': '11',
                                'date': '20170220T10:59:03', 'coords': '[-37.700000, 145.183300]', 'zone': 'HEADERS',
                                'id': '1315', 'block': '1'}])

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
            ret.append(nxlog.coords(_ip, db='nxapi/data/GeoIPCity_stripped_down.dat'))
        self.assertEqual(ret, ['[38.959900, -77.342800]', '[37.751000, -97.822000]', '[37.751000, -97.822000]', None, None])                    
