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
                                                     'total_processed': '472', 'vers': '0.52'})