from unittest import TestCase
from nxapi import processing


class TestProcessing(TestCase):
    maxDiff = None

    def test_short_str(self):
        whitelist = {'mz': ['$HEADERS_VAR:user-agent'], 'wl': [42000227]}
        nxlog = {'uri': '/phpMyAdmin-2.8.2/scripts/setup.php', 'block': '0',
                                                     'total_blocked': '204', 'ip': 'X.X.X.X', 'server': 'Y.Y.Y.Y',
                                                     'learning': '0', 'zone0': 'HEADERS', 'score0': '8',
                                                     'var_name0': 'user-agent', 'cscore0': '$UWA', 'id0': '42000227',
                                                     'total_processed': '472', 'vers': '0.52'}
        self.assertTrue(processing.check_whitelist(whitelist, nxlog))

        whitelist = {'mz': ['$HEADERS_VAR:user-agent'], 'wl': [42000227]}
        nxlog = {'uri': '/phpMyAdmin-2.8.2/scripts/setup.php', 'block': '0',
                                                     'total_blocked': '204', 'ip': 'X.X.X.X', 'server': 'Y.Y.Y.Y',
                                                     'learning': '0', 'zone0': 'BODY', 'score0': '8',
                                                     'var_name0': 'test', 'cscore0': '$UWA', 'id0': '42000227',
                                                     'total_processed': '472', 'vers': '0.52'}
        self.assertFalse(processing.check_whitelist(whitelist, nxlog))

        whitelist = {'mz': ['$HEADERS_VAR:user-agent'], 'wl': [42000227, 10]}
        nxlog = {'uri': '/phpMyAdmin-2.8.2/scripts/setup.php', 'block': '0',
                                                     'total_blocked': '204', 'ip': 'X.X.X.X', 'server': 'Y.Y.Y.Y',
                                                     'learning': '0', 'zone0': 'HEADERS', 'score0': '8',
                                                     'var_name0': 'user-agent', 'cscore0': '$UWA', 'id0': '10',
                                                     'total_processed': '472', 'vers': '0.52'}
        self.assertTrue(processing.check_whitelist(whitelist, nxlog))

        whitelist = {'mz': ['$HEADERS_VAR:user-agent'], 'wl': [42000227, 11]}
        nxlog = {'uri': '/phpMyAdmin-2.8.2/scripts/setup.php', 'block': '0',
                                                     'total_blocked': '204', 'ip': 'X.X.X.X', 'server': 'Y.Y.Y.Y',
                                                     'learning': '0', 'zone0': 'HEADERS', 'score0': '8',
                                                     'var_name0': 'user-agent', 'cscore0': '$UWA', 'id0': '10',
                                                     'total_processed': '472', 'vers': '0.52'}
        self.assertFalse(processing.check_whitelist(whitelist, nxlog))

        whitelist = {'mz': ['$HEADERS_VAR_X:^user-agent$'], 'wl': [42000227, 10]}
        nxlog = {'uri': '/phpMyAdmin-2.8.2/scripts/setup.php', 'block': '0',
                 'total_blocked': '204', 'ip': 'X.X.X.X', 'server': 'Y.Y.Y.Y',
                 'learning': '0', 'zone0': 'HEADERS', 'score0': '8',
                 'var_name0': 'user-agent', 'cscore0': '$UWA', 'id0': '10',
                 'total_processed': '472', 'vers': '0.52'}
        self.assertTrue(processing.check_whitelist(whitelist, nxlog))
