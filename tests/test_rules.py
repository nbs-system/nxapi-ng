from unittest import TestCase
from nxapi import rules


class TestRules(TestCase):
    maxDiff = None

    def test_short_str(self):
        rule = {'negative': True, 'detection': 'str:pif', 'msg': 'test msg', 'mz': 'BODY', 'score': '$XSS:3', 'sid': 5}
        self.assertEqual(rules.short_str(rule),
                         'MainRule negative "str:pif" "msg:test msg" "mz:BODY" "s:$XSS:3" id:5 ;')

    def test_explain(self):
        rule = {'negative': True, 'detection': 'str:pif', 'msg': 'test msg', 'mz': 'BODY', 'score': '$XSS:3', 'sid': 5}
        self.assertEqual(rules.explain(rule),
                         'The rule number <strong>5</strong> is <strong>not</strong> setting the <strong>$XSS</strong>'
                         ' score to <strong>3</strong> when it finds the string <strong>pif</strong>'
                         '  the <strong>body</strong>.')
        rule = {'negative': True, 'detection': 'str:pif', 'msg': 'test msg', 'mz': 'BODY|URL', 'score': '$XSS:3', 'sid': 5}
        self.assertEqual(rules.explain(rule),
                         'The rule number <strong>5</strong> is <strong>not</strong> setting the <strong>$XSS</strong>'
                         ' score to <strong>3</strong> when it finds the string <strong>pif</strong>'
                         '  the <strong>body</strong>, the <strong>url</strong>.')

    def test_parse(self):
        rule = 'MainRule negative "str:a" "msg:t" "mz:BODY" "s:$XSS:3" id:5 ;'
        errors, warnings, ret = rules.parse_rule(rule)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, ['rule IDs below 10k are reserved (5)'])
        self.assertEqual(ret, {'mz:': ['BODY'], 'str:': 'str:a', 's:': '$XSS:3', 'negative': '', 'id:': '5', 'msg:': 't'})

        rule = 'MainRule negative "str:a" "msg:t" "mz:BODY|URL" "s:$XSS:3" id:5 ;'
        errors, warnings, ret = rules.parse_rule(rule)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, ['rule IDs below 10k are reserved (5)'])
        self.assertEqual(ret, {'mz:': ['BODY', 'URL'], 'str:': 'str:a', 's:': '$XSS:3', 'negative': '', 'id:': '5', 'msg:': 't'})

    def test_validate(self):
        rule = {'negative': True, 'detection': 'str:pif', 'msg': 'test msg', 'mz': 'BODY', 'score': '$XSS:3', 'sid': 5}
        errors, warnings = rules.validate(rule)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, ['rule IDs below 10k are reserved (5)'])

        rule = {'negative': True, 'detection': 'str:pif', 'msg': 'test msg', 'mz': 'BODY|URL|WRONG', 'score': '$XSS:3',
                'sid': 100005}
        errors, warnings = rules.validate(rule)
        print(errors)
        self.assertIn("WRONG' is not a known sub-part of mz", str(errors))
        self.assertEqual(warnings, [])

