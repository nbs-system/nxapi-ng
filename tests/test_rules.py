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

        rule = 'MainRule negative "rx:^[\da-z_]+$" "mz:$ARGS_VAR:id|$BODY_VAR:id" "s:$LOG_TEST:1" id:42000456;'
        errors, warnings, ret = rules.parse_rule(rule)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {'rx:': 'rx:^[\\da-z_]+$', 'negative': '', 's:': '$LOG_TEST:1', 'id:': '42000456', 'mz:':
            ['$ARGS_VAR:id', '$BODY_VAR:id']})

        rule = 'MainRule "str:encoding=\\"utf-16\\"" "mz:BODY" "s:$UWA:8" id:42000459;'
        errors, warnings, ret = rules.parse_rule(rule)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {'mz:': ['BODY'], 'str:': 'str:encoding="utf-16"', 's:': '$UWA:8', 'id:': '42000459'})

        rule = 'MainRule "str:\\"" "msg:magento XSS" "mz:$ARGS_VAR:bridgename" "s:$UWA:8" id:42000466;'
        errors, warnings, ret = rules.parse_rule(rule)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {'msg:': 'magento XSS', 's:': '$UWA:8', 'id:': '42000466',
                               'mz:': ['$ARGS_VAR:bridgename'], 'str:': 'str:"'})

        rule = 'MainRule "str:\\"" "msg:magento XSS" "mz:$ARGS_VAR:bridgename" "s:$UWA:8" "id:42000466;'
        errors, warnings, ret = rules.parse_rule(rule)
        self.assertEqual(errors, ['No closing quotation in your rule'])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {})

        rule = '"str:\\"" "msg:magento XSS" "mz:$ARGS_VAR:bridgename" "s:$UWA:8" id:42000466;'
        errors, warnings, ret = rules.parse_rule(rule)
        self.assertEqual(errors, ['No mainrule/basicrule keyword.'])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {})

        rule = 'MainRule MainRule "str:a" "msg:magento XSS" "mz:$ARGS_VAR:bridgename" "s:$UWA:8" id:42000466;'
        errors, warnings, ret = rules.parse_rule(rule)
        self.assertEqual(errors, ['Duplicates elements: MainRule'])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {})

        rule = 'MainRule wrong "str:a" "msg:magento XSS" "mz:$ARGS_VAR:bridgename" "s:$UWA:8" id:42000466;'
        errors, warnings, ret = rules.parse_rule(rule)
        self.assertEqual(errors, ["'wrong' is an invalid element and thus can not be parsed."])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {})


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

