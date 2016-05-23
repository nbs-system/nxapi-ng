from unittest import TestCase
from nxapi import whitelist


class TestWhitelist(TestCase):
    maxDiff = None

    def test_parse(self):
        wlist = 'BasicRule wl:1000;'
        errors, warnings, ret = whitelist.parse(wlist)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {'wl': [1000]})

        wlist = 'BasicRule wl:1000 "mz:$ARGS_VAR:foo";'
        errors, warnings, ret = whitelist.parse(wlist)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {'mz': '$ARGS_VAR:foo', 'wl': [1000]})

        wlist = 'BasicRule wl:1000 "mz:$ARGS_VAR:foo|$URL:/bar";'
        errors, warnings, ret = whitelist.parse(wlist)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {'mz': '$ARGS_VAR:foo|$URL:/bar', 'wl': [1000]})

        wlist = 'BasicRule wl:1000 "mz:$URL:/bar|ARGS";'
        errors, warnings, ret = whitelist.parse(wlist)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {'mz': '$URL:/bar|ARGS', 'wl': [1000]})

        wlist = 'BasicRule wl:1000 "mz:ARGS|NAME";'
        errors, warnings, ret = whitelist.parse(wlist)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {'mz': 'ARGS|NAME', 'wl': [1000]})

        wlist = 'BasicRule wl:1000 "mz:$ARGS_VAR_X:meh";'
        errors, warnings, ret = whitelist.parse(wlist)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {'wl': [1000], 'mz': '$ARGS_VAR_X:meh'})

        wlist = 'BasicRule wl:1000 "mz:$ARGS_VAR_X:^meh";'
        errors, warnings, ret = whitelist.parse(wlist)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {'wl': [1000], 'mz': '$ARGS_VAR_X:^meh'})

        wlist = 'BasicRule wl:1000 "mz:$ARGS_VAR_X:^meh_[0-9]+$"'
        errors, warnings, ret = whitelist.parse(wlist)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(ret, {'wl': [1000], 'mz': '$ARGS_VAR_X:^meh_[0-9]+$'})

    def test_valide(self):
        wlist = {'wl': '1000', 'mz': '$ARGS_VAR_X:^meh_[0-9]+$'}
        errors, warnings = whitelist.validate(wlist)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_explain(self):
        wlist = {'wl': [1000], 'mz': '$ARGS_VAR_X:^meh_[0-9]+$'}
        self.assertEqual(whitelist.explain(wlist), 'Whitelist the rule 1000 if matching in $ARGS_VAR_X:^meh_[0-9]+$.')

        wlist = {'wl': [1000]}
        self.assertEqual(whitelist.explain(wlist), 'Whitelist the rule 1000.')

        wlist = {'mz': '$ARGS_VAR:foo', 'wl': [1000]}
        self.assertEqual(whitelist.explain(wlist), 'Whitelist the rule 1000 if matching in $ARGS_VAR:foo.')

        wlist = {'mz': '$ARGS_VAR:foo|$URL:/bar', 'wl': [1000]}
        self.assertEqual(whitelist.explain(wlist), 'Whitelist the rule 1000 if matching in $ARGS_VAR:foo|$URL:/bar.')

        wlist = {'mz': '$ARGS_VAR:foo|$URL:/bar', 'wl': [1000]}
        self.assertEqual(whitelist.explain(wlist), 'Whitelist the rule 1000 if matching in $ARGS_VAR:foo|$URL:/bar.')