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

        wlist = 'BasicRule wl:1000 "mz:$ARGS_VAR:foo|$URL:/bar;'
        errors, warnings, ret = whitelist.parse(wlist)
        self.assertEqual(errors, ['No closing quotation in your whitelist'])
        self.assertEqual(warnings, [])

    def test_validate(self):
        wlist = {'wl': [1000], 'mz': '$ARGS_VAR_X:^meh_[0-9]+$'}
        errors, warnings = whitelist.validate(wlist)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

        wlist = {'wl': [1000], 'mz': '$ARGS_VAR_X:test|NAME'}
        errors, warnings = whitelist.validate(wlist)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

        wlist = {'wl': [1000], 'mz': '$ARGS_VAR_X|ARGS_VAR_X|ARGS_VAR_X$'}
        errors, warnings = whitelist.validate(wlist)
        self.assertEqual(errors, ['The last argument of your matchzone with two pipes is not "NAME"'])
        self.assertEqual(warnings, [])

        wlist = {'wl': [1000], 'mz': '|||'}
        errors, warnings = whitelist.validate(wlist)
        self.assertEqual(errors, ['The matchzone has more than 2 pipes.'])
        self.assertEqual(warnings, [])

        wlist = {'wl': [1000], 'mz': '|'}
        errors, warnings = whitelist.validate(wlist)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

        wlist = {'wl': [1000], 'mz': '$ARGS_VAR_X:lol|ARGS_VAR_X'}
        errors, warnings = whitelist.validate(wlist)
        self.assertEqual(errors, ['You can not use regexp matchzone with non-regexp one'])
        self.assertEqual(warnings, [])

        wlist = {'wl': [1000], 'mz': '$ARGS_VAR_X:lol|$ARGS_VAR_X:lol|$ARGS_VAR_X:lol'}
        errors, warnings = whitelist.validate(wlist)
        self.assertEqual(errors, ['The last argument of your matchzone with two pipes is not "NAME"'])
        self.assertEqual(warnings, [])

        wlist = {'wl': [1000], 'mz': 'WRONG'}
        errors, warnings = whitelist.validate(wlist)
        self.assertEqual(errors, ["The matchzone WRONG is not valid."])
        self.assertEqual(warnings, [])

        wlist = {'wl': [1000], 'mz': 'ARGS|$ARGS_VAR_X|NAME'}
        errors, warnings = whitelist.validate(wlist)
        self.assertEqual(errors, ['You can not use regexp matchzone with non-regexp one'])
        self.assertEqual(warnings, [])

        wlist = {'wl': [1000], 'mz': 'ARGS:WRONG'}
        errors, warnings = whitelist.validate(wlist)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, ['The expression WRONG is not in lowercase.'])


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