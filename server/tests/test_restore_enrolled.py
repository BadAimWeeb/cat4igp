#!/usr/bin/env python3
"""Offline parser checks: python3 server/tests/test_restore_enrolled.py."""
import unittest

from restore_enrolled import ping_replies


class PingReplyAccounting(unittest.TestCase):
    def test_timestamped_and_plain_echo_replies_only(self):
        output = (
            '[1700000000.123456] 64 bytes from 198.18.0.2: icmp_seq=1 ttl=64 time=0.123 ms\n'
            '[1700000000.323456] no answer yet for icmp_seq=2\n'
            '[1700000000.523456] From 198.18.0.1 icmp_seq=2 Destination Host Unreachable\n'
            '64 bytes from 198.18.0.2: icmp_seq=3 ttl=64 time<1 ms\n'
            '4 packets transmitted, 2 received, +1 errors, 50% packet loss\n'
        )
        self.assertEqual(ping_replies(output, 4, 2), {1, 3})

    def test_notices_and_errors_are_not_successes(self):
        output = (
            '[1700000000.123456] no answer yet for icmp_seq=1\n'
            'From 198.18.0.1 icmp_seq=2 Destination Host Unreachable\n'
        )
        self.assertEqual(ping_replies(output, 2, 0), set())
        with self.assertRaisesRegex(AssertionError, 'accounting mismatch'):
            ping_replies(output, 2, 1)

    def test_duplicate_echoes_fail_closed(self):
        reply = '64 bytes from 198.18.0.2: icmp_seq=1 ttl=64 time=0.1 ms\n'
        duplicate = '64 bytes from 198.18.0.2: icmp_seq=1 ttl=64 time=0.2 ms (DUP!)\n'
        # iputils excludes duplicate echoes from its received count. Do not
        # silently collapse them into a seemingly healthy unique-reply set.
        for received in (1, 2):
            with self.subTest(received=received):
                with self.assertRaisesRegex(AssertionError, 'duplicate'):
                    ping_replies(reply + duplicate, 2, received)

    def test_out_of_range_and_unparsed_replies_fail_closed(self):
        for sequence in (0, 4):
            with self.subTest(sequence=sequence):
                with self.assertRaisesRegex(AssertionError, 'outside transmitted range'):
                    ping_replies(f'64 bytes from 198.18.0.2: icmp_seq={sequence} ttl=64 time=1 ms\n', 3, 1)
        with self.assertRaisesRegex(AssertionError, 'accounting mismatch'):
            ping_replies('unrecognized echo reply format\n', 3, 1)


if __name__ == '__main__':
    assert __debug__, 'do not run with Python optimization: parser acceptance uses assertions'
    unittest.main()
