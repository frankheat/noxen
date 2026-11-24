import unittest

from noxen.stack_format import format_stack_frame
from noxen.monitor import render_event_detail
from noxen.rendering import _stack_lines


class StackFormatTests(unittest.TestCase):
    def test_java_types_arrays_and_constructors(self):
        self.assertEqual(
            format_stack_frame('Ldev/noxen/playground/SecurityScenarioState;,recordReviewStatus,(Landroid/content/Context;Ljava/lang/String;)V'),
            'dev.noxen.playground.SecurityScenarioState.recordReviewStatus(android.content.Context, java.lang.String)',
        )
        self.assertEqual(format_stack_frame('Lapp/Test$Inner;,<init>,([[I[Ljava/lang/String;Z)V'),
                         'app.Test$Inner.<init>(int[][], java.lang.String[], boolean)')
        self.assertEqual(format_stack_frame('Lapp/Test;,read,()Ljava/lang/String;'), 'app.Test.read()')

    def test_unknown_and_java_frames_are_preserved(self):
        for frame in ('app.Test.run(Test.java:42)', 'native frame', 'Lapp/Test;,run,([)V',
                      'Lapp/Test;,run,(V)V', 'Lapp/Test;,run,()garbage'):
            self.assertEqual(format_stack_frame(frame), frame)

    def test_monitor_and_history_share_the_format(self):
        frame = 'Lapp/Test;,check,(Ljava/lang/String;)Z'
        event = {'stack': [frame], 'class': 'app.Test', 'method': 'check'}
        self.assertIn('app.Test.check(java.lang.String)', render_event_detail(event).plain)
        self.assertIn('app.Test.check(java.lang.String)', '\n'.join(_stack_lines([frame], 16)))
        self.assertEqual(event['stack'], [frame])
