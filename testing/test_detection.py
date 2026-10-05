"""Handbook guarantees, exercised through the actual CSV analyzer (no DB)."""
import csv
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BATCH = '11111111-1111-4111-8111-111111111111'


def analyze(path):
    result = subprocess.run(['python3', str(ROOT / 'ml/analyze.py'), str(path), '--batch', BATCH],
                            capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


class DetectionTests(unittest.TestCase):
    def flow(self, label=None, timestamp='2026-01-01T00:00:00Z'):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'flow.csv'
            header = ['Src IP', 'Dst IP', 'Dst Port', 'Timestamp', 'Protocol']
            row = ['192.0.2.1', '192.0.2.2', '80', timestamp, '6']
            if label is not None:
                header.append('Label'); row.append(label)
            with path.open('w', newline='') as fh:
                writer = csv.writer(fh); writer.writerow(header); writer.writerow(row)
            return analyze(path)

    def test_annotation_is_not_scored_as_detection(self):
        result = self.flow('Web Attack - Sql Injection')
        self.assertEqual(result['eval']['tp'], 0)
        self.assertEqual(result['eval']['fn'], 1)
        self.assertEqual(result['eval']['f1'], 0)
        self.assertEqual(len(result['incidents']), 1)
        self.assertTrue(all(s['detector'] == 'label' and s['score'] == 0.5 for s in result['signals']))
        self.assertEqual(result['standardization']['attack_classes'][0]['corroboration_pct'], 0)

    def test_unlabelled_quiet_flow_has_no_incident_or_eval(self):
        result = self.flow()
        self.assertEqual(result['incidents'], [])
        self.assertIsNone(result['eval'])
        self.assertEqual(result['standardization']['rows_standardized'], 1)

    def test_invalid_timestamp_is_a_clean_error(self):
        self.assertIn('error', self.flow(timestamp='not-a-date'))

    def test_empty_and_nonflow_csv_are_clean_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'bad.csv'
            for content in ['', 'name,value\na,b\n']:
                path.write_text(content)
                self.assertIn('error', analyze(path))

    def test_demo_slices_are_repeatable_and_incident_scoped(self):
        for name, technique, count in [('bruteforce_T1110', 'T1110', 2), ('ddos_T1498', 'T1498', 1), ('botnet_T1071', 'T1071', 8)]:
            with self.subTest(name=name):
                path = ROOT / f'data/cicids/demo/demo_{name}.csv'
                first = analyze(path)
                self.assertEqual(first, analyze(path))
                self.assertEqual(len(first['incidents']), count)
                self.assertTrue(any(technique in i['mitre_techniques'] for i in first['incidents']))
                ids = {e['event_id'] for e in first['events']}
                assigned = []
                for alert in first['alerts']:
                    self.assertTrue(set(alert['event_ids']) <= ids)
                    assigned.extend(alert['event_ids'])
                self.assertEqual(len(assigned), len(set(assigned)))
                self.assertTrue(all(s['event_id'] in ids for s in first['signals']))


if __name__ == '__main__':
    unittest.main()
