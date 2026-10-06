"""Verify setup command ordering with a fake psql; never connects to a DB."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SetupTests(unittest.TestCase):
    def run_loader(self, args):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            log = directory / 'calls.jsonl'
            fake = directory / 'psql'
            fake.write_text('#!/usr/bin/env python3\nimport os,sys,json\n'
                            'with open(os.environ["TEST_DATABASE_CALLS"], "a") as f: '
                            'f.write(json.dumps(sys.argv[1:])+"\\n")\n')
            fake.chmod(0o755)
            env = dict(os.environ, PATH=f'{directory}:{os.environ["PATH"]}',
                       DATABASE_URL='postgresql://unused/test', TEST_DATABASE_CALLS=str(log))
            result = subprocess.run(['bash', str(ROOT / 'scripts/load_db.sh'), *args],
                                    capture_output=True, text=True, env=env)
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, calls

    def test_default_applies_all_migrations_without_seed(self):
        result, calls = self.run_loader([])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c[c.index('-f') + 1] for c in calls], [
            'supabase/migrations/0001_init.sql', 'supabase/migrations/0002_alerts_rls.sql',
            'supabase/migrations/0003_batches.sql'])
        self.assertTrue(all('ON_ERROR_STOP=1' in c for c in calls))

    def test_seed_requires_explicit_replacement(self):
        result, calls = self.run_loader(['--seed', 'cicids'])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(calls, [])

    def test_cicids_seed_follows_every_migration(self):
        result, calls = self.run_loader(['--seed', 'cicids', '--replace-data'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[-1][-1], 'data/cicids_seed.sql')


if __name__ == '__main__':
    unittest.main()
