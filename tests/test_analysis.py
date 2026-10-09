import unittest,tempfile
from pathlib import Path
from cryptodebt import *
class AnalysisTests(unittest.TestCase):
    def test_dependency_and_debt(self):
        r=scan_project('examples/java');self.assertGreater(len(r['findings']),0);self.assertGreater(r['cadi'],0)
        self.assertIn('SizeAssump',r['smell_counts']);self.assertIn('Serialize',r['smell_counts'])
        for f in r['findings']:self.assertEqual(f['path'][0],f['root']);self.assertAlmostEqual(f['debt'],(1+math.log2(1+f['fanout']))*(1+.5*f['boundary']))
    def test_noncrypto_and_comments(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,'Plain.java').write_text('class Plain { byte[] b = new byte[256]; } // Signature.getInstance("RSA")')
            r=scan_project(d);self.assertEqual(r['roots'],[]);self.assertEqual(r['findings'],[])
    def test_suppression(self):
        r=scan_project('examples/java',policy_paths=('LocalSigner.java',));self.assertTrue(r['suppressions'])
    def test_role_patch_preserves_algorithm(self):
        r=role_factory_patch('examples/java/LocalSigner.java');self.assertIn('SHA256withRSA',r['policy']);self.assertNotIn('SHA256withRSA',r['rewritten']);self.assertIn('CryptoPolicy.signingSuite0()',r['rewritten'])
    def test_invalid_normalizer(self):
        with self.assertRaises(ValueError):scan_project('examples/java',dmax=0)
    def test_eight_smell_categories_have_executable_fixture(self):
        r=scan_project('examples/java')
        self.assertEqual(set(r['smell_counts']),set(RECIPES))
