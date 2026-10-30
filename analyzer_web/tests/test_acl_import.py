import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from analyzer_web.core import initialize, index_project
from analyzer_web.decoders.ad_acl import decode_acl, ZERO_GUID


class ACLImportTests(unittest.TestCase):
    def test_complete_import_and_atomic_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'portable_collection.json').write_text(json.dumps({'schema_version':'3.0','metadata':{'hostname':'HOST'},'status':'success'}))
            subject = 'S-1-5-21-1-2-3-1100'
            fixtures = {
                'identity/token': [{'sid':subject,'name':'LAB\\user','groups':[],'privileges':[]}],
                'permissions/domain_acl': [{'name':'target','object_class':['user'],'aces':[{'trustee_sid':subject,'access_type':'Allow','rights_raw':262144,'object_type':ZERO_GUID}]}],
                'permissions/file_acl': [{'path':'C:\\file.txt','access':[]}],
                'recent/recent_registry': [{'name':'example.txt'}],
                'logs/userassist': [{'name':'grfg.rkr'}],
            }
            for key, records in fixtures.items():
                path=root/(key+'.raw.json');path.parent.mkdir(exist_ok=True)
                path.write_text(json.dumps({'source':{'status':'success'},'records':records}))
            db=sqlite3.connect(':memory:');db.row_factory=sqlite3.Row;db.execute('PRAGMA foreign_keys=ON');initialize(db)
            pid=index_project(db,root)
            ace=json.loads(db.execute("SELECT data_json FROM decoded WHERE decoder='ad_acl'").fetchone()[0])
            self.assertTrue(ace['matches_current_token'])
            self.assertTrue(ace['is_notable_lead'])
            self.assertEqual(db.execute('SELECT count(*) FROM records').fetchone()[0],5)
            self.assertEqual(db.execute("SELECT count(*) FROM decoded WHERE decoder='file_acl'").fetchone()[0],1)
            self.assertGreater(db.execute('SELECT count(*) FROM findings').fetchone()[0],0)
            before=[tuple(r) for r in db.execute('SELECT * FROM records')]
            with patch('analyzer_web.core.decode_userassist',side_effect=TypeError('decoder failure')):
                with self.assertRaises(TypeError):index_project(db,root)
            self.assertEqual(before,[tuple(r) for r in db.execute('SELECT * FROM records')])
            self.assertEqual(index_project(db,root),pid)
            self.assertEqual(db.execute("SELECT count(*) FROM decoded WHERE decoder='ad_acl'").fetchone()[0],1)
            db.close()

    def test_change_password_is_not_reset_password(self):
        def decode(guid,trustee='S-1-1-0',mask=256,access='Allow'):
            return decode_acl({'name':'user','object_class':['user'],'aces':[{'trustee_sid':trustee,'rights_raw':mask,'access_type':access,'object_type':guid}]},{},{})[0]
        self.assertFalse(decode('ab721a53-1e2f-11d0-9819-00aa0040529b')['is_notable_lead'])
        self.assertTrue(decode('00299570-246d-11d0-a768-00aa006e0529')['is_notable_lead'])
        self.assertFalse(decode(ZERO_GUID,mask=262144,access='Deny')['is_notable_lead'])
        self.assertTrue(decode(ZERO_GUID,trustee='S-1-5-10',mask=262144)['is_notable_lead'])

    def test_expected_role_requires_exact_sid_property_and_mask(self):
        prefix='S-1-5-21-1-2-3'
        def check(trustee,mask,prop):
            return decode_acl({'name':'target','object_class':['user'],'aces':[{'trustee_sid':trustee,'rights_raw':mask,'object_type':prop,'access_type':'Allow'}]}, {}, {prefix:'lab.test'})[0]
        prop='5b47d60f-6090-40b2-9f37-2a4de88f3063'
        self.assertEqual(check(prefix+'-526',48,prop)['classification'],'expected_role')
        self.assertTrue(check(prefix+'-1100',48,prop)['is_notable_lead'])
        self.assertTrue(check(prefix+'-526',262144,prop)['is_notable_lead'])
        self.assertTrue(check('S-1-5-21-9-8-7-526',48,prop)['is_notable_lead'])

    def test_apply_gpo_is_not_edit_gpo(self):
        rec={'name':'policy','object_class':['groupPolicyContainer'],'aces':[{'trustee_sid':'S-1-5-11','rights_raw':256,'object_type':'edacfd8f-ffb3-11d1-b41d-00a0c968f939','access_type':'Allow'}]}
        self.assertFalse(decode_acl(rec,{}, {})[0]['is_notable_lead'])
        rec['aces'][0]['rights_raw']=262144
        self.assertTrue(decode_acl(rec,{}, {})[0]['is_notable_lead'])

if __name__=='__main__':unittest.main()
