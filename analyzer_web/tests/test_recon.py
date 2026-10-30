import json
import sqlite3
import unittest

from analyzer_web.core import initialize, _insert_decoded, _derive_recon_findings
from analyzer_web.decoders.network import decode_management
from analyzer_web.decoders.recent import profile_tags


class ReconTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        initialize(self.db)
        self.db.execute("INSERT INTO projects(id,name,path,metadata_json,errors_json) VALUES('p','test','/test','{}','[]')")

    def tearDown(self):
        self.db.close()

    def add(self, decoder, item, source=None):
        _insert_decoded(self.db, 'p', decoder, source or decoder, item)

    def findings(self):
        _derive_recon_findings(self.db, 'p')
        return [dict(row) for row in self.db.execute('SELECT * FROM findings')]

    def test_activity_is_informational_and_profiles_do_not_merge(self):
        self.add('service_events', {'service_name':'BackupAgent','is_driver':False,'account_name':'LocalSystem','profile_signal':True})
        self.add('scheduled_tasks', {'name':'NightlyBackup','runs_elevated':True,'is_vendor_task':False,'profile_signal':True})
        for user,count in [('alice',30),('bob',2)]:
            self.add('userassist', {'profile_path':user,'decoded_name':'editor.exe','run_count':count,'decode_status':'success'})
        self.add('network', {'kind':'dns_cache','name':'intranet.test'}, 'dns_cache')
        rows = self.findings()
        self.assertTrue(all(row['severity'] == 'info' for row in rows))
        profiles = [json.loads(row['evidence_json']) for row in rows if row['source']=='userassist']
        self.assertEqual({p['profile'] for p in profiles}, {'alice','bob'})
        self.assertEqual(len(profiles), 2)
        self.assertTrue(all(p['finding_type']=='profile' for p in profiles))

    def test_ad_flags_deduplicate_and_dc_default_is_not_high(self):
        account = {'sid':'S-1-5-21-1-1001','name':'svc','attributes':{'useraccountcontrol_flags':['DONT_REQ_PREAUTH']}}
        self.add('ad',account,'all_users')
        self.add('ad',account,'asrep_targets')
        self.add('ad',{'name':'DC1$','attributes':{'useraccountcontrol_flags':['SERVER_TRUST_ACCOUNT','TRUSTED_FOR_DELEGATION']}},'computers')
        rows = self.findings()
        self.assertEqual(sum(r['severity']=='high' for r in rows), 1)
        self.assertEqual(len(rows),2)

    def test_unknown_smb_and_deny_do_not_become_write_findings(self):
        self.assertFalse(decode_management({'kind':'smb_server','data':{}})['has_misconfiguration'])
        self.assertFalse(decode_management({'kind':'smb_server','data':{'EnableSMB1Protocol':'False','RequireSecuritySignature':'True'}})['has_misconfiguration'])
        denied = {'kind':'smb_share','data':{'Name':'Docs'},'share_access':[{'AccountName':'Everyone','AccessControlType':'Deny','AccessRight':'Full'}]}
        self.assertFalse(decode_management(denied)['has_misconfiguration'])
        denied['share_access'][0]['AccessControlType']='Allow'
        allowed = decode_management(denied)
        self.assertTrue(allowed['has_misconfiguration'])
        self.assertFalse(allowed['effective_access_evaluated'])

    def test_recent_tags_are_document_context_not_tool_blacklist(self):
        self.assertEqual(profile_tags(r'C:\Tools\mimikatz.exe',''), [])
        self.assertIn('Конфигурация', profile_tags(r'\\fileserver\IT\settings.json',''))
        self.assertIn('Сетевой ресурс', profile_tags(r'\\fileserver\IT\settings.json',''))


if __name__ == '__main__': unittest.main()
