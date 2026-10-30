import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from analyzer_web.core import initialize
from analyzer_web.context_graph import ProjectGraph
from analyzer_web.decoders.ad_acl import decode_acl, index_acl, sid_map, AD_GUID_MAP, ZERO_GUID

USER='S-1-5-21-1-2-3-1100'; TARGET='S-1-5-21-1-2-3-1101'


def acl(trustee=USER,mask=262144,**extra):
    return dict(trustee_sid=trustee,rights_raw=mask,access_type='Allow',object_type=ZERO_GUID,**extra)


class ACLTests(unittest.TestCase):
    def decode(self,ace): return decode_acl(dict(name='target',object_class=['user'],aces=[ace]),{}, {'S-1-5-21-1-2-3':'lab.test'},42)[0]

    def test_mask_zero_guid_and_provenance(self):
        row=self.decode(acl());self.assertIn('WriteDacl',row['rights_summary']);self.assertNotIn('GenericAll',row['rights_summary']);self.assertIn('Без ограничения',row['target_property']);self.assertTrue(row['is_notable_lead']);self.assertEqual(row['record_id'],42);self.assertFalse(row['effective_access_evaluated'])

    def test_deny_and_inherit_only_are_not_allow_leads(self):
        denied=acl();denied['access_type']='Deny';self.assertFalse(self.decode(denied)['is_notable_lead']);self.assertFalse(self.decode(acl(propagation_flags=2))['is_notable_lead']);self.assertTrue(self.decode(acl(is_inherited=True))['is_notable_lead'])

    def test_domain_rid_not_machine_rid(self):
        self.assertFalse(self.decode(acl('S-1-5-21-1-2-3-512'))['is_notable_lead']);self.assertTrue(self.decode(acl('S-1-5-21-4-5-6-512'))['is_notable_lead']);self.assertFalse(self.decode(acl('S-1-5-18'))['is_notable_lead'])

    def test_schema_guid_and_replication_are_not_attack_claims(self):
        self.assertEqual(AD_GUID_MAP['5b47d60f-6090-40b2-9f37-2a4de88f3063'],'Атрибут: msDS-KeyCredentialLink');self.assertNotIn('5b0b6110-4088-403c-9c1f-00b56b2b0180',AD_GUID_MAP)
        ace_record=acl(mask=256);ace_record['object_type']='1131f6aa-9c07-11d1-f79f-00c04fc2dcd2';self.assertIn('не подтверждает',self.decode(ace_record)['factual_note'])

    def test_missing_descriptor_and_masks(self):
        row=decode_acl({'name':'unknown','descriptor_status':'missing'}, {}, {})[0];self.assertEqual(row['kind'],'ad_acl_unavailable');self.assertFalse(row['is_notable_lead'])
        for value,name in [(983551,'GenericAll'),(131112,'GenericWrite'),(0x10000000,'GenericAll')]: self.assertIn(name,self.decode(acl(mask=value))['rights_summary'])
        self.assertFalse(self.decode(acl(mask='invalid'))['is_notable_lead'])


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.db=sqlite3.connect(':memory:');self.db.row_factory=sqlite3.Row;initialize(self.db)
        self.db.execute("INSERT INTO projects(id,name,path,hostname,metadata_json,errors_json) VALUES('p','Test',?,'HOST','{}','[]')",(str(self.root),))
    def tearDown(self): self.db.close();self.temp.cleanup()
    def record(self,section,source,data): self.db.execute("INSERT INTO records(project_id,section,source,ordinal,data_json) VALUES('p',?,?,0,?)",(section,source,json.dumps(data)))

    def test_sid_merge_cross_module_deny_and_allow_kept(self):
        self.record('identity','token',dict(sid=USER,name='LAB\\alice',groups=[],privileges=[]));self.record('domain','all_users',dict(attributes={'objectsid':[USER],'samaccountname':['alice'],'objectclass':['user'],'distinguishedname':['CN=alice,DC=lab,DC=test']}));denied=acl();denied['access_type']='Deny';self.record('permissions','domain_acl',dict(name='target',object_sid=TARGET,distinguished_name='CN=target,DC=lab,DC=test',object_class=['user'],aces=[acl(),denied]));self.record('logs','services_state',dict(Name='svc',StartName='LAB\\alice'));index_acl(self.db,'p');graph=ProjectGraph(self.db,'p')
        users=[n for n in graph.nodes.values() if n['properties'].get('sid')==[USER]];self.assertEqual(len(users),1);user=users[0];self.assertTrue({'identity','domain','permissions','logs'}<=set(user['sections']));view=graph.view('domain',user['id']);self.assertEqual(len([e for e in view['edges'] if e['layer']=='acl']),2);self.assertTrue(any(n['kind']=='service' for n in view['nodes']));self.assertEqual(len(graph.view(focus=user['id'],layers=[])['nodes']),1)

    def test_same_short_name_different_domains_stays_separate(self):
        for subject_sid,name in [(USER,'ONE\\alice'),(TARGET,'TWO\\alice')]: self.record('identity','token',dict(sid=subject_sid,name=name,groups=[],privileges=[]))
        self.record('logs','services_state',dict(Name='ambiguous',StartName='alice'));graph=ProjectGraph(self.db,'p');subjects=[n for n in graph.nodes.values() if n['kind'] in {'user','principal'}];self.assertEqual(len(subjects),3);unresolved=next(n for n in subjects if n['label']=='alice');self.assertNotIn('sid',unresolved['properties'])

    def test_canonical_file_copy_and_profile_boundary(self):
        self.record('identity','profiles',dict(sid=USER,path=r'C:\Users\alice'));self.record('identity','profiles',dict(sid=TARGET,path=r'C:\Users\alice2'));path=self.root/'history.txt';path.write_text('Get-Service\n',encoding='utf-8');self.db.execute("INSERT INTO artifacts(project_id,section,source,original_path,local_path,name,length,metadata_json) VALUES('p','logs','powershell_history',?,?, 'history.txt',12,'{}')",(r'C:\Users\ALICE2\history.txt',str(path)));self.record('permissions','file_acl',dict(path=r'c:/users/alice2/history.txt',access=[]));graph=ProjectGraph(self.db,'p');files=[n for n in graph.nodes.values() if n['kind']=='file'];self.assertEqual(len(files),1);self.assertEqual(len(files[0]['collected_files']),1);alice=next(n for n in graph.nodes.values() if n['properties'].get('sid')==[USER]);alice2=next(n for n in graph.nodes.values() if n['properties'].get('sid')==[TARGET]);self.assertEqual(alice['collected_files'],[]);self.assertEqual(len(alice2['collected_files']),1);self.assertEqual(alice2['leads'][0]['commands'],['Get-Service']);path.unlink();graph=ProjectGraph(self.db,'p');self.assertTrue(all(not n['collected_files'] for n in graph.nodes.values()))

    def test_limits_paging_project_scope_and_sid_map(self):
        self.record('identity','profiles',dict(sid=USER,path=r'C:\Users\local'));self.record('identity','token',dict(sid=USER,name='HOST\\local'));names,domains=sid_map(self.db,'p');self.assertEqual(names[USER]['name'],'HOST\\local');self.assertEqual(domains,{});self.assertNotIn('S-1-5-21-1-2-3-512',names)
        for i in range(30): self.record('logs','services_state',dict(Name=f'svc{i:02}'))
        graph=ProjectGraph(self.db,'p');one=graph.view(focus=graph.host,limit=12);two=graph.view(focus=graph.host,limit=12,offset=11);self.assertEqual(len(one['nodes']),12);self.assertEqual(one['total_neighbours'],31);self.assertEqual({n['id'] for n in one['nodes']}&{n['id'] for n in two['nodes']},{graph.host});self.assertEqual(graph.view()['nodes'],[])
        with self.assertRaises(ValueError): ProjectGraph(self.db,'other')
        with self.assertRaises(ValueError): graph.view(focus='outside-project')

    def test_service_process_and_tcp_are_factual_edges(self):
        self.record('network','processes',dict(pid=42,name='db.exe',path=r'C:\db.exe'));self.record('logs','services_state',dict(Name='db',ProcessId=42));self.record('network','tcp',dict(pid=42,local_address='127.0.0.1',local_port=5432,state='Listen'));graph=ProjectGraph(self.db,'p');process=next(n for n in graph.nodes.values() if n['kind']=='process');view=graph.view(focus=process['id']);self.assertTrue(any(n['kind']=='service' for n in view['nodes']));self.assertTrue(any(n['kind']=='port' for n in view['nodes']));self.assertFalse(any(e['tentative'] for e in view['edges']))


if __name__=='__main__': unittest.main()
