import csv
import json
import tempfile
import unittest
from pathlib import Path
from analyzer_web.core import connect, initialize, index_project
from analyzer_web.decoders.recent import parse_recent_csv
from analyzer_web.recent_profile import recent_observations


class RecentProfileTests(unittest.TestCase):
    def csv(self, path, rows):
        with path.open('w', encoding='utf-8-sig', newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)

    def test_description_and_target_are_distinct(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'AutomaticDestinations.csv'
            self.csv(p,[{'SourceFile':'test.automaticDestinations-ms','AppId':'unknown','AppIdDescription':'Editor','LocalPath':r'C:\Tools\program.exe','LastModified':'2026-01-01'}])
            row=parse_recent_csv(p)[0]
            self.assertEqual(row['application'],'Editor')
            self.assertEqual(row['target_application'],'program')
            self.assertEqual(row['target_modified'],'')
            self.assertEqual(row['entry_last_modified'],'2026-01-01')
            self.assertEqual(row['source_csv_row'],2)

    def test_static_custom_does_not_imply_script_use(self):
        row={'kind':'custom','application':'Неизвестное приложение','path':r'C:\x.ps1','profile_tags':['Сценарий'],'source_csv':'a.csv'}
        result=list(recent_observations(lambda _: [(row,'custom_destinations')]))[0][-1]
        self.assertEqual(result['possible_activities'],[])
        self.assertEqual(result['custom_records'],1)

    def test_duplicates_only_across_exports(self):
        row={'kind':'automatic','source_csv':'a.csv','raw_csv':{'Path':'x'},'application':'Editor'}
        result=list(recent_observations(lambda _: [(dict(row,profile_path='alice'),'a'),(dict(row,profile_path='alice'),'a'),(dict(row,profile_path='alice',source_csv='b.csv'),'b')]))[0][-1]
        self.assertEqual(result['unique_records'],2)

    def test_real_import_attribution_errors_and_counts(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)/'project'; recent=root/'recent';recent.mkdir(parents=True)
            (root/'portable_collection.json').write_text(json.dumps({'metadata':{},'status':'success'}))
            (recent/'recent_files.raw.json').write_text(json.dumps({'source':{'status':'success'},'records':[{'saved_path':r'C:\Temp\unique.automaticDestinations-ms','path':r'C:\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\hash.automaticDestinations-ms','profile_sid':'S-1-5-21-1-2-3-1000','profile_path':r'C:\Users\alice'}]}))
            for n in (1,2):
                self.csv(recent/f'{n}_AutomaticDestinations.csv',[{'SourceFile':r'D:\copied\unique.automaticDestinations-ms','AppId':'9b9cdc69c1c24e2b','LocalPath':r'C:\Users\bob\settings.ini'}])
            (recent/'broken_CustomDestinations.csv').write_text('wrong,header\na,b\n')
            d=connect(Path(t)/'db');initialize(d);pid=index_project(d,root)
            records=[json.loads(r[0]) for r in d.execute("select data_json from decoded where decoder='recent'")]
            self.assertEqual(len(records),2)
            self.assertTrue(all(r['profile_path']==r'C:\Users\alice' for r in records))
            self.assertTrue(all(r['application']=='Блокнот (64-bit)' for r in records))
            self.assertEqual(d.execute("select record_count from sources where name='automatic_destinations'").fetchone()[0],2)
            self.assertEqual(d.execute("select status from sources where name='custom_destinations'").fetchone()[0],'failed')
            evidence=json.loads(d.execute("select evidence_json from findings where source='jumplist_profile'").fetchone()[0])
            self.assertEqual(evidence['unique_records'],1)
            index_project(d,root)
            self.assertEqual(d.execute("select count(*) from decoded where decoder='recent'").fetchone()[0],2)
            d.close()

    def test_collector_only_collects_destinations(self):
        text=(Path(__file__).resolve().parents[2]/'tools/portable.ps1').read_text(encoding='utf-8-sig')
        block=text.split('function Collect-RecentFiles',1)[1].split('function Collect-RecentRegistry',1)[0]
        self.assertNotIn("label='recent'",block)
        self.assertIn("filter='*.automaticDestinations-ms'",block)
        self.assertIn("filter='*.customDestinations-ms'",block)
        specs=text.split('function Get-PortableRecentSpecs',1)[1].split('function Test-PortableDeadline',1)[0]
        self.assertNotIn('recent_registry',specs)

if __name__=='__main__':unittest.main()
