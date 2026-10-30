"""Единый граф проекта: только связи, подтверждённые исходными записями."""
import hashlib
import json
import ntpath
import re
from pathlib import Path
import xml.etree.ElementTree as ET

from .decoders.ad import normalize_record
from .decoders.ad_acl import sid, sid_map, object_kind, domain_of_dn

LAYERS = {'files','network','acl','domain','identity','logs','configs','browser'}


def canonical_path(value):
    return ntpath.normpath(str(value or '').replace('/', '\\')).casefold()


def executable(value):
    match = re.match(r'^\s*(?:"([^\"]+\.exe)"|(.+?\.exe))(?:\s|$)', str(value or ''), re.I)
    return (match.group(1) or match.group(2)) if match else None


class ProjectGraph:
    def __init__(self, db, pid):
        self.db, self.pid = db, pid
        self.nodes, self.edges, self.aliases, self.dns = {}, {}, {}, {}
        self.resolution, self.domains = sid_map(db, pid)
        project = db.execute('SELECT * FROM projects WHERE id=?', (pid,)).fetchone()
        if project is None: raise ValueError('Проект не найден')
        self.host_name = project['hostname'] or project['name']
        self.host = self.node('computer', 'host:'+self.host_name, self.host_name, {'hostname':self.host_name}, section='identity')
        self.records = []
        for row in db.execute('SELECT id,section,source,data_json FROM records WHERE project_id=? ORDER BY id', (pid,)):
            self.records.append((json.loads(row['data_json']), {'record_id':row['id'],'section':row['section'],'source':row['source']}))
        self.profiles = []
        self._seed_principals(); self._domain(); self._identity(); self._services_network(); self._files(); self._acl(); self._source_context()

    def node(self, kind, key, label, properties=None, ref=None, section=None):
        ident = kind+':'+hashlib.sha256(str(key).casefold().encode()).hexdigest()[:20]
        if ident not in self.nodes:
            self.nodes[ident] = {'id':ident,'kind':kind,'label':str(label or key),'sublabel':'','properties':{},'evidence':[],'sections':[],'collected_files':[],'leads':[]}
        node = self.nodes[ident]
        for name, value in (properties or {}).items():
            if value is not None and value not in node['properties'].setdefault(name, []): node['properties'][name].append(value)
        if ref and ref not in node['evidence']: node['evidence'].append(ref)
        section = section or (ref or {}).get('section')
        if section and section not in node['sections']: node['sections'].append(section)
        return ident

    def attach(self, ident, ref, properties=None):
        node = self.nodes[ident]
        if ref not in node['evidence']: node['evidence'].append(ref)
        if ref.get('section') and ref['section'] not in node['sections']: node['sections'].append(ref['section'])
        for name, value in (properties or {}).items():
            if value is not None and value not in node['properties'].setdefault(name, []): node['properties'][name].append(value)

    def link(self, source, target, label, ref, layer, tentative=False, detail=None):
        if not source or not target: return
        key = (source, target, label, layer, tentative)
        if key not in self.edges:
            self.edges[key] = {'id':hashlib.sha256(repr(key).encode()).hexdigest()[:20], 'source':source, 'target':target,
                               'label':label, 'layer':layer, 'tentative':tentative, 'evidence':[], 'properties':[]}
        edge = self.edges[key]
        if ref and ref not in edge['evidence']: edge['evidence'].append(ref)
        if detail and detail not in edge['properties']: edge['properties'].append(detail)

    def principal(self, subject_sid=None, name=None, dn=None, kind='principal', ref=None, scope=None):
        subject_sid = sid(subject_sid); qualified = str(name or '')
        if qualified.startswith('.\\'): qualified = self.host_name+qualified[1:]
        local = {'localsystem':'S-1-5-18','nt authority\\system':'S-1-5-18','nt authority\\localservice':'S-1-5-19','nt authority\\networkservice':'S-1-5-20'}
        subject_sid = subject_sid or local.get(qualified.casefold())
        if not subject_sid and dn and dn.casefold() in self.dns:
            ident = self.dns[dn.casefold()]
        elif not subject_sid and qualified.casefold() in self.aliases and len(self.aliases[qualified.casefold()]) == 1:
            ident = next(iter(self.aliases[qualified.casefold()]))
        else:
            resolved = self.resolution.get(subject_sid, {})
            kind = resolved.get('kind') or kind
            if kind not in {'user','group','computer','gpo','ou','domain'}: kind = 'principal'
            key = ('sid:'+subject_sid) if subject_sid else ('dn:'+dn.casefold()) if dn else ('name:'+qualified.casefold()) if '\\' in qualified else f'unresolved:{scope}:{qualified}'
            ident = self.node('principal', key, resolved.get('name') or qualified or dn or subject_sid, {'sid':subject_sid,'dn':dn,'principal_kind':kind}, ref)
            self.nodes[ident]['kind'] = kind; self.nodes[ident]['sublabel'] = subject_sid or dn or 'Имя без подтверждённого SID'
        if ref: self.attach(ident, ref, {'sid':subject_sid,'dn':dn})
        if dn: self.dns[dn.casefold()] = ident
        if '\\' in qualified: self.aliases.setdefault(qualified.casefold(), set()).add(ident)
        return ident

    def _seed_principals(self):
        for item, ref in self.records:
            if not isinstance(item, dict): continue
            if ref['section'] == 'domain' and isinstance(item.get('attributes'), dict):
                record = normalize_record(ref['source'], item); attrs = record.get('attributes') or {}; dn = record.get('distinguished_name')
                name = record.get('name'); subject_sid = record.get('sid') or sid(attrs.get('objectsid')); kind = object_kind(attrs.get('objectclass', []))
                if kind == 'object': kind = {'all_users':'user','groups':'group','computers':'computer','spn_accounts':'user','gpo_list':'gpo'}.get(ref['source'], 'principal')
                qualified = f'{domain_of_dn(dn)}\\{name}' if dn and name and '\\' not in name else name
                ident = self.principal(subject_sid, qualified, dn, kind, ref); self.attach(ident, ref, {'attributes':attrs})
            elif ref['section'] == 'permissions' and ref['source'] == 'domain_acl':
                dn = item.get('distinguished_name'); name = item.get('name')
                self.principal(item.get('object_sid'), f'{domain_of_dn(dn)}\\{name}' if dn and name else name, dn, object_kind(item.get('object_class', [])), ref)
            elif ref['section'] == 'identity' and ref['source'] in {'token','profiles'}:
                if not item.get('sid'): continue
                ident = self.principal(item.get('sid'), item.get('name'), kind='user', ref=ref)
                if ref['source'] == 'profiles' and item.get('path'): self.profiles.append((canonical_path(item['path']), ident))
                for group in item.get('groups', []):
                    if isinstance(group, dict): self.principal(group.get('sid'), group.get('name'), kind='group', ref=ref)
        membership = next((x.get('data') for x,r in self.records if r['section']=='domain' and isinstance(x,dict) and x.get('kind')=='computer_system'), None)
        if isinstance(membership, dict) and membership.get('PartOfDomain'):
            fqdn = (str(membership.get('Name'))+'.'+str(membership.get('Domain'))).casefold(); matches = []
            for node in self.nodes.values():
                for attrs in node['properties'].get('attributes', []):
                    if not isinstance(attrs, dict): continue
                    values = attrs.get('dnshostname') or []
                    if isinstance(values, str): values = [values]
                    if fqdn in [str(value).casefold() for value in values]: matches.append(node['id'])
            if len(set(matches)) == 1:
                old = self.host; self.host = matches[0]; self.nodes[self.host]['properties']['hostname'] = [self.host_name]
                if old != self.host: del self.nodes[old]

    def _domain(self):
        for item, ref in self.records:
            if ref['section'] != 'domain' or not isinstance(item, dict) or 'attributes' not in item: continue
            record = normalize_record(ref['source'], item); attrs = record.get('attributes') or {}; dn = record.get('distinguished_name')
            if not dn: continue
            obj = self.dns.get(dn.casefold())
            for field, reverse in [('memberof',False),('member',True)]:
                values = attrs.get(field) or []; values = values if isinstance(values, list) else [values]
                for value in values:
                    if not isinstance(value, str): continue
                    other = self.principal(dn=value, kind='group' if not reverse else 'principal', ref=ref)
                    self.link(other if reverse else obj, obj if reverse else other, 'Входит в группу', ref, 'domain')
            for field, label in [('serviceprincipalname','Зарегистрирован SPN'),('msds-allowedtodelegateto','Разрешена делегация к SPN')]:
                values = attrs.get(field) or []; values = values if isinstance(values, list) else [values]
                for value in values:
                    other = self.node('spn', value, value, ref=ref); self.link(obj, other, label, ref, 'domain')

    def _identity(self):
        for item, ref in self.records:
            if ref['section'] != 'identity' or ref['source'] != 'token' or not isinstance(item, dict): continue
            user = self.principal(item.get('sid'), item.get('name'), ref=ref); self.link(user, self.host, 'Контекст процесса сбора', ref, 'identity')
            for group in item.get('groups', []):
                if not isinstance(group, dict): continue
                target = self.principal(group.get('sid'), group.get('name'), kind='group', ref=ref)
                self.link(user, target, 'Группа присутствует в токене', ref, 'identity', detail={'attributes_raw':group.get('attributes_raw')})
            for privilege in item.get('privileges', []):
                self.nodes[user]['leads'].append({'kind':'token_privilege','text':f"{privilege.get('name')}: {privilege.get('state_raw')}",'evidence':[ref],'data':privilege})

    def _services_network(self):
        processes, services, display = {}, {}, {}
        for item, ref in self.records:
            if ref['section']=='network' and ref['source']=='processes' and isinstance(item,dict) and item.get('pid') is not None:
                pid=str(item['pid']); ident=self.node('process',pid,item.get('name') or f'PID {pid}',item,ref); self.nodes[ident]['sublabel']='PID '+pid
                processes[pid]=(ident,item); self.link(self.host,ident,'Процесс в снимке',ref,'network')
                if item.get('path'): self.link(ident,self.file(item['path'],ref),'Исполняемый файл',ref,'files')
        for item, ref in self.records:
            if ref['section']=='logs' and ref['source']=='services_state' and isinstance(item,dict) and item.get('Name'):
                name=item['Name']; ident=self.node('service',name,name,item,ref); services[name.casefold()]=ident
                if item.get('DisplayName'): display.setdefault(item['DisplayName'].casefold(),set()).add(ident)
                self.nodes[ident]['sublabel']=item.get('StartName') or ''; self.link(self.host,ident,'Служба зарегистрирована',ref,'logs')
                if item.get('StartName'): self.link(ident,self.principal(name=item['StartName'],ref=ref,scope=ident),'Запускается от имени',ref,'logs')
                exe=executable(item.get('PathName'))
                if exe: self.link(ident,self.file(exe,ref),'Путь исполняемого файла',ref,'files')
                for pid,(process,data) in processes.items():
                    exact=item.get('ProcessId') not in (None,0) and str(item['ProcessId'])==pid
                    path_match=exe and data.get('path') and canonical_path(exe)==canonical_path(data['path']) and ntpath.basename(exe).lower() not in {'svchost.exe','dllhost.exe'} and str(item.get('State')).lower()=='running'
                    if exact or path_match: self.link(ident,process,'PID службы совпадает' if exact else 'Совпадает EXE; связь не подтверждена',ref,'network',not exact)
        for item, ref in self.records:
            if ref['section']=='network' and ref['source'] in {'tcp','udp'} and isinstance(item,dict):
                pid=str(item.get('pid')); proto=ref['source'].upper()
                if pid not in processes: continue
                label=f"{proto} {item.get('local_address')}:{item.get('local_port')}"
                if proto=='TCP' and str(item.get('state')).lower()!='listen': label+=f" → {item.get('remote_address')}:{item.get('remote_port')}"
                endpoint=self.node('port',(pid,label),label,item,ref); self.nodes[endpoint]['sublabel']=str(item.get('state') or 'UDP')
                self.link(processes[pid][0],endpoint,'Сокет процесса по PID',ref,'network')
            if ref['section']=='logs' and ref['source']=='service_events' and isinstance(item,str) and len(item)<2_000_000:
                try: xml=ET.fromstring(item)
                except ET.ParseError: continue
                values={element.attrib.get('Name'):element.text for element in xml.findall('.//{*}EventData/{*}Data')}; key=str(values.get('ServiceName') or '').casefold()
                service=services.get(key)
                if not service and len(display.get(key,set()))==1: service=next(iter(display[key]))
                if service:
                    event=self.node('event',ref['record_id'],'Событие '+xml.findtext('.//{*}EventID','?'),values,ref); self.link(service,event,'Имя службы в событии',ref,'logs')
            if ref['section']=='permissions' and ref['source']=='service_acl' and isinstance(item,dict):
                service=services.get(str(item.get('service')).casefold())
                if service: self.attach(service,ref,{'service_acl_raw':item.get('raw')})

    def file(self, path, ref=None):
        ident=self.node('file',canonical_path(path),ntpath.basename(path) or path,{'path':path},ref); self.nodes[ident]['sublabel']=str(path); return ident

    def _files(self):
        root=Path(self.db.execute('SELECT path FROM projects WHERE id=?',(self.pid,)).fetchone()[0]).resolve()
        for row in self.db.execute('SELECT * FROM artifacts WHERE project_id=?',(self.pid,)):
            item=dict(row); ref={'section':item['section'],'source':item['source'],'artifact_id':item['id']}
            file_node=self.file(item['original_path'] or item['name'] or f"artifact:{item['id']}",ref); copied=False; path=Path(item['local_path'] or '')
            try: path.resolve().relative_to(root); copied=path.is_file()
            except ValueError: pass
            artifact={name:item[name] for name in ('id','name','original_path','section','source','length','sha256')}; artifact['available']=copied
            self.attach(file_node,ref,{'artifact':artifact}); owner=None
            if item.get('profile_sid'): owner=self.principal(item['profile_sid'],ref=ref)
            elif item.get('profile_path'):
                matches={node for profile,node in self.profiles if profile==canonical_path(item['profile_path'])}
                if len(matches)==1: owner=next(iter(matches))
            if not owner and item.get('original_path'):
                path_key=canonical_path(item['original_path']); matches=[(profile,node) for profile,node in self.profiles if path_key.startswith(profile.rstrip('\\')+'\\')]
                if matches:
                    longest=max(len(profile) for profile,node in matches); owners={node for profile,node in matches if len(profile)==longest}
                    if len(owners)==1: owner=next(iter(owners))
            context=owner or self.host; self.link(context,file_node,'Файл в профиле (не доказательство владельца)' if owner else 'Файл собран на узле',ref,'files')
            if copied:
                self.nodes[file_node]['collected_files'].append(artifact); self.nodes[context]['collected_files'].append(artifact)
                if item['source']=='powershell_history':
                    with path.open('rb') as handle: raw=handle.read(524289)
                    text=raw[:524288].decode('utf-8-sig',errors='replace'); lines=text.splitlines()
                    lead={'kind':'powershell_history','text':f'Сохранена история PowerShell: {len(lines)} строк в просмотренном фрагменте; выполнение команд не подтверждено.','commands':lines[:100],'truncated':len(raw)>524288 or len(lines)>100,'evidence':[ref]}
                    self.nodes[context]['leads'].append(lead); self.nodes[file_node]['leads'].append(lead)
        for edge in list(self.edges.values()):
            if edge['layer']=='files' and self.nodes[edge['target']]['kind']=='file':
                for artifact in self.nodes[edge['target']]['collected_files']:
                    if artifact not in self.nodes[edge['source']]['collected_files']: self.nodes[edge['source']]['collected_files'].append(artifact)

    def _acl(self):
        rows=self.db.execute("SELECT id,data_json FROM decoded WHERE project_id=? AND decoder='ad_acl'",(self.pid,))
        for row in rows:
            ace=json.loads(row['data_json']); ref={'section':'permissions','source':'domain_acl','decoded_id':row['id'],'record_id':ace.get('record_id'),'ace_index':ace.get('ace_index')}
            target=self.principal(ace.get('target_sid'),ace.get('target_name'),ace.get('target_dn'),ace.get('target_kind','principal'),ref)
            if not ace.get('trustee_sid'): continue
            trustee=self.principal(ace['trustee_sid'],ace.get('trustee_name'),kind=ace.get('trustee_kind','principal'),ref=ref)
            self.link(trustee,target,f"ACE {ace.get('access_type')}: {ace.get('rights_summary')}",ref,'acl',detail={name:ace.get(name) for name in ('object_type','target_property','is_inherited','propagation_flags','inherited_object_type','factual_note')})
            if ace.get('is_notable_lead'):
                lead={'kind':'ad_acl','text':ace['factual_note'],'evidence':[ref]}; self.nodes[target]['leads'].append(lead); self.nodes[trustee]['leads'].append(lead)
        for item, ref in self.records:
            if ref['section']=='permissions' and ref['source']=='file_acl' and isinstance(item,dict) and item.get('path'):
                file_node=self.file(item['path'],ref); self.attach(file_node,ref,{'file_acl':item})
                for ace in item.get('access') or []:
                    if not isinstance(ace,dict) or not ace.get('identity'): continue
                    principal=self.principal(ace['identity'],ace['identity'],ref=ref,scope=file_node)
                    self.link(principal,file_node,f"Файловая ACE {ace.get('type')}: {ace.get('rights')}",ref,'acl',detail=ace)

    def _source_context(self):
        for item, ref in self.records:
            if not isinstance(item,dict) or ref['section']=='recent': continue
            if item.get('profile_sid'): self.attach(self.principal(item['profile_sid'],ref=ref),ref)
            elif ref['section']=='configs' and not item.get('saved_path'): self.attach(self.host,ref)
        rows=self.db.execute("SELECT id,decoder,source,data_json FROM decoded WHERE project_id=? AND decoder IN ('browser','userassist')",(self.pid,))
        for row in rows:
            item=json.loads(row['data_json']); ref={'decoded_id':row['id'],'section':'browser' if row['decoder']=='browser' else 'logs','source':row['source']}; owner=None
            if item.get('profile_sid'): owner=self.principal(item['profile_sid'],ref=ref)
            elif item.get('profile_path'):
                matches={node for profile,node in self.profiles if profile==canonical_path(item['profile_path'])}
                if len(matches)==1: owner=next(iter(matches))
            if owner: self.attach(owner,ref)

    def view(self, section='all', focus=None, layers=None, limit=18, offset=0, q=''):
        layers=set(layers if layers is not None else LAYERS)
        if not layers <= LAYERS: raise ValueError('Неизвестный слой графа')
        candidates=[node for node in self.nodes.values() if (section=='all' or section in node['sections']) and (not q or q.casefold() in (node['label']+' '+node['sublabel']).casefold())]
        candidates.sort(key=lambda node:(node['kind'] in {'file','port','event'},node['label'].casefold(),node['id']))
        result={'candidates':[{name:node[name] for name in ('id','label','kind','sublabel')} for node in candidates[:200]],'candidate_count':len(candidates),'nodes':[],'edges':[],
                'total_nodes':len(self.nodes),'total_edges':len(self.edges),'focus':focus,'omitted':0,'offset':max(0,int(offset)),
                'note':'Единый граф проекта. Связи отражают собранные факты, а не эффективный доступ. Пунктир — неподтверждённое сопоставление.','layers':sorted(layers)}
        if not focus: return result
        if focus not in self.nodes: raise ValueError('Объект отсутствует в проекте')
        adjacent=[edge for edge in self.edges.values() if focus in (edge['source'],edge['target']) and edge['layer'] in layers]
        neighbours={edge['target'] if edge['source']==focus else edge['source'] for edge in adjacent}-{focus}
        neighbours=sorted(neighbours,key=lambda ident:(self.nodes[ident]['kind'] in {'file','port'},self.nodes[ident]['label'].casefold(),ident))
        limit=max(2,min(int(limit),24)); offset=max(0,int(offset)); selected=neighbours[offset:offset+limit-1]; ids={focus,*selected}
        result.update(nodes=[self.nodes[ident] for ident in [focus,*selected]],edges=[edge for edge in adjacent if edge['source'] in ids and edge['target'] in ids],
                      omitted=max(0,len(neighbours)-len(selected)),total_neighbours=len(neighbours),limit=limit)
        return result
