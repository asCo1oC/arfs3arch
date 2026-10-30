"""Нормализация ACE без попытки вычислить эффективный доступ или attack path."""
import base64
import json
import re
import uuid

from .ad import decode_sid_bytes, normalize_record

ZERO_GUID = '00000000-0000-0000-0000-000000000000'
AD_GUID_MAP = {
    ZERO_GUID: 'Без ограничения по типу (права задаёт маска ACE)',
    '00299570-246d-11d0-a768-00aa006e0529': 'User-Force-Change-Password',
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All',
    '89e95b76-444d-4c62-991a-0facbeda640c': 'DS-Replication-Get-Changes-In-Filtered-Set',
    'bf9679c0-0de6-11d0-a285-00aa003049e2': 'Атрибут: member',
    'f30e3bc1-9ff0-11d1-b603-0000f80367c1': 'Атрибут: gPCFileSysPath',
    '5b47d60f-6090-40b2-9f37-2a4de88f3063': 'Атрибут: msDS-KeyCredentialLink',
    'f3a64788-5306-11d1-a9c5-0000f80367c1': 'Validated-SPN',
    'edacfd8f-ffb3-11d1-b41d-00a0c968f939': 'Apply-Group-Policy (применение, не изменение GPO)',
}
WELL_KNOWN = {
    'S-1-1-0':'Everyone', 'S-1-5-11':'Authenticated Users',
    'S-1-5-18':'NT AUTHORITY\\SYSTEM', 'S-1-5-19':'NT AUTHORITY\\LOCAL SERVICE',
    'S-1-5-20':'NT AUTHORITY\\NETWORK SERVICE',
    'S-1-5-32-544':'BUILTIN\\Administrators', 'S-1-5-32-545':'BUILTIN\\Users',
    'S-1-3-0':'CREATOR OWNER', 'S-1-3-1':'CREATOR GROUP', 'S-1-5-10':'SELF'
}
DOMAIN_RIDS = {512:'Domain Admins',513:'Domain Users',514:'Domain Guests',515:'Domain Computers',516:'Domain Controllers',518:'Schema Admins',519:'Enterprise Admins',520:'Group Policy Creator Owners',521:'Read-only Domain Controllers',525:'Protected Users'}
BASELINE = {'S-1-5-18','S-1-5-32-544','S-1-3-0'}
RIGHTS = [(1,'CreateChild'),(2,'DeleteChild'),(4,'ListChildren'),(8,'Self'),(16,'ReadProperty'),(32,'WriteProperty'),(64,'DeleteTree'),(128,'ListObject'),(256,'ExtendedRight'),(65536,'Delete'),(131072,'ReadControl'),(262144,'WriteDacl'),(524288,'WriteOwner'),(1048576,'Synchronize')]


def sid(value):
    if isinstance(value, list): value = value[0] if value else None
    if isinstance(value, str) and re.fullmatch(r'S-\d+(?:-\d+)+', value, re.I): return value.upper()
    if isinstance(value, dict): value = value.get('value') if value.get('encoding') == 'base64' else None
    if isinstance(value, str):
        try: return decode_sid_bytes(base64.b64decode(value, validate=True))
        except (ValueError, TypeError): pass
    return None


def guid(value):
    if isinstance(value, dict):
        try: return str(uuid.UUID(bytes_le=base64.b64decode(value['value'], validate=True)))
        except (KeyError, ValueError, TypeError): return None
    try: return str(uuid.UUID(str(value)))
    except (ValueError, TypeError): return None


def domain_of_dn(dn):
    return '.'.join(re.findall(r'(?:^|,)DC=([^,]+)', str(dn or ''), re.I))


def object_kind(classes):
    values = classes if isinstance(classes, list) else [classes]
    classes = {str(x).lower() for x in values}
    for value, kind in [('computer','computer'),('group','group'),('grouppolicycontainer','gpo'),('domaindns','domain'),('organizationalunit','ou'),('user','user')]:
        if value in classes: return kind
    return 'object'


def sid_map(db, pid):
    result = {s:{'name':n,'kind':'group' if s in {'S-1-1-0','S-1-5-11','S-1-5-32-544','S-1-5-32-545'} else 'principal','origin':'well_known'} for s,n in WELL_KNOWN.items()}
    domains = {}
    for row in db.execute('SELECT section,source,data_json FROM records WHERE project_id=?', (pid,)):
        item = json.loads(row['data_json'])
        if not isinstance(item, dict): continue
        entries = []
        if row['section'] == 'domain' and isinstance(item.get('attributes'), dict):
            norm = normalize_record(row['source'], item); attrs = norm.get('attributes') or {}
            entries.append((norm.get('sid') or sid(attrs.get('objectsid')), norm.get('name'), object_kind(attrs.get('objectclass', [])), norm.get('distinguished_name')))
        elif row['section'] == 'permissions' and row['source'] == 'domain_acl':
            entries.append((sid(item.get('object_sid')), item.get('name'), object_kind(item.get('object_class', [])), item.get('distinguished_name')))
        elif row['section'] == 'identity':
            entries.append((sid(item.get('sid')), item.get('name') or item.get('path'), 'user', None))
            entries.extend((sid(g.get('sid')), g.get('name'), 'group', None) for g in item.get('groups', []) if isinstance(g, dict))
        for subject_sid, name, kind, dn in entries:
            if not subject_sid: continue
            if dn and re.fullmatch(r'S-1-5-21-\d+-\d+-\d+-\d+', subject_sid): domains[subject_sid.rsplit('-', 1)[0]] = domain_of_dn(dn)
            if name:
                qualified = f'{domain_of_dn(dn)}\\{name}' if dn and '\\' not in name and not str(name).upper().startswith('CN=') else str(name)
                if subject_sid not in result or dn or result[subject_sid].get('origin') == 'profile':
                    origin = 'directory' if dn else 'profile' if row['source'] == 'profiles' else 'identity'
                    result[subject_sid] = {'name':qualified,'kind':kind,'dn':dn,'origin':origin}
    for prefix, domain in domains.items():
        for rid, name in DOMAIN_RIDS.items():
            result.setdefault(f'{prefix}-{rid}', {'name':f'{domain}\\{name}','kind':'group','origin':'known_domain_rid'})
    return result, domains


def classify_ace(trustee, target_sid, mask, object_type, access, inherit_only, baseline):
    """Conservative triage of observed ACE, never an effective-access decision."""
    if mask is None or not trustee or not object_type:
        return 'unknown', 'Недостаточно данных для классификации', 'info'
    if access == 'Deny': return 'deny', 'Запрещающая ACE; учитывается при ручной проверке доступа', 'info'
    if access != 'Allow': return 'unknown', 'Неизвестный тип ACE; требуется ручная проверка', 'info'
    if inherit_only: return 'inherit_only', 'Действует только на наследников; на текущий объект не применяется', 'info'
    if baseline: return 'baseline', 'Ожидаемый административный субъект; запись сохранена', 'info'
    control = bool(mask & (0x10000000 | 0x40000000 | 0x40000 | 0x80000))
    # Change-password and SELF-specific maintenance rights differ from password reset.
    if not control and object_type == 'ab721a53-1e2f-11d0-9819-00aa0040529b' and mask & ~(256|16|131072) == 0:
        return 'baseline', 'Смена собственного пароля (не сброс чужого пароля)', 'info'
    self_properties = {'91e647de-d96f-4b70-9557-d63ff4f3ccd8','9b026da6-0d3c-465c-8bee-5199d7165cba','ea1b7b93-5e48-46d5-bc6c-4df4fda78a35','3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'}
    self_properties.update({'77b5b886-944a-11d1-aebd-0000f80367c1','e45795b2-9455-11d1-aebd-0000f80367c1','e45795b3-9455-11d1-aebd-0000f80367c1'})
    if trustee == 'S-1-5-10' and mask & ~(16|32|131072) == 0 and object_type in self_properties:
        return 'baseline', 'Ограниченное обслуживание собственных атрибутов (SELF)', 'info'
    if trustee == 'S-1-5-10' and mask == 256 and object_type in {'ab721a54-1e2f-11d0-9819-00aa0040529b','ab721a56-1e2f-11d0-9819-00aa0040529b'}:
        return 'baseline', 'Штатное специальное право SELF', 'info'
    if control:
        return 'interesting', 'Контроль объекта или изменение его ACL/владельца вне базовых администраторов', 'high'
    if mask & (32|256|8|1|2|64|65536):
        return 'interesting', 'Делегировано изменение атрибутов, специальное право или управление объектами; проверить назначение', 'medium'
    return 'read_only', 'Разрешения чтения и просмотра', 'info'


def decode_acl(record, resolution, domains, record_id=None):
    target_sid = sid(record.get('object_sid')); target_guid = guid(record.get('object_guid'))
    target_kind = object_kind(record.get('object_class', []))
    common = {'target_name':record.get('name') or record.get('distinguished_name'), 'target_dn':record.get('distinguished_name'),
              'target_sid':target_sid, 'target_guid':target_guid, 'target_kind':target_kind, 'owner_sid':record.get('owner_sid'),
              'record_id':record_id, 'effective_access_evaluated':False}
    if record.get('descriptor_status') in {'missing','decode_failed'}:
        return [dict(common, kind='ad_acl_unavailable', is_notable_lead=False, factual_note='Дескриптор не получен или не разобран; отсутствие ACE не означает отсутствие ограничений.', decode_status=record['descriptor_status'])]
    result = []
    for index, ace in enumerate(record.get('aces') or []):
        if not isinstance(ace, dict): continue
        trustee = sid(ace.get('trustee_sid')); principal = resolution.get(trustee, {})
        try: mask = int(ace.get('rights_raw')) & 0xffffffff
        except (ValueError, TypeError): mask = None
        parts = []
        if mask is not None:
            if mask & 0x10000000 or mask & 983551 == 983551: parts.append('GenericAll')
            elif mask & 0x40000000 or mask & 131112 == 131112: parts.append('GenericWrite')
            parts.extend(name for flag, name in RIGHTS if mask & flag)
        right = ', '.join(parts) or 'Маска не распознана'
        object_type = guid(ace.get('object_type'))
        prop = AD_GUID_MAP.get(object_type, object_type or 'GUID отсутствует/некорректен')
        access = ace.get('access_type')
        baseline = trustee in BASELINE or any(trustee == f'{prefix}-{rid}' for prefix in domains for rid in (512,518,519))
        try: inherit_only = bool(int(ace.get('propagation_flags', 0)) & 2)
        except (TypeError, ValueError): inherit_only = False
        classification, reason, priority = classify_ace(trustee, target_sid, mask, object_type, access, inherit_only, baseline)
        if classification == 'interesting':
            if target_kind == 'gpo' and mask == 256 and object_type == 'edacfd8f-ffb3-11d1-b41d-00a0c968f939':
                classification, reason, priority = 'baseline', 'Применение GPO, не право редактирования политики', 'info'
            if target_kind == 'domain' and trustee == 'S-1-5-11' and mask == 256 and object_type in {'05c74c5e-4deb-43b4-bd9f-86664c2a7fd5','ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501','280f369c-67c7-438e-ae98-1d46f3c6f541'}:
                classification, reason, priority = 'baseline', 'Соответствует стандартной ACE Authenticated Users класса domainDNS', 'info'
            if target_kind == 'group' and trustee == 'S-1-5-11' and mask == 256 and object_type == 'ab721a55-1e2f-11d0-9819-00aa0040529b':
                classification, reason, priority = 'baseline', 'Send-To для группы: соответствует стандартному дескриптору класса group', 'info'
            expected_property = (
                (object_type == '5b47d60f-6090-40b2-9f37-2a4de88f3063' and any(trustee == f'{p}-{r}' for p in domains for r in (526,527))) or
                (object_type == 'bf967a7f-0de6-11d0-a285-00aa003049e2' and any(trustee == f'{p}-517' for p in domains)) or
                (trustee == 'S-1-5-32-561' and object_type in {'6db69a1c-9422-11d1-aebd-0000f80367c1','5805bc62-bdc9-4428-a5e2-856a0f4c185e'})
            )
            if expected_property and mask is not None and mask & ~(16|32|131072) == 0:
                classification, reason, priority = 'expected_role', 'Профильное разрешение встроенной роли; проверить членство, не считать нестандартной делегацией', 'info'
        notable = classification == 'interesting'
        note = f'ACE {access}: {principal.get("name") or trustee or "неизвестный SID"} → {common["target_name"]}; {right}; {prop}. Эффективный доступ не вычислялся.'
        if inherit_only: note += ' ACE предназначена только для наследования.'
        if object_type in {'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'}: note += ' Отдельная ACE не подтверждает возможность DCSync.'
        result.append(dict(common, kind=f'ad_{target_kind}_ace', ace_index=index, trustee_sid=trustee,
                           trustee_name=principal.get('name') or trustee or 'SID не распознан', trustee_kind=principal.get('kind','principal'),
                           access_type=access, rights_raw=mask, rights_summary=right, target_property=prop, object_type=object_type,
                           is_inherited=bool(ace.get('is_inherited')), is_notable_lead=notable, is_common_admin_principal=baseline,
                           classification=classification, interest_reason=reason, review_priority=priority,
                           factual_note=note, inherited_object_type=ace.get('inherited_object_type'), inheritance_type=ace.get('inheritance_type'),
                           propagation_flags=ace.get('propagation_flags'), object_flags=ace.get('object_flags'), raw_ace=ace))
    return result


def index_acl(db, pid):
    resolution, domains = sid_map(db, pid)
    token_sids = set()
    for token_row in db.execute("SELECT data_json FROM records WHERE project_id=? AND section='identity' AND source='token'", (pid,)):
        token = json.loads(token_row['data_json'])
        token_sids.add(sid(token.get('sid')))
        for group in token.get('groups', []):
            attributes = str(group.get('attributes_raw') or '').lower()
            if 'enabled group' in attributes and 'deny only' not in attributes:
                token_sids.add(sid(group.get('sid')))
    token_sids.discard(None)
    db.execute("DELETE FROM decoded WHERE project_id=? AND decoder='ad_acl'", (pid,))
    rows = db.execute("SELECT id,data_json FROM records WHERE project_id=? AND section='permissions' AND source='domain_acl'", (pid,)).fetchall()
    for row in rows:
        record = json.loads(row['data_json'])
        if not isinstance(record, dict): continue
        for item in decode_acl(record, resolution, domains, row['id']):
            item['matches_current_token'] = item.get('trustee_sid') in token_sids
            if item.get('classification') == 'expected_role' and item['matches_current_token']:
                item.update(is_notable_lead=True, review_priority='medium', interest_reason='Профильное право встроенной роли присутствует у текущего токена; проверить применимость')
            db.execute("INSERT INTO decoded(project_id,decoder,source,data_json) VALUES(?,'ad_acl','domain_acl',?)", (pid, json.dumps(item, ensure_ascii=False)))
