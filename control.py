"""Constrained human-approval queue. No proposal means no firewall action."""
import datetime,hashlib,hmac,ipaddress,json,os,secrets,subprocess,threading,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parent
QUEUE=ROOT/'data'/'proposals';QUEUE.mkdir(exist_ok=True)
PRIVATE=ROOT.parents[1]/'work'/'firewall-control';PRIVATE.mkdir(parents=True,exist_ok=True)
TOKEN=secrets.token_urlsafe(32);LOCK=threading.RLock()
REVIEWERS={'investigator','dependency','challenger'}
REVIEW_TASKS={'investigator':'/root/exception_investigator','dependency':'/root/dependency_analyst','challenger':'/root/independent_challenger'}
REVIEW_LEDGER=PRIVATE/'review-ledger';REVIEW_LEDGER.mkdir(exist_ok=True)
KEY_FILE=PRIVATE/'review-key'
if not KEY_FILE.exists():
 try:
  with KEY_FILE.open('xb') as f:f.write(secrets.token_bytes(32))
 except FileExistsError:pass
REVIEW_KEY=KEY_FILE.read_bytes()
def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def write(p,obj):
 t=p.with_suffix('.tmp');t.write_text(json.dumps(obj,indent=2),encoding='utf-8');t.replace(p)
def digest(p):return hashlib.sha256(json.dumps({k:p[k] for k in ('id','action','evidenceFingerprint','reason','impact','validation')},sort_keys=True,separators=(',',':')).encode()).hexdigest()
def review_signature(r):return hmac.new(REVIEW_KEY,json.dumps({k:v for k,v in r.items() if k!='signature'},sort_keys=True,separators=(',',':')).encode(),hashlib.sha256).hexdigest()
def record_review(proposal,agent,verdict,summary,task_ref):
 """Coordinator-only local call after receiving an actual specialist review; no HTTP route."""
 if agent not in REVIEWERS or task_ref!=REVIEW_TASKS[agent] or verdict not in ('approve','hold','reject') or not summary.strip():raise ValueError('Actual specialist provenance required')
 r={'agent':agent,'verdict':verdict,'summary':summary,'taskRef':task_ref,'proposalDigest':digest(proposal),'recordedAt':stamp()};r['signature']=review_signature(r)
 write(REVIEW_LEDGER/(proposal['id']+'-'+agent+'.json'),r)
def trusted_reviews(p):
 result=[]
 for agent in sorted(REVIEWERS):
  path=REVIEW_LEDGER/(str(uuid.UUID(p['id']))+'-'+agent+'.json')
  if path.exists():
   r=read(path)
   if r.get('agent')==agent and r.get('taskRef')==REVIEW_TASKS[agent] and hmac.compare_digest(r.get('signature',''),review_signature(r)):result.append(r)
 return result
def validate_action(a,require_file=True):
 if set(a)!={'direction','program','protocol','localPort','remoteIP','profile'}:raise ValueError('Unexpected action fields')
 if a['direction']!='Inbound' or a['protocol'] not in ('TCP','UDP') or a['profile'] not in ('Public','Private','Domain'):raise ValueError('Only one inbound TCP/UDP profile is supported')
 if type(a['localPort']) is not int or not 1<=a['localPort']<=65535:raise ValueError('One integer local port is required')
 ip=ipaddress.ip_address(a['remoteIP'])
 if str(ip)!=a['remoteIP'] or '%' in a['remoteIP'] or ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_reserved or str(ip)=='255.255.255.255':raise ValueError('One canonical unicast remote IP is required')
 p=Path(a['program'])
 if not p.is_absolute() or p.suffix.lower()!='.exe' or any(c in a['program'] for c in '*?%\r\n"') or str(p.resolve()).lower()!=str(p).lower():raise ValueError('An exact absolute .exe path without links or expansion is required')
 if require_file and not p.is_file():raise ValueError('Target executable is missing')
 return a
def validate_proposal(p,evidence):
 if str(uuid.UUID(p['id']))!=p['id']:raise ValueError('Invalid proposal identity')
 validate_action(p['action'])
 for field in ('reason','impact','validation'):
  if not isinstance(p.get(field),str) or not p[field].strip():raise ValueError('Proposal needs '+field)
 if p.get('evidenceFingerprint')!=evidence.get('fingerprint'):raise ValueError('Evidence changed; fresh agent review is required')
 if not any(r.get('Program','').lower()==p['action']['program'].lower() for r in evidence['rules']):raise ValueError('Executable is not in collected rule evidence')
 d=digest(p);reviews=trusted_reviews(p)
 if len(reviews)!=3 or {r.get('agent') for r in reviews}!=REVIEWERS:raise ValueError('All three specialist reviews are required')
 if any(r.get('verdict')!='approve' or r.get('proposalDigest')!=d or not r.get('summary') for r in reviews):raise ValueError('Each specialist must approve this exact proposal digest')
 return d
def records():
 p=PRIVATE/'records.json';return read(p) if p.exists() else {}
def reconcile():
 rec=records();changed=False
 for key,item in rec.items():
  if item.get('status') not in ('awaiting_windows','unknown'):continue
  result=PRIVATE/(item['runId']+'-result.json')
  if result.exists():
   try:
    r=read(result)
    if r.get('runId')!=item['runId']:continue
    item['result']=r;item['updatedAt']=stamp();item['status']=('blocked' if item['operation']=='block' else 'rolled_back') if r.get('verified') is True else 'failed';changed=True
   except (ValueError,OSError):pass
  elif (datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(item['updatedAt'])).total_seconds()>120 and item['status']!='unknown':
   item['status']='unknown';item['result']={'message':'No verified execution result. Do not assume the firewall changed.'};changed=True
 if changed:write(PRIVATE/'records.json',rec)
 return rec
def list_items(evidence):
 with LOCK:
  rec=reconcile();items=[]
  for path in sorted(QUEUE.glob('*.json')):
   try:
    p=read(path);p['digest']=digest(p);p['reviews']=[{k:v for k,v in r.items() if k!='signature'} for r in trusted_reviews(p)]
    try:validate_proposal(p,evidence);p['ready']=True;p['gate']='All specialist reviews complete'
    except (ValueError,KeyError,TypeError) as ex:p['ready']=False;p['gate']=str(ex)
    p['execution']=rec.get(p['id']);items.append(p)
   except (ValueError,KeyError,TypeError,OSError):continue
  for key,item in rec.items():
   if key not in {p['id'] for p in items}:
    p=dict(item['proposal']);p.update(digest=digest(p),ready=False,gate='Previously approved action',execution=item);items.append(p)
  return items
def approve(proposal_id,expected_digest,operation,evidence):
 with LOCK:
  if str(uuid.UUID(proposal_id))!=proposal_id:raise ValueError('Invalid proposal identity')
  rec=reconcile();existing=rec.get(proposal_id)
  if operation=='block':
   if existing:raise ValueError('This proposal was already consumed; it cannot be replayed')
   p=read(QUEUE/(proposal_id+'.json'));d=validate_proposal(p,evidence)
  elif operation=='rollback':
   if not existing or not (existing['status']=='blocked' or (existing['status']=='failed' and (existing.get('priorReceipt') or existing.get('result',{}).get('receipt')))):raise ValueError('Only a receipted Palis-created block can be rolled back')
   p=existing['proposal'];d=digest(p);validate_action(p['action'],require_file=False)
  else:raise ValueError('Unknown operation')
  if not secrets.compare_digest(d,expected_digest):raise ValueError('Proposal changed; reopen the approval')
  run_id=str(uuid.uuid4());rule_name='Palis-Block-'+proposal_id
  bundle={'runId':run_id,'ruleName':rule_name,'operation':operation,'action':p['action'],'expiresAt':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=90)).isoformat(),'profileBaseline':evidence['profilesText'],'ruleBaseline':evidence['rules'],'receipt':(existing.get('result',{}).get('receipt') or existing.get('priorReceipt')) if existing else None}
  path=PRIVATE/(run_id+'.json');write(path,bundle);bundle_hash=hashlib.sha256(path.read_bytes()).hexdigest()
  rec[proposal_id]={'proposal':p,'operation':operation,'status':'awaiting_windows','updatedAt':stamp(),'runId':run_id,'ruleName':rule_name,'priorReceipt':bundle['receipt']};write(PRIVATE/'records.json',rec)
  args=['C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe','-NoProfile','-File',str(ROOT/'execution-broker.ps1'),'-Bundle',str(path),'-ExpectedHash',bundle_hash,'-Result',str(PRIVATE/(run_id+'-result.json'))]
  try:subprocess.Popen(args,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  except OSError as ex:
   rec[proposal_id]['status']='failed';rec[proposal_id]['result']={'message':str(ex)};write(PRIVATE/'records.json',rec);raise ValueError('Windows executor could not start')
  return {'status':'awaiting_windows','message':'Review Windows UAC. A block is not confirmed until its rule properties are verified.'}
