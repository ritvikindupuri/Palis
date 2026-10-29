"""Local-only dashboard. Serves real shared agent files; never starts or simulates agents."""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import json, subprocess, datetime, hashlib, threading, os, time
from xml.sax.saxutils import escape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
import control

ROOT=Path(__file__).resolve().parent
DATA=ROOT/'data'; REPORTS=ROOT/'reports'; REPORTS.mkdir(exist_ok=True)
LOCK=threading.RLock()
MONITOR={'status':'starting','intervalSeconds':10,'startedAt':None,'lastSuccessAt':None,'lastError':None,'collectionCount':0,'changeCount':0,'revision':0}
IDS=('investigator','dependency','challenger')
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def atomic(path, obj):
    tmp=path.with_suffix('.tmp'); tmp.write_text(json.dumps(obj,indent=2),encoding='utf-8'); tmp.replace(path)
def collect():
    args=['C:/Windows/System32/netsh.exe','advfirewall']
    p=subprocess.run(args+['show','allprofiles'],capture_output=True,text=True,check=True,timeout=15)
    current=subprocess.run(args+['show','currentprofile'],capture_output=True,text=True,check=True,timeout=15)
    r=subprocess.run(args+['firewall','show','rule','name=all','dir=in','status=enabled','verbose'],capture_output=True,text=True,check=True,timeout=15)
    rules=[]
    for block in r.stdout.split('Rule Name:')[1:]:
        row={'Rule Name':block.splitlines()[0].strip()}
        for line in block.splitlines()[1:]:
            if ':' in line:
                k,v=line.split(':',1); row[k.strip()]=v.strip()
        rules.append(row)
    allow=[x for x in rules if x.get('Action')=='Allow']
    public=[x for x in allow if 'Public' in x.get('Profiles','') and x.get('RemoteIP')=='Any']
    runtime=[x for x in public if x.get('Rule Name') in ('Node.js JavaScript Runtime','Python','python.exe')]
    for x in runtime: x['ExecutableExists']=Path(x.get('Program','')).is_file()
    stamp=now()
    snapshot={'collectedAt':stamp,'source':'Local netsh advfirewall (read-only)','totalEnabledInbound':len(rules),'inboundAllow':len(allow),'publicRemoteAny':len(public),'runtimeCandidates':runtime,'profilesText':p.stdout,'currentProfileText':current.stdout,'rules':rules,'limitations':['Text inventory may omit package, security and other effective filters.','No listeners, historical usage or business ownership established.','Counts are review candidates, not exposed-service counts.']}
    snapshot['fingerprint']=hashlib.sha256(json.dumps([sorted(rules,key=lambda x:json.dumps(x,sort_keys=True)),p.stdout,current.stdout],sort_keys=True).encode()).hexdigest()
    with LOCK: atomic(DATA/'evidence.json',snapshot)
    return snapshot
def load(path): return json.loads(path.read_text(encoding='utf-8-sig'))
from report_builder import render_report
def state():
    with LOCK:
        evidence=load(DATA/'evidence.json')
        session=load(DATA/'session.json'); agents=[]
        for spec in session['agents']:
            path=DATA/(spec['id']+'.json')
            try: a=load(path) if path.exists() else {'id':spec['id'],'status':'waiting','events':[]}
            except (ValueError,OSError): a={'id':spec['id'],'status':'updating','events':[]}
            a={**spec,**a}; a['pdf']=None
            baseline=DATA/(a['id']+'-assessment-evidence.json')
            if not baseline.exists(): atomic(baseline,evidence)
            assessed=load(baseline)
            a['evidenceChangedSinceAssessment']=assessed.get('fingerprint')!=evidence.get('fingerprint')
            a['assessmentEvidenceCollectedAt']=assessed['collectedAt']
            if a.get('status')=='finished' and a.get('report'):
                render_report(a,assessed); a['pdf']='/reports/'+a['id']+'.pdf'
            agents.append(a)
        log=DATA/'monitor-events.jsonl'
        events=[]
        if log.exists():
            for line in log.read_text(encoding='utf-8').splitlines()[-150:]:
                try: events.append(json.loads(line))
                except ValueError: pass
        return {'session':session,'agents':agents,'evidence':{k:v for k,v in evidence.items() if k!='rules'},'monitor':dict(MONITOR),'monitorEvents':events,'approvals':control.list_items(evidence),'serverTime':now()}
def monitor_event(kind,text):
    with LOCK:
        with (DATA/'monitor-events.jsonl').open('a',encoding='utf-8') as f: f.write(json.dumps({'at':now(),'kind':kind,'text':text,'agent':'Local firewall monitor'})+'\n')
def monitor_loop():
    MONITOR['startedAt']=now()
    previous=load(DATA/'evidence.json')
    monitor_event('status','Continuous read-only monitoring started; firewall scans every 10 seconds. These are collector events, not AI agent messages.')
    while True:
        try:
            fresh=collect()
            with LOCK:
                MONITOR.update(status='healthy',lastSuccessAt=fresh['collectedAt'],lastError=None,collectionCount=MONITOR['collectionCount']+1,revision=MONITOR['revision']+1)
                if previous.get('fingerprint')!=fresh['fingerprint']:
                    before={json.dumps(x,sort_keys=True) for x in previous['rules']}; after={json.dumps(x,sort_keys=True) for x in fresh['rules']}
                    added=len(after-before); removed=len(before-after)
                    MONITOR['changeCount']+=1
                    monitor_event('change',f'Firewall evidence changed: {added} distinct rule definitions added; {removed} removed. Profile or executable-presence changes may also require review. Agent reassessment required.')
                    history=DATA/'history'; history.mkdir(exist_ok=True)
                    atomic(history/(fresh['collectedAt'].replace(':','-')+'.json'),fresh)
                previous=fresh
        except Exception as ex:
            with LOCK:
                first=MONITOR.get('status')!='error'; MONITOR.update(status='error',lastError=str(ex),revision=MONITOR['revision']+1)
            if first: monitor_event('error','Firewall collection failed: '+str(ex))
        time.sleep(10)
class Handler(SimpleHTTPRequestHandler):
    def __init__(self,*a,**kw): super().__init__(*a,directory=str(ROOT),**kw)
    def do_GET(self):
        if self.headers.get('Host')!='127.0.0.1:8765':
            self.send_error(403,'Use the local dashboard address');return
        if self.path.split('?')[0]=='/api/control':
            payload=json.dumps({'token':control.TOKEN}).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(payload);return
        if self.path.split('?')[0]=='/api/events':
            self.send_response(200); self.send_header('Content-Type','text/event-stream'); self.send_header('Connection','keep-alive'); self.end_headers()
            try:
                while True:
                    payload=json.dumps(state())
                    self.wfile.write(('event: state\ndata: '+payload+'\n\n').encode()); self.wfile.flush(); time.sleep(1)
            except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError): pass
            return
        if self.path.split('?')[0]=='/api/state':
            try: payload=json.dumps(state()).encode(); self.send_response(200)
            except Exception as ex: payload=json.dumps({'error':str(ex)}).encode(); self.send_response(500)
            self.send_header('Content-Type','application/json'); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(payload); return
        super().do_GET()
    def do_POST(self):
        if self.headers.get('Host')!='127.0.0.1:8765' or self.headers.get('Origin')!='http://127.0.0.1:8765' or not control.secrets.compare_digest(self.headers.get('X-Palis-Approval',''),control.TOKEN):
            self.send_error(403,'Explicit local approval is required');return
        if self.path!='/api/approve':self.send_error(404);return
        try:
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=4096 or self.headers.get('Content-Type')!='application/json':raise ValueError('Expected a bounded JSON approval')
            body=json.loads(self.rfile.read(size));op=body.get('operation')
            if body.get('confirmation')!=('BLOCK' if op=='block' else 'UNBLOCK'):raise ValueError('Typed confirmation is required')
            evidence=collect()
            result=control.approve(body['id'],body['digest'],op,evidence)
            monitor_event('approval','Human approved '+op+' proposal '+body['id']+'; Windows execution awaits verification.')
            payload=json.dumps(result).encode();self.send_response(202)
        except (ValueError,KeyError,TypeError,OSError,subprocess.SubprocessError) as ex:
            payload=json.dumps({'error':str(ex)}).encode();self.send_response(409)
        self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(payload)
    def end_headers(self):
        self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Cache-Control','no-store');self.send_header('X-Frame-Options','DENY');self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");super().end_headers()
if __name__=='__main__':
    collect(); state()
    threading.Thread(target=monitor_loop,daemon=True).start()
    print('Exception Zero: http://127.0.0.1:8765 (local-only, read-only; Ctrl+C to stop)',flush=True)
    ThreadingHTTPServer(('127.0.0.1',8765),Handler).serve_forever()
