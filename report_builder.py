"""Palis evidence-bound assessment reports. Vector charts; no invented telemetry."""
import collections,datetime,hashlib,json,re
from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak,Flowable,KeepTogether
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.lib import colors
VERSION='palis-assessment-2026-10-23-v4'
ROOT=Path(__file__).resolve().parent
NAVY=colors.HexColor('#142C3B');TEAL=colors.HexColor('#087F79');MINT=colors.HexColor('#55CFB5');INK=colors.HexColor('#243F50');GRAY=colors.HexColor('#647988');PALE=colors.HexColor('#EEF5F6');LINE=colors.HexColor('#DCE6EB');ORANGE=colors.HexColor('#D78A60')
def timestamp(value):
 if not value:return 'Not recorded'
 dt=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
 try:
  from zoneinfo import ZoneInfo
  dt=dt.astimezone(ZoneInfo('America/Indianapolis'))
 except Exception:
  year=dt.year;spring=datetime.datetime(year,3,8+(6-datetime.datetime(year,3,1).weekday())%7,7,tzinfo=datetime.timezone.utc);fall=datetime.datetime(year,11,1+(6-datetime.datetime(year,11,1).weekday())%7,6,tzinfo=datetime.timezone.utc)
  daylight=spring<=dt<fall;dt=dt.astimezone(datetime.timezone(datetime.timedelta(hours=-4 if daylight else -5),'EDT' if daylight else 'EST'))
 return dt.strftime('%B %d, %Y | %I:%M:%S %p %Z')
def clean(value):return str(value).replace('\u2011','-').replace('\u2013','-').replace('\u2014',' - ').replace('\u2019',"'").replace('\u2192',' to ')
def logo(c,x,y,scale=1):
 for points,color in [([(0,0),(0,24),(10,30),(10,6)],MINT), ([(14,-2),(14,30),(24,36),(24,4)],colors.HexColor('#B4E9DE')), ([(28,4),(28,21),(38,27),(38,10)],colors.HexColor('#67AECB'))]:
  p=c.beginPath();p.moveTo(x+points[0][0]*scale,y+points[0][1]*scale)
  for px,py in points[1:]:p.lineTo(x+px*scale,y+py*scale)
  p.close();c.setFillColor(color);c.drawPath(p,fill=1,stroke=0)
class PagedCanvas(canvas.Canvas):
 def __init__(self,*a,**k):super().__init__(*a,**k);self.saved=[]
 def showPage(self):self.saved.append(dict(self.__dict__));self._startPage()
 def save(self):
  total=len(self.saved)
  for state in self.saved:
   self.__dict__.update(state)
   if self._pageNumber>1:
    self.setStrokeColor(LINE);self.line(54,43,558,43);self.setFillColor(GRAY);self.setFont('Helvetica',8);self.drawString(54,29,'PALIS  /  LOCAL FIREWALL ASSESSMENT');self.drawRightString(558,29,f'{self._pageNumber} / {total}')
   super().showPage()
  super().save()
class Charts(Flowable):
 def __init__(self,rules):super().__init__();self.rules=rules;self.width=504;self.height=405
 def draw(self):
  c=self.canv;rules=self.rules;n=len(rules);allow=sum(r.get('Action')=='Allow' for r in rules);block=sum(r.get('Action')=='Block' for r in rules)
  c.setFillColor(PALE);c.roundRect(0,175,235,225,8,fill=1,stroke=0);c.roundRect(250,175,254,225,8,fill=1,stroke=0)
  c.setFillColor(INK);c.setFont('Helvetica-Bold',11);c.drawString(17,377,'Rule actions');c.drawString(266,377,'Protocol distribution')
  cx,cy,rad=117,288,50;c.setFillColor(MINT);c.circle(cx,cy,rad,fill=1,stroke=0)
  if block and n:c.setFillColor(ORANGE);c.wedge(cx-rad,cy-rad,cx+rad,cy+rad,90,360*block/n,fill=1,stroke=0)
  c.setFillColor(PALE);c.circle(cx,cy,rad-11,fill=1,stroke=0);c.setFillColor(NAVY);c.setFont('Helvetica-Bold',22);c.drawCentredString(cx,cy-2,str(n));c.setFont('Helvetica',8);c.setFillColor(GRAY);c.drawCentredString(cx,cy-17,'enabled inbound rules')
  for yy,label,val,col in [(210,'Allow',allow,TEAL),(191,'Block',block,ORANGE)]:c.setFillColor(col);c.circle(20,yy+3,3,fill=1,stroke=0);c.setFont('Helvetica',9);c.setFillColor(INK);c.drawString(31,yy,label);c.drawRightString(217,yy,str(val))
  count=collections.Counter(r.get('Protocol','Not shown') for r in rules)
  for i,(name,val) in enumerate(count.most_common()):
   yy=345-i*23;c.setFillColor(GRAY);c.setFont('Helvetica',9);c.drawString(266,yy,str(name));c.setFillColor(LINE);c.roundRect(315,yy+1,137,5,2,fill=1,stroke=0);c.setFillColor(colors.HexColor('#5B9BC4'));c.roundRect(315,yy+1,max(2,137*val/max(count.values())),5,2,fill=1,stroke=0);c.setFillColor(INK);c.drawRightString(486,yy,str(val))
  c.setFillColor(PALE);c.roundRect(0,0,504,155,8,fill=1,stroke=0);c.setFillColor(INK);c.setFont('Helvetica-Bold',11);c.drawString(17,130,'Remote-address scope')
  groups=[('Any address',sum(r.get('RemoteIP')=='Any' for r in rules)),('Local subnet',sum('LocalSubnet' in r.get('RemoteIP','') and r.get('RemoteIP')!='Any' for r in rules))];groups.append(('Other scope',n-sum(v for _,v in groups)))
  for i,(name,val) in enumerate(groups):
   yy=99-i*29;c.setFont('Helvetica',9);c.setFillColor(GRAY);c.drawString(17,yy,name);c.setFillColor(LINE);c.roundRect(115,yy+1,320,7,3,fill=1,stroke=0);c.setFillColor(TEAL);c.roundRect(115,yy+1,max(2,320*val/max(1,n)),7,3,fill=1,stroke=0);c.setFillColor(INK);c.drawRightString(486,yy,f'{val}  ({val/max(1,n):.1%})')
def render_report(agent,evidence):
 report=agent.get('report')
 if not report:return None
 relevant={k:agent.get(k) for k in ('id','name','updatedAt','report','activity')}
 signature=hashlib.sha256(json.dumps([VERSION,relevant,evidence],sort_keys=True).encode()).hexdigest()
 output=ROOT/'reports'/(agent['id']+'.pdf');digest=output.with_suffix('.sha256')
 if output.exists() and digest.exists() and digest.read_text()==signature:return output
 generated=datetime.datetime.now(datetime.timezone.utc).isoformat();rules=evidence['rules'];n=len(rules);allow=sum(r.get('Action')=='Allow' for r in rules);block=sum(r.get('Action')=='Block' for r in rules)
 styles=getSampleStyleSheet()
 for name,size,leading,color in [('Body',10,15,INK),('Small',8,12,GRAY),('TableCell',8,12,INK),('TableHead',8,11,colors.white),('Intro',12,18,INK),('CoverTitle',34,40,colors.white),('CoverDeck',12,18,colors.HexColor('#BBD1DA')),('CoverMeta',9,15,colors.HexColor('#D0E0E5')),('Kicker',9,12,TEAL)]:styles.add(ParagraphStyle(name=name,fontName='Helvetica',fontSize=size,leading=leading,textColor=color,spaceAfter=9,wordWrap='CJK'))
 styles['Body'].spaceAfter=7
 styles['CoverTitle'].fontName='Helvetica-Bold';styles['Heading1'].fontSize=22;styles['Heading1'].leading=28;styles['Heading1'].textColor=NAVY;styles['Heading1'].spaceAfter=16;styles['Heading1'].keepWithNext=True;styles['Heading2'].fontSize=13;styles['Heading2'].leading=18;styles['Heading2'].textColor=TEAL;styles['Heading2'].spaceBefore=12;styles['Heading2'].spaceAfter=8;styles['Heading2'].keepWithNext=True
 def p(t,style='Body'):return Paragraph(escape(clean(t)).replace('\n','<br/>'),styles[style])
 def heading(k,title):return [p(k.upper(),'Kicker'),p(title,'Heading1')]
 def table(headers,rows,widths):
  t=Table([[p(h,'TableHead') for h in headers]]+[[p(v,'TableCell') for v in row] for row in rows],colWidths=widths,repeatRows=1,hAlign='LEFT');t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),NAVY),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,PALE]),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),10),('RIGHTPADDING',(0,0),(-1,-1),10),('TOPPADDING',(0,0),(-1,-1),9),('BOTTOMPADDING',(0,0),(-1,-1),6),('LINEBELOW',(0,0),(-1,0),.5,NAVY)]));return t
 short={'investigator':'Intent & ownership','dependency':'Dependencies & policy scope','challenger':'Independent evidence review'}[agent['id']]
 title={'investigator':'Firewall intent\nand ownership','dependency':'Firewall dependencies\nand policy scope','challenger':'Independent firewall\nassessment'}[agent['id']]
 story=[Spacer(1,95),p('LOCAL WINDOWS FIREWALL ASSESSMENT','CoverDeck'),p(title,'CoverTitle'),Spacer(1,15),p(report['summary'],'CoverDeck'),Spacer(1,35),p('Prepared by: '+agent.get('name',short),'CoverMeta'),p('Report generated: '+timestamp(generated),'CoverMeta'),p('Evidence snapshot: '+timestamp(evidence['collectedAt']),'CoverMeta'),p('Last agent update: '+timestamp(agent.get('updatedAt')),'CoverMeta'),Spacer(1,20),p('Scope: collected enabled inbound rules on this Windows computer.\nPrivate local assessment | Configuration evidence only','CoverMeta'),PageBreak()]
 story+=heading('01 / Decision brief','Executive summary')
 story+=[p(report['summary'],'Intro'),table(['Inbound rules','Allow rules','Block rules','Public / Any allows'],[[n,allow,block,evidence['publicRemoteAny']]],[126]*4),Spacer(1,16),p('Assessment disposition','Heading2'),p('Further evidence is required before changing the reviewed permissions. Broad configuration scope identifies review candidates; it does not establish malicious activity, external reachability or safe removal.'),p('Confirmed in the assessed snapshot','Heading2')]
 facts=[f'{n} enabled inbound definitions were collected: {allow} allow and {block} block rules.',f"{evidence['publicRemoteAny']} allow definitions include Public and RemoteIP Any.",f"{len(evidence.get('runtimeCandidates',[]))} Node/Python candidate entries were identified by the collector."]
 for fact in facts:story.append(p('- '+fact))
 story+=[p('What this report does not assert','Heading2'),p('No packet capture, connection-history analysis, vulnerability scan, malicious-IP determination or end-to-end application test supports this report. Rule counts are not exposed-service counts. Existing block definitions are not a count of threats blocked by Palis.'),p('Report contents','Heading2'),p('Configuration analytics | Profile coverage | Runtime candidate register | Specialist findings | Validation gates | Evidence provenance | Communication record','Small'),PageBreak()]
 story+=heading('02 / Configuration analytics','The firewall at a glance')
 story+=[Charts(rules),Spacer(1,14),p('Figure 1. Configuration distributions derived from the assessed enabled inbound inventory (E3). Each chart counts rule definitions. No traffic volume, risk score or time trend is inferred.','Small'),p('How to interpret the visualizations','Heading2'),p('The action ring shows configured allows and blocks. Protocol bars count each definition once. Remote-address categories are mutually exclusive: Any, LocalSubnet-containing scopes, and all remaining displayed scopes. A broad source scope can still be constrained by executable, profile, service, interface, authentication or other filters.'),PageBreak()]
 story+=heading('03 / Policy context','Profiles and evidence coverage')
 profile_counts=[]
 for profile in ('Domain','Private','Public'):
  rr=[r for r in rules if profile in r.get('Profiles','')];profile_counts.append([profile,len(rr),sum(r.get('Action')=='Allow' for r in rr),sum(r.get('Action')=='Block' for r in rr)])
 story+=[table(['Profile','Definitions','Allow','Block'],profile_counts,[150,118,118,118]),p('Profile counts overlap because one rule can apply to multiple profiles. Do not sum these rows to obtain the inventory total. Source: E3.','Small')]
 blocks=re.split(r'(?=Domain Profile Settings:|Private Profile Settings:|Public Profile Settings:)',evidence['profilesText'])
 settings=[]
 for text in blocks:
  match=re.search(r'(Domain|Private|Public) Profile Settings:',text)
  if not match:continue
  def field(key):
   m=re.search(r'^'+re.escape(key)+r'\s+([^\r\n]+)',text,re.M);return m.group(1).strip() if m else 'Not shown'
  settings.append([match.group(1),field('State'),field('Firewall Policy'),field('LogAllowedConnections')+' / '+field('LogDroppedConnections')])
 story+=[p('Profile settings','Heading2'),table(['Profile','State','Default policy','Allowed / dropped text logs'],settings,[72,48,224,160]),p('Current-profile output: '+evidence['currentProfileText'].split('Profile Settings:')[0].strip()+'. Profile state and default policy come from E1 and E2; effective applicability can require additional filters.','Small'),p('Coverage boundaries','Heading2'),table(['Evidence available','Evidence not established'],[['Displayed enabled inbound rules, scope fields and profile settings','Disabled rules, outbound rules and complete package/security filters'],['Selected executable-presence checks recorded in runtimeCandidates','Live processes/listeners, application ownership and representative business use'],['Actual agent-authored assessments and peer communications','Historical usage, malicious traffic and tested external reachability']],[252,252]),PageBreak()]
 story+=heading('04 / Candidate register','Runtime permissions to review')
 candidates=evidence.get('runtimeCandidates',[])
 cr=[]
 for i,r in enumerate(candidates,1):cr.append([f'R{i:02}',r.get('Rule Name','Not shown'),r.get('Protocol','Not shown'),r.get('LocalPort','Not shown'),r.get('Profiles','Not shown'),str(r.get('ExecutableExists','Not recorded'))])
 story+=[p('These entries are review candidates, not approved remediation actions. Register references below are report-local row labels, not stable Windows rule identifiers.','Small'),table(['Ref.','Displayed name','Protocol','Local port','Profiles','File exists'],cr,[36,142,62,65,110,89]),Spacer(1,12)]
 paths=[]
 for i,r in enumerate(candidates,1):
  program=r.get('Program','Not shown')
  if program not in [v[1] for v in paths]:paths.append([', '.join(f'R{j:02}' for j,c in enumerate(candidates,1) if c.get('Program')==program),program])
 story+=[p('Executable bindings','Heading2'),table(['References','Exact displayed executable'],paths,[85,419]),p('Reading the register','Heading2'),p('TCP and UDP permissions are distinct. Different executable paths remain distinct even when display names match. A present file is not proof that the program is running, listening, required or safe. The displayed scope must be combined with complete effective filters and owner-defined workflow requirements.'),PageBreak()]
 story+=heading('05 / Specialist assessment',short)
 for section in report.get('sections',[]):
  story.append(p(re.sub(r'^\d+\.\s*','',section['heading']),'Heading2'))
  for item in section.get('paragraphs',[]):story.append(p(item))
  for item in section.get('bullets',[]):story.append(p('- '+item))
 story.append(PageBreak())
 story+=heading('06 / Next steps','Validation and decision gates')
 checklist=[['1. Identify','Resolve the exact rule identity, full filters and executable/service/package binding.','Rule definition and ownership record'],['2. Establish need','Confirm required application transactions, clients, schedules and recovery paths.','Owner attestation and representative workflow list'],['3. Validate scope','Correlate executable-mapped listeners, interfaces, profiles and applicable effective policies.','Endpoint and policy evidence with collection times'],['4. Review proposal','Specify the smallest justified change and its expected operational impact.','Exact diff, three specialist reviews and proposed tests'],['5. Approve','Require a human decision for the exact scope. For app-created blocks, Windows elevation is also required.','Recorded approval, immutable scope and rollback receipt'],['6. Verify outcome','Check rule/filter state and owner-defined application behavior; investigate regressions.','Post-change evidence, test outcomes and closure decision']]
 story+=[table(['Gate','Required work','Evidence output'],checklist,[72,255,177]),p('Unresolved questions from this specialist','Heading2')]
 for item in agent.get('activity',{}).get('blockers',[]):story.append(p('- '+item))
 story+=[p('Next agent-reported step','Heading2'),p(agent.get('activity',{}).get('nextStep','No next step published.')),p('Change-control boundary','Heading2'),p('This assessment is not an authorization to block or remove access. The separate Palis approval workflow can propose narrow inbound blocks for human review. A created-rule receipt verifies configuration state, not packet-level enforcement. Existing historical rule counts must not be described as actions performed by this report.'),PageBreak()]
 story+=heading('07 / Audit trail','Evidence and methodology')
 story+=[table(['ID','Source / collection','Supports'],[['E1','netsh advfirewall show allprofiles','Displayed profile state, policy and text-log settings'],['E2','netsh advfirewall show currentprofile','Current profile output at snapshot capture'],['E3','netsh advfirewall firewall show rule name=all dir=in status=enabled verbose','Displayed enabled inbound rule fields and all derived inventory charts'],['E4','runtimeCandidates.ExecutableExists','Selected local executable-presence checks recorded by the collector'],['E5','Agent JSON report, activity and events','Specialist-authored findings, public work summaries and actual peer messages']],[35,285,184]),p('Time and version record','Heading2'),table(['Record','Value'],[['Report generated',timestamp(generated)],['Assessment last updated',timestamp(agent.get('updatedAt'))],['Evidence snapshot captured',timestamp(evidence['collectedAt'])],['Report template',VERSION],['Evidence fingerprint',evidence.get('fingerprint','Not recorded')]],[150,354]),p('Method and limitations','Heading2'),p('The collector reads local netsh output and normalizes displayed key/value fields. PowerShell CIM access was denied during the original inventory pass, so the assessment does not claim complete CIM/effective-filter visibility. Program paths, labels and counts are local observations rather than vendor-wide findings. These results do not describe Palo Alto Networks internal infrastructure.'),p('Dates are shown in America/Indianapolis time. Report generation, evidence capture and agent activity are separate events. Reformatting a report does not imply a fresh agent investigation. Newer live snapshots may exist in the dashboard; compare fingerprints before relying on an older assessment.'),PageBreak()]
 story+=heading('08 / Communication record','Actual specialist updates')
 ev=sorted(agent.get('events',[]),key=lambda e:e.get('at',''))
 for item in ev:
  story.append(KeepTogether([p(timestamp(item.get('at'))+' | '+item.get('kind','update')+(' | To '+item['to'] if item.get('to') else ''),'Small'),p(item.get('text',''))]))
 story+=[p('Access to underlying data','Heading2'),p('The local dashboard Rules tab provides every collected enabled inbound definition, search, filters, detailed field inspection and CSV export. Source evidence JSON and collector history are downloadable from Reports. This PDF includes the candidate register and an evidence fingerprint; it does not substitute for complete source records.'),p('End of assessment','Kicker')]
 def cover(c,doc):
  c.setFillColor(NAVY);c.rect(0,0,612,792,fill=1,stroke=0);c.setFillColor(colors.HexColor('#1A3C47'));c.rect(450,0,162,792,fill=1,stroke=0);logo(c,54,714,.9);c.setFillColor(colors.white);c.setFont('Helvetica-Bold',22);c.drawString(100,726,'Palis');c.setFillColor(MINT);c.rect(54,677,55,3,fill=1,stroke=0);c.setFont('Helvetica',8);c.setFillColor(colors.HexColor('#B5CDD7'));c.drawString(54,35,'PRIVATE LOCAL ASSESSMENT  /  CONFIGURATION EVIDENCE ONLY')
 def page_header(c,doc):
  c.setFillColor(TEAL);c.setFont('Helvetica-Bold',9);c.drawString(54,758,'PALIS');c.setFillColor(GRAY);c.setFont('Helvetica',8);c.drawRightString(558,758,short.upper());c.setStrokeColor(LINE);c.line(54,746,558,746)
 temp=output.with_suffix('.tmp.pdf')
 SimpleDocTemplate(str(temp),pagesize=(612,792),leftMargin=54,rightMargin=54,topMargin=65,bottomMargin=62,title=report['title'],author='Palis | '+agent.get('name',agent['id']),subject='Local Windows Firewall evidence assessment').build(story,onFirstPage=cover,onLaterPages=page_header,canvasmaker=PagedCanvas)
 temp.replace(output);digest.write_text(signature);return output
