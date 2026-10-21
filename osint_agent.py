#!/usr/bin/env python3
import argparse,datetime as dt,ipaddress,json,re,socket,ssl,subprocess,shutil
from pathlib import Path
from urllib.parse import urlparse
import requests,dns.resolver,phonenumbers
from phonenumbers import carrier,geocoder
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
UA="NEXUS-OSINT/1.0 (+https://github.com/Reza-Basafa/Professional-Osint-Agent)"
S=requests.Session(); S.headers.update({"User-Agent":UA})
SITES={"GitHub":"https://github.com/{}/","GitLab":"https://gitlab.com/{}/","Reddit":"https://www.reddit.com/user/{}/","Medium":"https://medium.com/@{}","Twitch":"https://www.twitch.tv/{}","YouTube":"https://www.youtube.com/@{}","Pinterest":"https://www.pinterest.com/{}/","Instagram":"https://www.instagram.com/{}/","TikTok":"https://www.tiktok.com/@{}","X":"https://x.com/{}"}
def now(): return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
def clean(t):
 t=t.strip()
 if not t or len(t)>253 or any(ord(c)<32 for c in t): raise ValueError("Invalid target length or control characters.")
 return t
def ips(host):
 out=sorted({a[4][0].split("%")[0] for a in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)})
 if not out or any(not ipaddress.ip_address(x).is_global for x in out): raise ValueError("Target resolves to a non-public IP; refused.")
 return out
def domain(t):
 ips(t); out={"domain":t,"addresses":ips(t),"mx":[],"ns":[],"txt":[],"notes":[]}
 for typ in ("MX","NS","TXT"):
  try: out[typ.lower()]=[str(x).strip('"')[:400] for x in dns.resolver.resolve(t,typ,lifetime=7)][:20]
  except Exception as e: out["notes"].append(typ+" lookup: "+type(e).__name__)
 return out
def urlcheck(raw):
 p=urlparse(raw if "://" in raw else "https://"+raw)
 if p.scheme not in ("http","https") or not p.hostname or p.username or p.password: raise ValueError("Enter a public HTTP(S) URL without embedded credentials.")
 host=p.hostname.encode("idna").decode("ascii"); resolved=ips(host)
 out={"url":p.geturl(),"host":host,"resolved_ips":resolved,"http_status":None,"title":None,"tls":None,"headers":{},"notes":[]}
 if p.scheme=="https":
  try:
   with socket.create_connection((host,p.port or 443),timeout=7) as s:
    with ssl.create_default_context().wrap_socket(s,server_hostname=host) as z: out["tls"]={"version":z.version(),"certificate_expiry":z.getpeercert().get("notAfter","Unknown")}
  except Exception as e: out["tls"]="Unavailable: "+type(e).__name__
 try:
  r=S.get(p.geturl(),timeout=7,allow_redirects=False,stream=True); out["http_status"]=r.status_code
  keys=("content-type","server","strict-transport-security","content-security-policy","x-content-type-options","x-frame-options","referrer-policy","permissions-policy","location")
  out["headers"]={k:r.headers[k][:400] for k in keys if k in r.headers}
  if 300<=r.status_code<400: out["notes"].append("Redirect not followed for safety.")
  if "text/html" in r.headers.get("content-type","").lower():
   h=next(r.iter_content(12000),b"").decode(r.encoding or "utf-8",errors="replace"); m=re.search(r"<title[^>]*>(.*?)</title>",h,re.I|re.S)
   if m: out["title"]=re.sub(r"\s+"," ",re.sub(r"<[^>]+>","",m.group(1))).strip()[:400]
  r.close()
 except Exception as e: out["notes"].append("HTTP request: "+type(e).__name__)
 return out
def username(t):
 # Accept common social-handle notation such as @example, but not full URLs or email addresses.
 t=t.strip()
 if t.startswith("@"): t=t[1:]
 if not re.fullmatch(r"[A-Za-z0-9._-]{1,39}",t): raise ValueError("Enter a username only (1-39 letters, digits, dot, underscore, or hyphen); omit URLs, spaces, and email addresses.")
 rows=[]
 for site,fmt in SITES.items():
  u=fmt.format(t)
  try:
   r=S.get(u,timeout=7,allow_redirects=False,stream=True); c=r.status_code; r.close()
   state="Candidate; manually verify" if c==200 else ("HTTP 404; not conclusive" if c==404 else ("Redirect/blocked; unknown" if c in (301,302,303,307,308,401,403,429) else "Unknown"))
   rows.append({"platform":site,"url":u,"http_status":c,"assessment":state})
  except Exception as e: rows.append({"platform":site,"url":u,"assessment":"Request error: "+type(e).__name__})
 return {"username":t,"profiles":rows,"note":"URL checks do not prove identity or account ownership."}
DKIM_SELECTORS=("default","google","selector1","selector2","k1","s1","s2","mail","dkim","smtp","mandrill","everlytickey1","everlytickey2")
def mail_auth(domain_name):
 out={"spf":[],"dmarc":[],"dkim_selector_checks":{},"notes":[]}
 try:
  txt=[r.to_text().strip('"') for r in dns.resolver.resolve(domain_name,"TXT",lifetime=7)]
  out["spf"]=[x for x in txt if x.lower().startswith("v=spf1")]
 except Exception as e: out["notes"].append("SPF/domain TXT lookup: "+type(e).__name__)
 try:
  txt=[r.to_text().strip('"') for r in dns.resolver.resolve("_dmarc."+domain_name,"TXT",lifetime=7)]
  out["dmarc"]=[x for x in txt if x.lower().startswith("v=dmarc1")]
 except Exception as e: out["notes"].append("DMARC lookup: "+type(e).__name__)
 for selector in DKIM_SELECTORS:
  q=selector+"._domainkey."+domain_name
  try:
   vals=[r.to_text().strip('"') for r in dns.resolver.resolve(q,"TXT",lifetime=3)]
   out["dkim_selector_checks"][selector]={"record_found":bool(vals),"records":vals[:3]}
  except Exception as e:
   out["dkim_selector_checks"][selector]={"record_found":False,"status":type(e).__name__}
 out["notes"].append("DKIM checks probe a short list of common selectors only; not finding one does not prove DKIM is absent.")
 return out
def email(t):
 if len(t)>254 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",t): return {"email":t,"syntax":"Invalid or unsupported","note":"No mailbox or breach-database lookup."}
 d=t.rsplit("@",1)[1].lower(); out={"email":t,"syntax":"Looks valid","domain":d,"mx":[],"note":"Does not confirm mailbox existence; no breach database queried."}
 try: out["mx"]=[str(x.exchange).rstrip(".") for x in dns.resolver.resolve(d,"MX",lifetime=7)]
 except Exception as e: out["mx_status"]="No MX result: "+type(e).__name__
 out["email_authentication"]=mail_auth(d)
 return out
def sherlock_check(t):
 if not shutil.which("sherlock"):
  return {"enabled":True,"status":"Unavailable","note":"Sherlock CLI is not installed in this environment."}
 try:
  r=subprocess.run(["sherlock",t,"--print-found","--no-color","--timeout","8"],capture_output=True,text=True,timeout=150,check=False)
  raw=(r.stdout or "")+"\n"+(r.stderr or "")
  found=[]
  for line in raw.splitlines():
   if "[+]" in line:
    m=re.search(r"(https?://\S+)",line)
    if m: found.append({"service":line.split("[+]",1)[1].split(":",1)[0].strip(),"url":m.group(1).rstrip(".,")})
  return {"enabled":True,"exit_code":r.returncode,"found_profiles":found[:100],"note":"Sherlock results are candidate public profile matches, not proof that accounts share an owner. Rate limits and false positives are possible.","output_excerpt":raw[-2500:]}
 except subprocess.TimeoutExpired:
  return {"enabled":True,"status":"Timed out","note":"Sherlock exceeded its 150-second limit; retry later or use fewer checks."}
 except Exception as e:
  return {"enabled":True,"status":"Failed","error":type(e).__name__,"note":"Sherlock did not complete successfully."}
def phone(t):
 try:
  n=phonenumbers.parse(t,None)
  return {"input":t,"possible":phonenumbers.is_possible_number(n),"valid_numbering_plan":phonenumbers.is_valid_number(n),"international_format":phonenumbers.format_number(n,phonenumbers.PhoneNumberFormat.INTERNATIONAL),"region":geocoder.description_for_number(n,"en") or "Unavailable","carrier_label":carrier.name_for_number(n,"en") or "Unavailable","note":"Numbering-plan metadata only; no GPS or subscriber lookup."}
 except Exception as e: return {"input":t,"error":"Could not parse: "+type(e).__name__,"note":"Use international format with country code."}
def collect(k,t,use_sherlock=False):
 if k=="domain":
  if "://" in t or "/" in t or "@" in t: raise ValueError("Domain mode accepts only a domain, e.g. example.com.")
  result=domain(t); result["mail_authentication"]=mail_auth(t)
  return {"DNS and mail authentication":result}
 if k=="url": return {"Website":urlcheck(t)}
 if k=="username":
  result={"Public profile checks":username(t)}
  if use_sherlock: result["Sherlock extended checks"]=sherlock_check(t)
  return result
 if k=="email": return {"Email checks":email(t)}
 if k=="phone": return {"Phone metadata":phone(t)}
 raise ValueError("Unsupported type.")
def flatten(v,p=""):
 rows=[]
 if isinstance(v,dict):
  for k,x in v.items(): rows+=flatten(x,(p+" / " if p else "")+str(k))
 elif isinstance(v,list):
  if not v: rows.append((p,"None reported"))
  for i,x in enumerate(v,1): rows+=flatten(x,f"{p} [{i}]")
 else: rows.append((p,str(v) if v is not None else "Unavailable"))
 return rows
def makepdf(path,k,t,data,stamp):
 navy=colors.HexColor("#0B1220"); panel=colors.HexColor("#142238"); green=colors.HexColor("#35E0A1"); white=colors.HexColor("#EDF3FA"); muted=colors.HexColor("#A3B2C7")
 st=getSampleStyleSheet()
 st.add(ParagraphStyle(name="CoverN",parent=st["Title"],fontName="Helvetica-Bold",fontSize=24,leading=29,textColor=green,spaceAfter=8))
 st.add(ParagraphStyle(name="SubN",parent=st["Normal"],fontSize=9,leading=13,textColor=muted))
 st.add(ParagraphStyle(name="HeadN",parent=st["Heading2"],fontSize=12,leading=16,textColor=green,spaceBefore=12,spaceAfter=6))
 st.add(ParagraphStyle(name="BodyN",parent=st["BodyText"],fontSize=8,leading=11,textColor=white,wordWrap="CJK"))
 st.add(ParagraphStyle(name="SmallN",parent=st["BodyText"],fontSize=7,leading=9,textColor=muted,wordWrap="CJK"))
 esc=lambda x:str(x).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
 doc=SimpleDocTemplate(str(path),pagesize=A4,leftMargin=17*mm,rightMargin=17*mm,topMargin=17*mm,bottomMargin=19*mm,title="NEXUS OSINT Report")
 story=[Spacer(1,8*mm),Paragraph("NEXUS / OSINT",st["CoverN"]),Paragraph("PUBLIC-SOURCE INTELLIGENCE REPORT",st["SubN"]),Spacer(1,5*mm)]
 meta=[["TARGET",esc(t)],["ANALYSIS TYPE",k.upper()],["GENERATED (UTC)",stamp],["COLLECTION","Public sources and non-invasive metadata"]]
 tb=Table([[Paragraph("<b>"+esc(a)+"</b>",st["SmallN"]),Paragraph(b,st["BodyN"])] for a,b in meta],colWidths=[43*mm,125*mm])
 tb.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),panel),("BOX",(0,0),(-1,-1),.5,green),("INNERGRID",(0,0),(-1,-1),.25,colors.HexColor("#2B3B53")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),8),("TOPPADDING",(0,0),(-1,-1),7),("BOTTOMPADDING",(0,0),(-1,-1),7)]))
 story += [tb,Spacer(1,5*mm),Paragraph("Executive summary",st["HeadN"])]
 summaries={"domain":"Collected public DNS and resolution metadata.","url":"Reviewed HTTP metadata, selected security headers, and TLS details where reachable.","username":"Checked selected public profile URLs; candidates require manual verification.","email":"Checked syntax and public MX records only; no mailbox or breach lookup.","phone":"Parsed numbering-plan metadata only; no handset location or subscriber identification."}
 story.append(Paragraph(summaries[k],st["BodyN"]))
 for section,payload in data.items():
  story.append(Paragraph(esc(section),st["HeadN"]))
  rows=[[Paragraph("<b>Field</b>",st["SmallN"]),Paragraph("<b>Observed value</b>",st["SmallN"])]]
  for a,b in flatten(payload): rows.append([Paragraph(esc(a),st["SmallN"]),Paragraph(esc(b),st["BodyN"])])
  tab=Table(rows,colWidths=[48*mm,120*mm],repeatRows=1)
  tab.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),panel),("BACKGROUND",(0,1),(-1,-1),colors.HexColor("#0F1929")),("BOX",(0,0),(-1,-1),.4,colors.HexColor("#2D4058")),("INNERGRID",(0,0),(-1,-1),.25,colors.HexColor("#223149")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),6),("RIGHTPADDING",(0,0),(-1,-1),6),("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5)])); story.append(tab)
 story.append(Paragraph("Methodology and limitations",st["HeadN"]))
 for n in ["Results reflect a point in time; public services may rate-limit requests.","A missing result does not prove an account or record does not exist.","No authentication bypass, exploitation, or private-data access is performed.","Only investigate systems and data you own or are authorized to assess. Findings are leads, not verified identity claims."]: story += [Paragraph("• "+n,st["BodyN"]),Spacer(1,2)]
 story.append(Spacer(1,5*mm)); story.append(Paragraph("github.com/Reza-Basafa/Professional-Osint-Agent",st["SmallN"]))
 def page(c,d):
  c.saveState(); c.setFillColor(navy); c.rect(0,0,A4[0],A4[1],fill=1,stroke=0); c.setStrokeColor(green); c.line(17*mm,13*mm,A4[0]-17*mm,13*mm); c.setFont("Helvetica",7); c.setFillColor(muted); c.drawString(17*mm,8*mm,"PUBLIC-SOURCE OSINT • NOT VERIFIED IDENTITY"); c.drawRightString(A4[0]-17*mm,8*mm,"PAGE "+str(d.page)); c.restoreState()
 doc.build(story,onFirstPage=page,onLaterPages=page)
def main():
 p=argparse.ArgumentParser(); p.add_argument("--type",required=True,choices=("domain","url","username","email","phone")); p.add_argument("--target",required=True); p.add_argument("--out",default="reports"); p.add_argument("--sherlock",action="store_true",help="Run the optional Sherlock public-profile check for username targets."); a=p.parse_args()
 if a.sherlock and a.type!="username": p.error("--sherlock can only be used with --type username")
 t=clean(a.target); stamp=now(); out=Path(a.out); out.mkdir(parents=True,exist_ok=True); data=collect(a.type,t,a.sherlock)
 safe=re.sub(r"[^A-Za-z0-9._-]+","_",t).strip("._-")[:50] or "target"; stem=f"nexus_osint_{a.type}_{safe}"
 payload={"tool":"NEXUS Public-Source OSINT","version":"1.1.0","generated_at_utc":stamp,"target_type":a.type,"target":t,"results":data,"notice":"Authorized public-source research only; findings are not identity verification."}
 (out/(stem+".json")).write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8"); makepdf(out/(stem+".pdf"),a.type,t,data,stamp)
 print("PDF_REPORT="+str(out/(stem+".pdf"))); print("JSON_REPORT="+str(out/(stem+".json")))
if __name__=="__main__": main()
