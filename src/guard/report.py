"""Audit log -> text report: posture for management, rule/agent breakdown for security."""

import json
from collections import Counter
from datetime import datetime, timedelta


def bar(n: int, top: int, width: int = 24) -> str:
    return "█" * max(1, round(width * n / top)) if n else ""


def pct(values: list[float], q: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, int(q * len(s)))] if s else 0.0


def render(events: list[dict], now: datetime, window: timedelta = timedelta(days=1)) -> str:
    since = now - window
    recent = [e for e in events if datetime.fromisoformat(e["ts"]) >= since]
    decisions = [e for e in recent if "verdict" in e and e.get("event") in ("PreToolUse", "UserPromptSubmit", "mcp")]
    verdicts = Counter(e.get("would", e["verdict"]) for e in decisions)
    rules = Counter(e["rule"] for e in decisions if e.get("rule") not in (None, "ok"))
    pii = Counter()
    for e in recent:
        pii.update(e.get("pii") or {})
    sigs = Counter(s for e in recent for s in e.get("signatures", []))
    agents = Counter((e.get("agent", "?"), e.get("would", e["verdict"])) for e in decisions)
    lat = [e["latency_ms"] for e in decisions if "latency_ms" in e]
    total = sum(verdicts.values()) or 1
    lines = [
        f"AI CONTROL LAYER — last {window} (until {now:%Y-%m-%d %H:%M} UTC)",
        "",
        f"decisions {sum(verdicts.values())}   allow {verdicts['allow']}   ask {verdicts['ask']}   "
        f"deny {verdicts['deny']}   block-rate {verdicts['deny'] / total:.0%}",
        f"hook latency  p50 {pct(lat, .5):.1f} ms   p95 {pct(lat, .95):.1f} ms",
        "",
    ]
    for title, counter in (("denials by rule", rules), ("PII detected", pii), ("attack signatures", sigs)):
        lines.append(title)
        top = max(counter.values(), default=1)
        lines += [f"  {k:<22} {n:>5} {bar(n, top)}" for k, n in counter.most_common(10)] or ["  -"]
        lines.append("")
    lines.append("agents (verdict)")
    lines += [f"  {a:<12} {v:<6} {n:>5}" for (a, v), n in sorted(agents.items())] or ["  -"]
    consent = [e for e in recent if e.get("event") == "consent"]
    lines += ["", "consent"] + ([f"  {e['ts'][:19]}  {e.get('user')}  {e['verdict']}" for e in consent[-5:]] or ["  -"])
    return "\n".join(lines)


# --- interactive dashboard: one offline HTML file, data embedded as JSON ---

DECIDING = ("PreToolUse", "UserPromptSubmit", "mcp", "gateway")
MAX_ROWS = 5000  # ponytail: newest rows only; a huge log would bloat the file


def source_of(e: dict) -> str:
    return "hook" if e.get("event") in ("PreToolUse", "UserPromptSubmit") else str(e.get("event", "?"))


def detail_of(e: dict) -> str:
    """Names and counts only: the audit log never holds values, and neither does this."""
    parts = [str(e[k]) for k in ("tool", "model", "upstream", "judge_category", "path") if e.get(k)]
    parts += [str(s) for s in e.get("signatures") or []]
    parts += [f"{k}x{n}" for k, n in (e.get("pii") or {}).items()] + [str(k) for k in e.get("kinds") or []]
    return " ".join(parts)


def stats(events: list[dict], now: datetime) -> dict:
    ev = lambda e: e.get("would", e.get("verdict"))  # noqa: E731  # monitor mode: what enforce would do
    dec = [e for e in events if e.get("event") in DECIDING and "verdict" in e]
    gw = [e for e in events if e.get("event") == "gateway"]
    today = now.date().isoformat()
    deny = sum(ev(e) == "deny" for e in dec)
    hooks = [e["latency_ms"] for e in dec if e["event"] != "gateway" and "latency_ms" in e]
    guard = [e["guard_ms"] for e in gw if "guard_ms" in e]
    hours = (
        (datetime.fromisoformat(max(e["ts"] for e in events)) - datetime.fromisoformat(min(e["ts"] for e in events))).total_seconds() / 3600
        if events
        else 0
    )
    cut = 10 if hours > 48 else 13  # per-hour for the last two days, per-day beyond
    buckets: dict[str, list[int]] = {}
    for e in dec:
        b = buckets.setdefault(e["ts"][:cut], [0, 0])
        b[0] += 1
        b[1] += ev(e) == "deny"
    by = {k: Counter() for k in ("principal", "model")}
    for e in gw:
        for k, c in by.items():
            c[e.get(k, "?")] += e.get("cost_usd", 0)
    pii, masked = Counter(), Counter()
    for e in events:
        pii.update(e.get("pii") or {})
        masked.update(e.get("masked_out") or {})
    scores = Counter(min(9, int(e["judge_score"] * 10)) for e in events if isinstance(e.get("judge_score"), int | float))
    return {
        "now": now.isoformat(),
        "kpi": {
            "events": len(events), "decisions": len(dec), "denies": deny,
            "block_rate": deny / len(dec) if dec else 0,
            "spend_today": sum(e.get("cost_usd", 0) for e in gw if e["ts"][:10] == today),
            "spend_total": sum(e.get("cost_usd", 0) for e in gw),
            "tokens": sum(e.get("tokens", 0) for e in gw),
            "guard_p50": pct(guard, .5), "guard_p95": pct(guard, .95),
            "hook_p50": pct(hooks, .5), "hook_p95": pct(hooks, .95),
        },  # fmt: skip
        "spend_principal": by["principal"].most_common(10),
        "spend_model": by["model"].most_common(10),
        "blocks": sorted([k, *v] for k, v in buckets.items()),
        "posture": {
            "mode": "monitor" if any("would" in e for e in dec) else "enforce",
            "monitor_seen": any("would" in e for e in dec),
            "consent": dict(Counter(e["verdict"] for e in events if e.get("event") == "consent")),
        },
        "rules": Counter(e["rule"] for e in dec if ev(e) != "allow" and e.get("rule") not in (None, "ok")).most_common(10),
        "agents": sorted(Counter((e.get("agent") or e.get("principal") or "?", ev(e)) for e in dec).items()),
        "signatures": Counter(s for e in events for s in e.get("signatures") or []).most_common(10),
        "pii": pii.most_common(), "masked": masked.most_common(),
        "judge": [scores[i] for i in range(10)],
        "rows": [
            {"ts": e["ts"][:19], "source": source_of(e), "who": e.get("agent") or e.get("principal") or e.get("user") or "",
             "verdict": ev(e) or "", "rule": e.get("rule") or "", "detail": detail_of(e)}
            for e in reversed(events[-MAX_ROWS:]) if e.get("event") in (*DECIDING, "consent")
        ],
    }  # fmt: skip


def render_html(events: list[dict], now: datetime) -> str:
    data = json.dumps(stats(events, now), ensure_ascii=False).replace("<", "\\u003c")  # no </script>, no <!--
    return PAGE.replace("__DATA__", data)


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Control Layer</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--mute:#777;--line:#ddd;--bar:#555;--red:#c8102e}
@media(prefers-color-scheme:dark){:root{--bg:#121212;--fg:#e8e8e8;--mute:#999;--line:#333;--bar:#aaa;--red:#ff5b6e}}
*{box-sizing:border-box}
body{margin:0;padding:1rem;max-width:1100px;margin-inline:auto;background:var(--bg);color:var(--fg);
font:14px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-variant-numeric:tabular-nums}
h1{font-size:1.1rem;margin:0}h2{font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mute);margin:1.5rem 0 .5rem;border-bottom:1px solid var(--line)}
header{display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:.5rem}
nav button,.bar button{font:inherit;color:inherit;background:none;border:1px solid var(--line);padding:.3rem .8rem;cursor:pointer}
nav button[aria-selected=true]{background:var(--fg);color:var(--bg)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.5rem}
.tile{border:1px solid var(--line);padding:.5rem .7rem}.tile b{display:block;font-size:1.5rem;font-weight:600}.tile span{color:var(--mute);font-size:.75rem}
.tile.red b{color:var(--red)}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:0 2rem}
.row{display:grid;grid-template-columns:minmax(80px,140px) 1fr 70px;gap:.5rem;align-items:center;font-size:.85rem}
.row i{display:block;height:.7rem;background:var(--bar)}.row.red i{background:var(--red)}.row span:last-child{text-align:right}
.row span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
svg{width:100%;height:90px}svg rect{fill:var(--bar)}svg rect.d{fill:var(--red)}
.bar{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:.5rem}
input,select{font:inherit;color:inherit;background:var(--bg);border:1px solid var(--line);padding:.3rem}input{flex:1;min-width:140px}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.8rem}
th,td{text-align:left;padding:.25rem .5rem;border-bottom:1px solid var(--line);white-space:nowrap}td.deny{color:var(--red);font-weight:600}
.mute{color:var(--mute)}[hidden]{display:none}
</style></head><body>
<header><h1>AI Control Layer</h1><span class="mute" id="asof"></span></header>
<nav role="tablist"><button role="tab" aria-selected="true" data-v="m">Management</button>
<button role="tab" aria-selected="false" data-v="s">Security</button></nav>
<main id="m"></main><main id="s" hidden></main>
<script type="application/json" id="data">__DATA__</script>
<script>
const D=JSON.parse(document.getElementById("data").textContent),K=D.kpi,$=id=>document.getElementById(id);
const el=(t,c,x,p)=>{const n=document.createElement(t);if(c)n.className=c;if(x!==undefined)n.textContent=x;if(p)p.append(n);return n};
const f1=n=>n.toFixed(1),usd=n=>"$"+n.toFixed(n<1?4:2),int=n=>n.toLocaleString("en");
const sec=(p,t)=>{el("h2","",t,p);return el("div","",undefined,p)};
function rows(p,t,pairs,fmt=int,red){const b=sec(p,t);if(!pairs.length)el("div","mute","none",b);
 const top=Math.max(...pairs.map(x=>x[1]),0)||1;
 for(const[k,n]of pairs){const r=el("div","row"+(red?" red":""),undefined,b);el("span","",k,r).title=k;
  const w=el("span","",undefined,r),i=el("i","",undefined,w);i.style.width=Math.max(2,100*n/top)+"%";el("span","",fmt(n),r)}}
function tiles(p,list){const g=el("div","tiles",undefined,p);for(const[l,v,red]of list){const t=el("div","tile"+(red?" red":""),undefined,g);el("b","",v,t);el("span","",l,t)}}
function chart(p,t,series){const b=sec(p,t),S="http://www.w3.org/2000/svg";
 if(!series.length)return el("div","mute","none",b);
 const svg=document.createElementNS(S,"svg"),w=100/series.length,top=Math.max(...series.map(x=>x[1]))||1;
 svg.setAttribute("viewBox","0 0 100 40");svg.setAttribute("preserveAspectRatio","none");
 series.forEach(([k,n,d],i)=>{for(const[v,c]of[[n,""],[d,"d"]]){const h=40*v/top,r=document.createElementNS(S,"rect");
  r.setAttribute("x",i*w+w*.1);r.setAttribute("y",40-h);r.setAttribute("width",w*.8);r.setAttribute("height",h);r.setAttribute("class",c);
  const ti=document.createElementNS(S,"title");ti.textContent=k+": "+n+" decisions, "+d+" denies";r.append(ti);svg.append(r)}});
 b.append(svg);el("div","mute",series[0][0]+"  ..  "+series[series.length-1][0]+"  (grey: decisions, red: denies)",b)}
$("asof").textContent="as of "+D.now.slice(0,16).replace("T"," ")+" UTC";
{const m=$("m");
 tiles(m,[["events",int(K.events)],["block rate",(100*K.block_rate).toFixed(1)+"%",1],["denies",int(K.denies),1],
  ["gateway spend today",usd(K.spend_today)],["gateway spend total",usd(K.spend_total)],["tokens",int(K.tokens)],
  ["guard overhead p50 / p95",f1(K.guard_p50)+" / "+f1(K.guard_p95)+" ms"],["hook latency p50 / p95",f1(K.hook_p50)+" / "+f1(K.hook_p95)+" ms"]]);
 const c=el("div","cols",undefined,m);
 rows(el("div","",undefined,c),"Spend per principal (USD)",D.spend_principal,usd);
 rows(el("div","",undefined,c),"Spend per model (USD)",D.spend_model,usd);
 chart(m,"Blocks over time",D.blocks);
 const P=D.posture,b=sec(m,"Posture");
 el("div","","mode: "+P.mode+(P.monitor_seen?" (monitor decisions seen: denies shown are would-be)":""),b);
 el("div","","consent: "+(Object.entries(P.consent).map(([k,n])=>k+" "+n).join(", ")||"none recorded"),b)}
{const s=$("s"),c=el("div","cols",undefined,s),col=()=>el("div","",undefined,c);
 rows(col(),"Top rules",D.rules,int,1);
 rows(col(),"Agents x verdict",D.agents.map(([[a,v],n])=>[a+" / "+v,n]),int);
 rows(col(),"Signatures hit",D.signatures);
 rows(col(),"PII detected (kinds)",D.pii);
 rows(col(),"PII masked in model output",D.masked);
 rows(col(),"Judge score histogram",D.judge.map((n,i)=>[(i/10).toFixed(1)+"-"+((i+1)/10).toFixed(1),n]));
 el("h2","","Decisions",s);
 const bar=el("div","bar",undefined,s),q=el("input","",undefined,bar),V=el("select","",undefined,bar),O=el("select","",undefined,bar);
 q.placeholder="filter text";q.setAttribute("aria-label","filter text");V.setAttribute("aria-label","verdict");O.setAttribute("aria-label","source");
 for(const[sel,all,key]of[[V,"all verdicts","verdict"],[O,"all sources","source"]]){el("option","",all,sel).value="";
  for(const v of[...new Set(D.rows.map(r=>r[key]))].sort())el("option","",v,sel).value=v}
 V.value=D.rows.some(r=>r.verdict=="deny")?"deny":"";
 const eb=el("button","","Export JSON",bar),cb=el("button","","Export CSV",bar),info=el("div","mute","",s),
  w=el("div","scroll",undefined,s),T=el("table","",undefined,w),F=["ts","source","who","verdict","rule","detail"];
 const hr=el("tr","",undefined,el("thead","",undefined,T));for(const k of F)el("th","",k,hr);const tb=el("tbody","",undefined,T);
 const cur=()=>{const t=q.value.toLowerCase();return D.rows.filter(r=>(!V.value||r.verdict==V.value)&&(!O.value||r.source==O.value)&&(!t||F.some(k=>r[k].toLowerCase().includes(t))))};
 const draw=()=>{const l=cur();tb.replaceChildren();info.textContent=l.length+" rows"+(l.length>200?" (first 200 shown, export has all)":"");
  for(const r of l.slice(0,200)){const tr=el("tr","",undefined,tb);for(const k of F)el("td",k=="verdict"&&r[k]=="deny"?"deny":"",r[k],tr)}};
 const dl=(name,type,text)=>{const a=el("a");a.href=URL.createObjectURL(new Blob([text],{type}));a.download=name;a.click();URL.revokeObjectURL(a.href)};
 const csv=x=>{x=/^[=+\-@\t\r]/.test(x)?"'"+x:x;return '"'+x.replaceAll('"','""')+'"'};
 eb.onclick=()=>dl("guard-decisions.json","application/json",JSON.stringify(cur(),null,1));
 cb.onclick=()=>dl("guard-decisions.csv","text/csv",[F.join(","),...cur().map(r=>F.map(k=>csv(r[k])).join(","))].join("\n"));
 for(const x of[q,V,O])x.oninput=draw;draw()}
for(const b of document.querySelectorAll("nav button"))b.onclick=()=>{
 for(const x of document.querySelectorAll("nav button")){x.setAttribute("aria-selected",x==b);$(x.dataset.v).hidden=x!=b}};
</script></body></html>
"""
