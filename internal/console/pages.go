package console

import (
	"fmt"
	"net/http"
)

const pageShell = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>%s</title>
<style>
body{font-family:system-ui,sans-serif;margin:2rem;background:#f4f6f8;color:#1f2937}
h1{font-size:1.25rem} table{border-collapse:collapse;background:#fff;width:100%%}
th,td{border:1px solid #dde3ea;padding:.4rem .6rem;text-align:left;font-size:.9rem}
th{background:#e8edf3} .badge{display:inline-block;padding:.1rem .5rem;border-radius:999px;font-size:.75rem}
.ok{background:#d9f6dd;color:#0a7a2f}.bad{background:#fde2e2;color:#b00020}.mid{background:#e8ecf1;color:#555}
</style></head><body>
<nav><a href="/">总览</a> · <a href="/console/certificates">证书</a> · <a href="/console/requests">申请</a> · <a href="/console/revocations">吊销</a> · <a href="/console/crl">CRL</a></nav>
<h1>%s</h1><div id="app">加载中…</div>
<script>%s</script></body></html>`

const commonJS = `
async function getJSON(u){const r=await fetch(u);return r.json()}
function esc(v){return String(v).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function table(rows,cols){return '<table><tr>'+cols.map(c=>'<th>'+c+'</th>').join('')+'</tr>'+rows.map(r=>'<tr>'+r.map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')+'</table>'}
function badge(s){const m={'active':'ok','revoked':'bad','expired':'bad','approved':'mid','pending':'mid'};return '<span class="badge '+(m[s]||'mid')+'">'+esc(s)+'</span>'}
`

func (a *API) index(w http.ResponseWriter, _ *http.Request) {
	script := commonJS + `
Promise.all([getJSON('/api/certificates'),getJSON('/api/revocations'),getJSON('/api/requests'),getJSON('/api/crl'),getJSON('/api/metrics'),getJSON('/api/audit'),getJSON('/api/verify/stats')]).then(([c,r,q,crl,m,a,v])=>{
  const active=c.filter(x=>x.status==='active').length;
  document.getElementById('app').innerHTML =
    '<p>证书 '+c.length+' 张（active '+active+'），吊销记录 '+r.length+' 条，申请 '+q.length+' 个，CRL 版本 '+crl.version+'。</p>'+
    '<p>指标：'+m.certificates+' 证书 / '+m.revocations+' 吊销 / '+m.requests+' 申请；校验缓存 命中 '+v.hits+' 次 / 未命中 '+v.misses+' 次。</p>'+
    '<p>审计事件：'+Object.keys(a.summary).map(k=>k+'='+a.summary[k]).join('，')+'</p>';
})`
	servePage(w, "CertBridge 总览", "CertBridge 总览", script)
}

func (a *API) certsPage(w http.ResponseWriter, _ *http.Request) {
	script := commonJS + `
getJSON('/api/certificates').then(c=>{
  const expired=c.filter(x=>x.status==='expired').length;
  document.getElementById('app').innerHTML='<p>共 '+c.length+' 张，已过期 '+expired+' 张。</p>'+
    table(c.map(x=>[esc(x.id.slice(0,8)),x.serial,x.generation,badge(x.status),esc(x.reason||''),esc(x.subject),esc(x.expires_at)]),['证书','序列号','代际','状态','吊销原因','主体','到期时间']);
})`
	servePage(w, "证书", "证书列表", script)
}

func (a *API) requestsPage(w http.ResponseWriter, _ *http.Request) {
	script := commonJS + `
getJSON('/api/requests').then(q=>{
  const pending=q.filter(x=>x.status==='pending').length;
  document.getElementById('app').innerHTML='<p>待审核 '+pending+' 个。</p>'+
    table(q.map(x=>[esc(x.id.slice(0,8)),esc(x.fingerprint),badge(x.status),esc(x.snapshot.subject),esc(x.snapshot.digest.slice(0,12))]),['申请','指纹','状态','主体','快照摘要']);
})`
	servePage(w, "申请", "申请列表", script)
}

func (a *API) revocationsPage(w http.ResponseWriter, _ *http.Request) {
	script := commonJS + `
getJSON('/api/revocations').then(r=>{
  const byReason={};
  r.forEach(x=>{byReason[x.reason]=(byReason[x.reason]||0)+1});
  document.getElementById('app').innerHTML='<p>原因分布：'+Object.keys(byReason).map(k=>k+'='+byReason[k]).join('，')+'</p>'+
    table(r.map(x=>[x.serial,x.generation,esc(x.reason),esc(x.revoked_at)]),['序列号','代际','原因','时间']);
})`
	servePage(w, "吊销", "吊销记录", script)
}

func (a *API) crlPage(w http.ResponseWriter, _ *http.Request) {
	script := commonJS + `
getJSON('/api/crl').then(c=>{
  const encoded=typeof c.entries==='undefined'?'':c.entries.length;
  document.getElementById('app').innerHTML='<p>版本 '+c.version+'，条目 '+(encoded||0)+'。</p>'+
    table(c.entries.map(x=>[x.serial,x.generation,esc(x.reason)]),['序列号','代际','原因']);
})`
	servePage(w, "CRL", "吊销列表", script)
}

func servePage(w http.ResponseWriter, title, heading, script string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(fmt.Sprintf(pageShell, title, heading, script)))
}
