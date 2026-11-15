import {integrity} from '../api/entities.js';
import {session} from '../stores/session.js';
import {heading} from '../components/common/shell.js';
import {esc,notify} from '../utils/dom.js';
import {submit} from '../hooks/forms.js';

const msdate=v=>v?new Date(v).toLocaleString('zh-CN',{hour12:false}):'—';
const short=h=>h?esc(String(h).slice(0,16))+'…':'—';
const REASONS={seq_gap:'丢失记录',link_mismatch:'链节被改写',hash_mismatch:'记录被改写',head_diverged:'链头不一致',truncated:'尾部被截断',checkpoint_mismatch:'凭证锚点被改写'};
const entityLink=e=>{if(!e)return '—';const k=e.kind,id=esc(e.id);
 if(k==='dataset')return '<a href="#/datasets">数据批次 #'+id+'</a>';
 if(k==='job')return '<a href="#/results/'+id+'">分析任务 #'+id+'</a>';
 if(k==='delivery')return '<a href="#/reports">分发归档 #'+id+'</a>';
 if(k==='legacy')return '<span>旧日志登记批次</span>';
 return '<span>证据链自身</span>';};

export async function integrityPage(){
 const [st,events,exports,legacy,key]=await Promise.all(
   [integrity.status(),integrity.events(),integrity.exports(),integrity.legacy(),integrity.publicKey().catch(()=>null)]);
 const broken=st.status!=='ok',b=st.first_break;
 const statusBadge=broken?'<span class="badge bad">已损坏</span>':'<span class="badge ok">完整</span>';
 const banner=broken?'<div class="banner">证据链已损坏：系统已拒绝新增批准与简报分发。请定位首个断点、凭独立保管的最近凭证离线核验，修复后再恢复业务。</div>':'';
 const breakCard=broken&&b?'<section class="panel break-card"><div class="section-title"><h2>首个断点</h2><span>'+esc(REASONS[b.reason]||b.reason)+'</span></div><div class="break-grid"><div><span>断点序号</span><strong>#'+esc(b.seq)+'</strong></div><div><span>类型</span><strong>'+esc(REASONS[b.reason]||b.reason)+'</strong></div><div><span>关联业务</span><strong>'+entityLink(b.entity)+'</strong></div></div><p class="hint">'+esc(b.detail)+'</p></section>':'';
 const drift=(st.drift||[]).map(d=>'<p class="warning">序号 '+esc(d.seq)+' · '+entityLink(d.entity)+'：'+esc(d.detail)+'</p>').join('');
 const admin=session.user.role==='admin';
 return heading('06 / EVIDENCE CHAIN','证据链与完整性','接入、分析完成、批准与简报分发逐节入链，与业务变更同事务提交。任何改写、丢失或截尾都会在核验中现形。','<button class="button" id="verify-now">立即核验 ↻</button>')
 +banner
 +'<div class="integrity-grid"><section class="panel status-panel"><div class="section-title"><h2>完整性状态</h2>'+statusBadge+'</div><div class="break-grid"><div><span>链头序号</span><strong>'+(st.head?esc(st.head.seq):'—')+'</strong></div><div><span>链头哈希</span><strong>'+short(st.head&&st.head.hash)+'</strong></div><div><span>链上事件</span><strong>'+esc(st.events)+'</strong></div><div><span>核验时间</span><strong>'+msdate(st.checked_at_ms)+'</strong></div></div>'
 +(st.last_export?'<p class="hint">最近导出：第 '+esc(st.last_export.package_seq)+' 包 · 截止序号 '+esc(st.last_export.cutoff_seq)+' · '+msdate(st.last_export.created_at_ms)+'</p>':'<p class="hint">尚未导出证据包。</p>')
 +(drift?'<div class="section-title"><h2>业务与证据快照偏差</h2><span>争议复查线索</span></div>'+drift:'')
 +'</section>'
 +breakCard
 +'<section class="panel"><div class="section-title"><h2>导出与离线核验</h2><span>固定截止点 · 凭证续验</span></div>'
 +(admin?'<button class="primary" id="export-now">导出证据包 ↗</button><div id="export-result"></div>':'<p class="hint">仅业务负责人可导出证据包。</p>')
 +'<p class="hint">导出取当前链头为固定截止点，导出期间新增的记录自动留给下一包。凭证文件（evidence-*-checkpoint.json）须复制到独立介质保管；下次核验凭上次凭证续验，可发现改写、丢失记录与截尾。核验公钥指纹：'+esc(key?key.key_id:'—')+'</p>'
 +(exports.length?'<div class="table-wrap"><table><thead><tr><th>包号</th><th>截止序号</th><th>包哈希</th><th>导出时间</th></tr></thead><tbody>'+exports.map(x=>'<tr><td>第 '+esc(x.package_seq)+' 包</td><td>'+esc(x.cutoff_seq)+'</td><td>'+short(x.package_hash)+'</td><td>'+msdate(x.created_at_ms)+'</td></tr>').join('')+'</tbody></table></div>':'')
 +'</section></div>'
 +'<section class="panel"><div class="section-title"><h2>链上事件</h2><span>最近 '+events.length+' 条</span></div><div class="table-wrap"><table><thead><tr><th>序号</th><th>阶段</th><th>关联业务</th><th>事件哈希</th><th>时间</th></tr></thead><tbody>'
 +events.map(e=>'<tr><td>#'+esc(e.seq)+'</td><td>'+esc(e.label)+'</td><td>'+entityLink(e.entity)+'</td><td title="'+esc(e.hash)+'">'+short(e.hash)+'</td><td>'+msdate(e.at)+'</td></tr>').join('')
 +'</tbody></table></div></section>'
 +'<section class="panel"><div class="section-title"><h2>旧日志</h2><span class="badge unverified">未认证历史</span></div>'
 +(legacy.length?legacy.map(x=>'<div class="legacy-row"><div><strong>'+esc(x.source)+'</strong><p>'+esc(x.content)+'</p><small>登记于 '+msdate(x.imported_at_ms)+' · '+esc(x.imported_by)+'</small></div><span class="badge unverified">未认证历史</span></div>').join(''):'<p class="empty">暂无旧日志。</p>')
 +'<p class="hint">旧日志来自证据链建立之前，无法回溯验证，仅作参考；它们不属于已验证证据，不参与链上哈希。</p>'
 +(admin?'<form id="legacy-form"><label>来源标识<input name="source" required minlength="2" value="WH_calibration_pairs-2025手工台账.csv"></label><label>旧日志内容（每行一条）<textarea name="lines" rows="4" required></textarea></label><button type="submit" class="primary">登记为未认证历史</button></form>':'')
 +'</section>';
}

export function bindIntegrity(refresh){
 document.querySelector('#verify-now').onclick=async()=>{try{const st=await integrity.verify();notify(st.status==='ok'?'核验通过：证据链完整':'核验发现断点：#'+(st.first_break&&st.first_break.seq),st.status!=='ok');await refresh();}catch(e){notify(e.message,true);}};
 const ex=document.querySelector('#export-now');
 if(ex)ex.onclick=async()=>{try{const r=await integrity.exportNow();document.querySelector('#export-result').innerHTML='<p class="hint">已导出第 '+esc(r.package_seq)+' 包（截止序号 '+esc(r.cutoff_seq)+'）：<br>证据包 '+esc(r.package_path)+'<br>凭证 '+esc(r.checkpoint_path)+'<br>'+esc(r.note)+'</p>';notify('证据包已导出');}catch(e){notify(e.message,true);}};
 const form=document.querySelector('#legacy-form');
 if(form)submit(form,async f=>{const lines=String(f.get('lines')).split('\n').map(s=>s.trim()).filter(Boolean);const r=await integrity.importLegacy({source:f.get('source'),lines});notify('已登记 '+r.count+' 条未认证历史');await refresh();});
}
