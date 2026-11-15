# `dashboard/validate.cjs`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/dashboard/validate.cjs). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Проверки расчётов и состояний Vega, форм hits.total, ограничений, ссылок объектов и параметров обновления.

**Применение.** После сборки выполняем node validate.cjs с доступным модулем Vega.

**Особенности.** Путь require к Vega привязан к исходной рабочей станции и при переносе требует настройки. Проверочные SVG используют искусственные данные; это не скриншоты Wazuh.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-8 без BOM. **Объём:** 56 строк.

**SHA256 оригинала:** `80142b430747c7abf58444328b2ad230d73e14f3f58167c4bc8df5231da02e11`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```javascript
// Искусственные данные используются только для локальной проверки визуализаций.
const fs=require('fs');
const path=require('path');
const assert=require('assert/strict');
const vega=require('C:/Users/impal/Documents/Codex/2026-06-27/asav-wazuh-lab/password-policy-card/colored-table/validation-runtime/node_modules/vega');
const root=__dirname;
const now=Date.now(), future=new Date(now+300000).toISOString(), past=new Date(now-300000).toISOString(), observed=new Date(now-60000).toISOString();
function host(id,state='ok',until=future){return {document_kind:'host',agent_id:id,agent_name:'ARM-'+id,os:'Windows',expected:true,host_state:state,host_state_label:state==='ok'?'Данные получены':'Ошибка сборщика',snapshot_complete:state==='ok',valid_until:until,observed_at:observed,user_count:3,over_threshold_count:1,never_expires_count:1,policy_read_status:'ok',policy_max_age_seconds:7776000};}
function user(id,name,state='ok',until=future){return {document_kind:'user',agent_id:id,agent_name:'ARM-'+id,username:name,sid:'S-1-5-21-1-2-3-'+name,host_state:'ok',is_current_snapshot:true,valid_until:until,row_state:state,row_state_label:state==='ok'?'Порог не превышен':state,age_seconds:86400,enabled:true,threshold_days:60,threshold_exceeded:state==='overdue',never_expires:false,expired_reported:false,policy_expired_calculated:false,observed_at:observed};}
const hosts=[host('1'),host('2'),host('3','error'),host('4','ok',past),host('5','never_reported')];
const users=[user('1','Администратор'),user('1','02-overdue','overdue'),{...user('1','03-disabled','disabled'),enabled:false},user('1','04-cloud','excluded'),{...user('3','05-old','error'),host_state:'error',is_current_snapshot:false},user('4','06-expired-publication','ok',past)];
const checks=[];
async function render(name,docs,suffix,total=docs.length,totalShape='object',relation='eq'){
 const spec=JSON.parse(fs.readFileSync(path.join(root,name.toUpperCase()+'.vega.json'),'utf8'));
 assert.equal(spec.width,'container'); assert.equal(spec.height,'container');
 const query=spec.data[0].url;
 assert.equal(query.index,'lab-password-audit-current'); assert.equal(query.body.size,10000); assert.equal(query.body.track_total_hits,true);
 assert.equal(query['%timefield%'],undefined);assert.equal(query['%context%'],undefined);
 spec.width=1200; spec.height=name==='kpi'?160:name==='hosts'?320:530;
 spec.data[0]={name:'response',values:[{total:totalShape==='number'?total:{value:total,relation},hits:docs.map(r=>({_source:r}))}]};
 const clock=spec.signals.find(s=>s.name==='clock'); delete clock.init;delete clock.on;clock.value=now;
 const view=new vega.View(vega.parse(spec),{renderer:'none'}); await view.runAsync();
 const svg=await view.toSVG(); fs.writeFileSync(path.join(root,`LOCAL_TEST_ONLY_${name}_${suffix}.svg`),svg);
 const result={svg,rows:name==='kpi'?view.data('tiles'):view.data('rows'),truncated:view.signal('truncated')};
 view.finalize(); return result;
}
(async()=>{
 const kpi=await render('kpi',hosts,'states');
 assert.deepEqual(kpi.rows.map(r=>r.value),['2 / 5','2','2','3']); checks.push('KPI counts only expected fresh complete hosts');
 const h=await render('hosts',hosts,'states');
 assert.equal(h.rows[3].stateLabel,'Данные устарели');assert.equal(h.rows[2].healthy,false);checks.push('Host health includes errors and publication expiry');
 const u=await render('users',[...hosts,...users],'states');
 assert.deepEqual(u.rows.map(r=>r.state),['overdue','disabled','excluded','ok','error','stale']);
 assert.equal(u.rows.find(r=>r.user==='Администратор').paper,'#EAF5EE');
 assert.equal(u.rows.find(r=>r.user==='06-expired-publication').paper,'#F1F3F6');
 assert.equal(u.rows.find(r=>r.user==='02-overdue').paper,'#FDEBE9');checks.push('User normal/overdue/disabled/cloud/error/stale states and colors');
 assert.match(u.svg,/Администратор/);checks.push('Cyrillic SVG render');
 const truncated=await render('kpi',hosts,'truncated',10001);
 assert.equal(truncated.truncated,true);assert.deepEqual(truncated.rows.map(r=>r.value),['—','—','—','—']);assert.match(truncated.svg,/10 000/);checks.push('Truncation is visible and KPI values withheld');
 const legacy=await render('kpi',hosts,'legacy-total',hosts.length,'number');
 assert.equal(legacy.truncated,false);assert.deepEqual(legacy.rows.map(r=>r.value),['2 / 5','2','2','3']);checks.push('Legacy numeric hits.total is accepted');
 const legacyTruncated=await render('kpi',hosts,'legacy-truncated',10001,'number');assert.equal(legacyTruncated.truncated,true);checks.push('Legacy numeric total retains truncation protection');
 const lowerBound=await render('kpi',hosts,'lower-bound',hosts.length,'object','gte');assert.equal(lowerBound.truncated,true);checks.push('Object hits.total relation=gte remains incomplete');
 const liveShape=[{...host('004'),agent_name:'WIN11-AMTONSI',over_threshold_count:4,never_expires_count:3},host('001','never_reported'),host('002','never_reported'),host('003','never_reported')];
 for(const shape of ['object','number']) { const fixture=await render('kpi',liveShape,'live-contract-'+shape,4,shape);assert.equal(fixture.truncated,false);assert.deepEqual(fixture.rows.map(r=>r.value),['1 / 4','4','3','3']); }
 checks.push('Four-host contract KPI 1/4,4,3,3 for object and numeric totals');
 const empty=await render('kpi',[],'empty');assert.deepEqual(empty.rows.map(r=>r.value),['—','—','—','—']);checks.push('No-data is not zero violations');
 const emptyTable=await render('users',[],'empty');assert.equal(emptyTable.rows.length,0);assert.match(emptyTable.svg,/Данные ещё не опубликованы/);checks.push('Empty table state');
 const objs=fs.readFileSync(path.join(root,'Wazuh-Password-Audit-v2.ndjson'),'utf8').trim().split('\n').map(JSON.parse);
 const ids=new Set(objs.map(o=>o.type+':'+o.id)); assert.equal(ids.size,objs.length);
 for(const obj of objs) for(const ref of obj.references) assert(ids.has(ref.type+':'+ref.id));
 const dash=objs.find(o=>o.type==='dashboard');assert.equal(JSON.parse(dash.attributes.panelsJSON).length,3);checks.push('Saved object IDs and references are complete');
 assert.equal(dash.attributes.timeRestore,true);assert.deepEqual(dash.attributes.refreshInterval,{pause:false,value:60000});assert.equal(dash.attributes.timeFrom,'now-24h');assert.equal(dash.attributes.timeTo,'now');checks.push('Dashboard restores enabled 60-second automatic refresh');
 fs.writeFileSync(path.join(root,'validation.json'),JSON.stringify({passed:true,vega_version:vega.version,checks,live_imported:false,fixtures_only:true},null,2));
 console.log(JSON.stringify({passed:true,checks:checks.length,vega:vega.version}));
})().catch(e=>{console.error(e.stack);process.exitCode=1});
```
