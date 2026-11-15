"""Prepare Wazuh/OpenSearch saved objects locally; no live mutations."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PREFIX = "lab-password-audit-v2-"
ALIAS = "lab-password-audit-current"
NAVY = "#172B4D"
GRAY = "#526175"
COLORS = {"ok": "#166534", "overdue": "#B42318", "other": "#526175"}


def text(mark, x, y, size=12, fill=GRAY, **extra):
    value = {"type": "text", "encode": {"update": {
        "x": {"signal": x}, "y": {"signal": y}, "fontSize": {"value": size},
        "font": {"value": "Arial"}, "fill": {"value": fill}, **extra}}}
    value["encode"]["update"]["text"] = {"signal": mark}
    return value


def base(kinds):
    return {
        "$schema": "https://vega.github.io/schema/vega/v5.json",
        "background": "#FFFFFF",
        "width": "container", "height": "container",
        "autosize": {"type": "fit-x", "contains": "padding"}, "padding": 8,
        "config": {"text": {"font": "Arial"}},
        "signals": [
            {"name": "clock", "init": "now()", "on": [{"events": {"type": "timer", "throttle": 10000}, "update": "now()"}]},
            # OpenSearch responds with an object normally, but Dashboard's Vega loader
            # can request rest_total_hits_as_int and supply a legacy numeric total.
            {"name": "totalHits", "update": "length(data('response')) === 0 ? 0 : isNumber(data('response')[0].total) ? data('response')[0].total : isValid(data('response')[0].total) && isNumber(data('response')[0].total.value) ? data('response')[0].total.value : NaN"},
            {"name": "truncated", "update": "length(data('response')) > 0 && (!isFinite(totalHits) || totalHits > length(data('documents')) || (!isNumber(data('response')[0].total) && isValid(data('response')[0].total.relation) && data('response')[0].total.relation !== 'eq'))"},
        ],
        "data": [
            {"name": "response", "url": {"index": ALIAS, "body": {
                "size": 10000, "track_total_hits": True,
                "query": {"terms": {"document_kind": kinds}},
                "sort": [{"agent_id": "asc"}, {"document_kind": "asc"}],
            }}, "format": {"property": "hits"}},
            {"name": "documents", "source": "response", "transform": [
                {"type": "flatten", "fields": ["hits"], "as": ["hit"]},
                {"type": "formula", "as": "r", "expr": "datum.hit._source"},
            ]},
        ],
        "marks": [text("truncated ? 'Данные ограничены 10 000 документами. Показатели неполные; уточните область запроса.' : ''", "0", "12", 11, "#B42318")],
    }


def hosts_dataset():
    return {"name": "hosts", "source": "documents", "transform": [
        {"type": "filter", "expr": "datum.r.document_kind === 'host'"},
        {"type": "formula", "as": "fresh", "expr": "isValid(datum.r.valid_until) && isFinite(toNumber(toDate(datum.r.valid_until))) && clock <= toNumber(toDate(datum.r.valid_until))"},
        {"type": "formula", "as": "healthy", "expr": "datum.fresh && datum.r.host_state === 'ok' && datum.r.snapshot_complete === true"},
        {"type": "formula", "as": "stateLabel", "expr": "!datum.fresh ? 'Данные устарели' : datum.r.host_state_label"},
        {"type": "formula", "as": "agent", "expr": "datum.r.agent_id"},
    ]}


def kpis():
    spec = base(["host"])
    spec["data"] += [hosts_dataset(),
        {"name": "expected", "source": "hosts", "transform": [{"type": "filter", "expr": "datum.r.expected === true"}]},
        {"name": "healthy", "source": "expected", "transform": [{"type": "filter", "expr": "datum.healthy"}]},
        {"name": "over", "source": "healthy", "transform": [{"type": "aggregate", "fields": ["r.over_threshold_count"], "ops": ["sum"], "as": ["n"]}]},
        {"name": "never", "source": "healthy", "transform": [{"type": "aggregate", "fields": ["r.never_expires_count"], "ops": ["sum"], "as": ["n"]}]},
        {"name": "tiles", "values": [
            {"column": 0, "title": "АРМ: свежие / ожидаемые", "key": "coverage", "ink": "#087F8C"},
            {"column": 1, "title": "Активные: возраст выше порога", "key": "over", "ink": "#B42318"},
            {"column": 2, "title": "Активные: пароль бессрочный", "key": "never", "ink": "#A15C00"},
            {"column": 3, "title": "АРМ: неполные / без данных", "key": "missing", "ink": "#526175"},
        ], "transform": [
            {"type": "formula", "as": "value", "expr": "truncated || length(data('expected')) === 0 ? '—' : datum.key === 'coverage' ? length(data('healthy')) + ' / ' + length(data('expected')) : datum.key === 'missing' ? '' + (length(data('expected')) - length(data('healthy'))) : length(data('healthy')) === 0 ? '—' : datum.key === 'over' ? format(data('over')[0].n, ',') : format(data('never')[0].n, ',')"},
            {"type": "formula", "as": "subtitle", "expr": "datum.key === 'over' || datum.key === 'never' ? 'Только свежие полные снимки АРМ' : datum.key === 'missing' ? 'Ошибка, неполнота или устаревание' : 'Ожидаемые узлы по реестру охвата'"},
        ]},
    ]
    spec["marks"] += [
        {"type": "rect", "from": {"data": "tiles"}, "encode": {"update": {
            "x": {"signal": "datum.column * width / 4 + 2"}, "y": {"value": 25},
            "width": {"signal": "width / 4 - 10"}, "height": {"value": 118},
            "fill": {"value": "#F5F8FC"}, "stroke": {"value": "#D8E1EC"}, "cornerRadius": {"value": 6}}}},
    ]
    for field, y, size, color in [("title", 47, 11, NAVY), ("value", 94, 31, None), ("subtitle", 123, 10, GRAY)]:
        mark = {"type": "text", "from": {"data": "tiles"}, "encode": {"update": {
            "x": {"signal": "datum.column * width / 4 + 14"}, "y": {"value": y},
            "text": {"field": field}, "fontSize": {"value": size},
            "fill": {"value": color} if color else {"field": "ink"},
            "limit": {"signal": "width / 4 - 30"}, "fontWeight": {"value": 600 if field == "value" else 400}}}}
        spec["marks"].append(mark)
    return spec


def add_paging(spec, source="rows", page_size=12):
    spec["signals"] += [
        {"name": "pageSize", "value": page_size},
        {"name": "page", "value": 0, "on": [
            {"events": "@next:click", "update": "min(page + 1, max(0, ceil(length(data('rows')) / pageSize) - 1))"},
            {"events": "@previous:click", "update": "max(0, page - 1)"},
        ]},
        {"name": "safePage", "update": "min(page, max(0, ceil(length(data('rows')) / pageSize) - 1))"},
    ]
    spec["data"].append({"name": "visible", "source": source, "transform": [
        {"type": "filter", "expr": "datum.row > safePage * pageSize && datum.row <= (safePage + 1) * pageSize"},
        {"type": "formula", "as": "localRow", "expr": "datum.row - safePage * pageSize - 1"},
    ]})
    for name, label, fraction in [("previous", "‹ Назад", .76), ("next", "Далее ›", .88)]:
        mark = text(repr(label), f"width * {fraction}", "height - 8", 12, "#087F8C", cursor={"value": "pointer"})
        mark["name"] = name; spec["marks"].append(mark)
    spec["marks"].append(text("length(data('rows')) === 0 ? 'Нет записей' : 'Страница ' + (safePage + 1) + ' / ' + ceil(length(data('rows')) / pageSize) + ' · записей: ' + length(data('rows'))", "0", "height - 8", 11))


def table(spec, columns, rowheight=34):
    spec["marks"] += [
        {"type": "rect", "encode": {"update": {"x": {"value": 0}, "y": {"value": 26}, "width": {"signal": "width"}, "height": {"value": 38}, "fill": {"value": NAVY}}}},
        {"type": "rect", "from": {"data": "visible"}, "encode": {"update": {
            "x": {"value": 0}, "y": {"signal": f"64 + datum.localRow * {rowheight}"}, "width": {"signal": "width"}, "height": {"value": rowheight-1}, "fill": {"field": "paper"}}}},
    ]
    for title, field, start, width in columns:
        spec["marks"].append(text(repr(title), f"6 + width * {start}", "49", 10, "white", fontWeight={"value": 600}))
        spec["marks"].append({"type": "text", "from": {"data": "visible"}, "encode": {"update": {
            "x": {"signal": f"6 + width * {start}"}, "y": {"signal": f"64 + (datum.localRow + 0.5) * {rowheight}"},
            "baseline": {"value": "middle"}, "text": {"field": field}, "fontSize": {"value": 11},
            "fill": {"field": "ink"}, "limit": {"signal": f"width * {width} - 10"},
            "tooltip": {"signal": "isValid(datum.r.age_seconds) ? format(datum.r.age_seconds, ',') + ' с' : 'Нет данных'" if field == "age" else f"datum.{field}"}}}})
    spec["marks"].append(text("length(data('rows')) === 0 ? 'Данные ещё не опубликованы. Проверяем сбор и обработчик состояния.' : ''", "8", "100", 12))


def host_table():
    spec = base(["host"])
    spec["data"] += [hosts_dataset(), {"name": "rows", "source": "hosts", "transform": [
        {"type": "collect", "sort": {"field": "r.agent_name", "order": "ascending"}},
        {"type": "formula", "as": "name", "expr": "datum.r.agent_name"},
        {"type": "formula", "as": "os", "expr": "isValid(datum.r.os) ? datum.r.os : '—'"},
        {"type": "formula", "as": "scopeLabel", "expr": "datum.r.expected === true ? 'Да' : 'Вне реестра'"},
        {"type": "formula", "as": "observed", "expr": "isValid(datum.r.observed_at) ? timeFormat(toDate(datum.r.observed_at), '%d.%m %H:%M') : '—'"},
        {"type": "formula", "as": "usersLabel", "expr": "datum.healthy && isValid(datum.r.user_count) ? '' + datum.r.user_count : '—'"},
        {"type": "formula", "as": "policyLabel", "expr": "datum.r.policy_read_status === 'not_collected' ? 'XP: не собирается' : datum.r.policy_read_status !== 'ok' ? 'Не определена' : datum.r.policy_max_age_unlimited === true ? 'Без ограничения' : isValid(datum.r.policy_max_age_seconds) ? format(datum.r.policy_max_age_seconds / 86400, '.0f') + ' сут.' : 'Не определена'"},
        {"type": "formula", "as": "paper", "expr": "datum.healthy ? '#EAF5EE' : '#F1F3F6'"},
        {"type": "formula", "as": "ink", "expr": "datum.healthy ? '#166534' : '#526175'"},
        {"type": "window", "ops": ["row_number"], "as": ["row"]},
    ]}]
    add_paging(spec, page_size=6)
    table(spec, [("АРМ", "name", 0, .17), ("ОС", "os", .17, .16), ("В охвате", "scopeLabel", .33, .09),
        ("Проверка", "observed", .42, .12), ("Польз.", "usersLabel", .54, .07),
        ("Макс. срок по политике", "policyLabel", .61, .17), ("Состояние сбора", "stateLabel", .78, .22)])
    return spec


def user_table():
    spec = base(["host", "user"])
    spec["data"] += [hosts_dataset(), {"name": "rows", "source": "documents", "transform": [
        {"type": "filter", "expr": "datum.r.document_kind === 'user'"},
        {"type": "lookup", "from": "hosts", "key": "agent", "fields": ["r.agent_id"], "as": ["host"]},
        {"type": "formula", "as": "fresh", "expr": "isValid(datum.r.valid_until) && isFinite(toNumber(toDate(datum.r.valid_until))) && clock <= toNumber(toDate(datum.r.valid_until))"},
        {"type": "formula", "as": "state", "expr": "!datum.fresh ? 'stale' : datum.r.row_state"},
        {"type": "formula", "as": "name", "expr": "datum.r.agent_name"},
        {"type": "formula", "as": "user", "expr": "datum.r.username"},
        {"type": "formula", "as": "age", "expr": "isValid(datum.r.age_seconds) ? datum.r.age_seconds < 86400 ? 'Менее суток' : format(floor(datum.r.age_seconds / 86400), ',') + ' сут.' : '—'"},
        {"type": "formula", "as": "threshold", "expr": "(datum.r.threshold_exceeded === true ? 'Да' : datum.r.threshold_exceeded === false ? 'Нет' : '—') + (isValid(datum.r.threshold_days) ? ' / ' + datum.r.threshold_days : '')"},
        {"type": "formula", "as": "never", "expr": "datum.r.never_expires === true ? 'Да' : datum.r.never_expires === false ? 'Нет' : '—'"},
        {"type": "formula", "as": "reported", "expr": "datum.r.expired_reported === true ? 'Да' : datum.r.expired_reported === false ? 'Нет' : '—'"},
        {"type": "formula", "as": "policy", "expr": "datum.r.policy_expired_calculated === true ? 'Истёк' : datum.r.policy_expired_calculated === false ? 'Не истёк' : 'Не определён'"},
        {"type": "formula", "as": "label", "expr": "!datum.fresh ? 'Данные устарели' : datum.r.row_state_label"},
        {"type": "formula", "as": "observed", "expr": "isValid(datum.r.observed_at) ? timeFormat(toDate(datum.r.observed_at), '%d.%m %H:%M') : '—'"},
        {"type": "formula", "as": "paper", "expr": "datum.state === 'overdue' ? '#FDEBE9' : datum.state === 'ok' ? '#EAF5EE' : '#F1F3F6'"},
        {"type": "formula", "as": "ink", "expr": "datum.state === 'overdue' ? '#B42318' : datum.state === 'ok' ? '#166534' : '#526175'"},
        {"type": "collect", "sort": {"field": ["r.agent_name", "r.username"], "order": ["ascending", "ascending"]}},
        {"type": "window", "ops": ["row_number"], "as": ["row"]},
    ]}]
    add_paging(spec, page_size=12)
    table(spec, [("АРМ", "name", 0, .13), ("Пользователь", "user", .13, .15), ("Возраст", "age", .28, .09),
        ("> порога / сут.", "threshold", .37, .07), ("Бессроч.", "never", .44, .07), ("Windows: истёк", "reported", .51, .11),
        ("По политике", "policy", .62, .11), ("Состояние", "label", .73, .16), ("Проверка", "observed", .89, .11)])
    return spec


def build():
    specs = {"kpi": kpis(), "hosts": host_table(), "users": user_table()}
    titles = {"kpi": "Пароли — охват и показатели по свежим снимкам", "hosts": "АРМ — полнота и свежесть сбора", "users": "Локальные пользователи — возраст и срок паролей"}
    descriptions = {
        "kpi": "Показатели только по свежим полным ожидаемым АРМ. Прочерк означает отсутствие достоверного знаменателя. Срок действия публикации пересчитывается в браузере.",
        "hosts": "Охват берём из реестра ожидаемых АРМ. Ошибки и узлы без данных не скрываем. Локальная политика XP новым адаптером не собирается.",
        "users": "Одна строка на agent.id+SID принятого снимка. Старые строки при ошибке сбора отмечаем серым. Порог возраста, бессрочность и истечение по политике — разные показатели. Полное соответствие и сложность пароля не проверяются.",
    }
    objects=[]; panels=[]; refs=[]
    geometry={"kpi":(0,0,48,8),"hosts":(0,8,48,16),"users":(0,24,48,26)}
    for key,spec in specs.items():
        (HERE/(key.upper()+".vega.json")).write_text(json.dumps(spec,ensure_ascii=False,indent=2),encoding="utf-8")
        obj={"type":"visualization","id":PREFIX+key,"attributes":{
            "title":titles[key],"description":descriptions[key],"version":1,"uiStateJSON":"{}",
            "visState":json.dumps({"title":titles[key],"type":"vega","aggs":[],"params":{"spec":json.dumps(spec,ensure_ascii=False)}},ensure_ascii=False),
            "kibanaSavedObjectMeta":{"searchSourceJSON":json.dumps({"query":{"language":"kuery","query":""},"filter":[]})}},
            "references":[],"migrationVersion":{"visualization":"7.10.0"}}
        objects.append(obj); n=str(len(panels)+1); ref="panel_"+n; x,y,w,h=geometry[key]
        panels.append({"version":"2.19.6","panelIndex":n,"gridData":{"x":x,"y":y,"w":w,"h":h,"i":n},"embeddableConfig":{},"panelRefName":ref})
        refs.append({"name":ref,"type":"visualization","id":obj["id"]})
    objects.append({"type":"dashboard","id":PREFIX+"overview","attributes":{
        "title":"Контроль паролей локальных учётных записей — АРМ",
        "description":"Актуальные снимки локального SAM без AD. Порог возраста не равен проверке сложности. Таблица не зависит от исторического диапазона времени; данные берём из текущего состояния. Ошибки/устаревание не трактуем как отсутствие нарушений.",
        "hits":0,"version":1,"timeRestore":True,"timeFrom":"now-24h","timeTo":"now",
        "refreshInterval":{"pause":False,"value":60000},
        "panelsJSON":json.dumps(panels,ensure_ascii=False),"optionsJSON":json.dumps({"useMargins":True,"hidePanelTitles":False}),
        "kibanaSavedObjectMeta":{"searchSourceJSON":json.dumps({"query":{"language":"kuery","query":""},"filter":[]})}},
        "references":refs,"migrationVersion":{"dashboard":"7.9.3"}})
    (HERE/"Wazuh-Password-Audit-v2.ndjson").write_text("\n".join(json.dumps(o,ensure_ascii=False,separators=(",",":")) for o in objects)+"\n",encoding="utf-8")
    manifest={"dashboard_id":PREFIX+"overview","objects":len(objects),"panels":len(panels),"alias":ALIAS,
        "live_imported":False,"time_filter_applied":False,"query_limit":10000,
        "notice":"Все Vega-панели показывают текущее состояние alias; исторический диапазон и общий DQL не применяются. Пагинация таблиц локальная, лимит запроса отображается явно."}
    (HERE/"manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps(manifest,ensure_ascii=False))


if __name__=="__main__": build()
