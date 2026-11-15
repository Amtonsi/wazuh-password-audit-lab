# `dashboard/KPI.vega.json`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/dashboard/KPI.vega.json). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Полный код четырёх карточек: охват АРМ, превышения возраста, индивидуальная бессрочность и отсутствие свежих полных данных.

**Применение.** Используем в Vega 5 либо импортируем в составе общего NDJSON. Источник: lab-password-audit-current.

**Особенности.** Счётчики пользователей относятся к свежим полным ожидаемым АРМ. Явный never_expires отличается от общей неограниченной политики; усечённую выборку не выдаём за полную.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-8 без BOM. **Объём:** 367 строк.

**SHA256 оригинала:** `b7db1076c6b60d25245a2afc95c81c6254dd8f6ee6f07f51b4eabe5c4c860361`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```json
{
  "$schema": "https://vega.github.io/schema/vega/v5.json",
  "background": "#FFFFFF",
  "width": "container",
  "height": "container",
  "autosize": {
    "type": "fit-x",
    "contains": "padding"
  },
  "padding": 8,
  "config": {
    "text": {
      "font": "Arial"
    }
  },
  "signals": [
    {
      "name": "clock",
      "init": "now()",
      "on": [
        {
          "events": {
            "type": "timer",
            "throttle": 10000
          },
          "update": "now()"
        }
      ]
    },
    {
      "name": "totalHits",
      "update": "length(data('response')) === 0 ? 0 : isNumber(data('response')[0].total) ? data('response')[0].total : isValid(data('response')[0].total) && isNumber(data('response')[0].total.value) ? data('response')[0].total.value : NaN"
    },
    {
      "name": "truncated",
      "update": "length(data('response')) > 0 && (!isFinite(totalHits) || totalHits > length(data('documents')) || (!isNumber(data('response')[0].total) && isValid(data('response')[0].total.relation) && data('response')[0].total.relation !== 'eq'))"
    }
  ],
  "data": [
    {
      "name": "response",
      "url": {
        "index": "lab-password-audit-current",
        "body": {
          "size": 10000,
          "track_total_hits": true,
          "query": {
            "terms": {
              "document_kind": [
                "host"
              ]
            }
          },
          "sort": [
            {
              "agent_id": "asc"
            },
            {
              "document_kind": "asc"
            }
          ]
        }
      },
      "format": {
        "property": "hits"
      }
    },
    {
      "name": "documents",
      "source": "response",
      "transform": [
        {
          "type": "flatten",
          "fields": [
            "hits"
          ],
          "as": [
            "hit"
          ]
        },
        {
          "type": "formula",
          "as": "r",
          "expr": "datum.hit._source"
        }
      ]
    },
    {
      "name": "hosts",
      "source": "documents",
      "transform": [
        {
          "type": "filter",
          "expr": "datum.r.document_kind === 'host'"
        },
        {
          "type": "formula",
          "as": "fresh",
          "expr": "isValid(datum.r.valid_until) && isFinite(toNumber(toDate(datum.r.valid_until))) && clock <= toNumber(toDate(datum.r.valid_until))"
        },
        {
          "type": "formula",
          "as": "healthy",
          "expr": "datum.fresh && datum.r.host_state === 'ok' && datum.r.snapshot_complete === true"
        },
        {
          "type": "formula",
          "as": "stateLabel",
          "expr": "!datum.fresh ? 'Данные устарели' : datum.r.host_state_label"
        },
        {
          "type": "formula",
          "as": "agent",
          "expr": "datum.r.agent_id"
        }
      ]
    },
    {
      "name": "expected",
      "source": "hosts",
      "transform": [
        {
          "type": "filter",
          "expr": "datum.r.expected === true"
        }
      ]
    },
    {
      "name": "healthy",
      "source": "expected",
      "transform": [
        {
          "type": "filter",
          "expr": "datum.healthy"
        }
      ]
    },
    {
      "name": "over",
      "source": "healthy",
      "transform": [
        {
          "type": "aggregate",
          "fields": [
            "r.over_threshold_count"
          ],
          "ops": [
            "sum"
          ],
          "as": [
            "n"
          ]
        }
      ]
    },
    {
      "name": "never",
      "source": "healthy",
      "transform": [
        {
          "type": "aggregate",
          "fields": [
            "r.never_expires_count"
          ],
          "ops": [
            "sum"
          ],
          "as": [
            "n"
          ]
        }
      ]
    },
    {
      "name": "tiles",
      "values": [
        {
          "column": 0,
          "title": "АРМ: свежие / ожидаемые",
          "key": "coverage",
          "ink": "#087F8C"
        },
        {
          "column": 1,
          "title": "Активные: возраст выше порога",
          "key": "over",
          "ink": "#B42318"
        },
        {
          "column": 2,
          "title": "Активные: пароль бессрочный",
          "key": "never",
          "ink": "#A15C00"
        },
        {
          "column": 3,
          "title": "АРМ: неполные / без данных",
          "key": "missing",
          "ink": "#526175"
        }
      ],
      "transform": [
        {
          "type": "formula",
          "as": "value",
          "expr": "truncated || length(data('expected')) === 0 ? '—' : datum.key === 'coverage' ? length(data('healthy')) + ' / ' + length(data('expected')) : datum.key === 'missing' ? '' + (length(data('expected')) - length(data('healthy'))) : length(data('healthy')) === 0 ? '—' : datum.key === 'over' ? format(data('over')[0].n, ',') : format(data('never')[0].n, ',')"
        },
        {
          "type": "formula",
          "as": "subtitle",
          "expr": "datum.key === 'over' || datum.key === 'never' ? 'Только свежие полные снимки АРМ' : datum.key === 'missing' ? 'Ошибка, неполнота или устаревание' : 'Ожидаемые узлы по реестру охвата'"
        }
      ]
    }
  ],
  "marks": [
    {
      "type": "text",
      "encode": {
        "update": {
          "x": {
            "signal": "0"
          },
          "y": {
            "signal": "12"
          },
          "fontSize": {
            "value": 11
          },
          "font": {
            "value": "Arial"
          },
          "fill": {
            "value": "#B42318"
          },
          "text": {
            "signal": "truncated ? 'Данные ограничены 10 000 документами. Показатели неполные; уточните область запроса.' : ''"
          }
        }
      }
    },
    {
      "type": "rect",
      "from": {
        "data": "tiles"
      },
      "encode": {
        "update": {
          "x": {
            "signal": "datum.column * width / 4 + 2"
          },
          "y": {
            "value": 25
          },
          "width": {
            "signal": "width / 4 - 10"
          },
          "height": {
            "value": 118
          },
          "fill": {
            "value": "#F5F8FC"
          },
          "stroke": {
            "value": "#D8E1EC"
          },
          "cornerRadius": {
            "value": 6
          }
        }
      }
    },
    {
      "type": "text",
      "from": {
        "data": "tiles"
      },
      "encode": {
        "update": {
          "x": {
            "signal": "datum.column * width / 4 + 14"
          },
          "y": {
            "value": 47
          },
          "text": {
            "field": "title"
          },
          "fontSize": {
            "value": 11
          },
          "fill": {
            "value": "#172B4D"
          },
          "limit": {
            "signal": "width / 4 - 30"
          },
          "fontWeight": {
            "value": 400
          }
        }
      }
    },
    {
      "type": "text",
      "from": {
        "data": "tiles"
      },
      "encode": {
        "update": {
          "x": {
            "signal": "datum.column * width / 4 + 14"
          },
          "y": {
            "value": 94
          },
          "text": {
            "field": "value"
          },
          "fontSize": {
            "value": 31
          },
          "fill": {
            "field": "ink"
          },
          "limit": {
            "signal": "width / 4 - 30"
          },
          "fontWeight": {
            "value": 600
          }
        }
      }
    },
    {
      "type": "text",
      "from": {
        "data": "tiles"
      },
      "encode": {
        "update": {
          "x": {
            "signal": "datum.column * width / 4 + 14"
          },
          "y": {
            "value": 123
          },
          "text": {
            "field": "subtitle"
          },
          "fontSize": {
            "value": 10
          },
          "fill": {
            "value": "#526175"
          },
          "limit": {
            "signal": "width / 4 - 30"
          },
          "fontWeight": {
            "value": 400
          }
        }
      }
    }
  ]
}
```
