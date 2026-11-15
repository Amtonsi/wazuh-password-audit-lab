# `dashboard/HOSTS.vega.json`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/dashboard/HOSTS.vega.json). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Полный код таблицы АРМ: ОС, охват, время, количество пользователей, максимальный срок политики и состояние сбора.

**Применение.** Используем как Vega-панель на текущем alias.

**Особенности.** Состояние отражает результаты сбора. При истечении valid_until строка становится устаревшей; неизвестную политику XP не заменяем нулём.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-8 без BOM. **Объём:** 834 строк.

**SHA256 оригинала:** `c1d074f970ea40522d642bbced24cfc51c5ffedcf69f5b48be4e5034f46a9069`.

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
    },
    {
      "name": "pageSize",
      "value": 6
    },
    {
      "name": "page",
      "value": 0,
      "on": [
        {
          "events": "@next:click",
          "update": "min(page + 1, max(0, ceil(length(data('rows')) / pageSize) - 1))"
        },
        {
          "events": "@previous:click",
          "update": "max(0, page - 1)"
        }
      ]
    },
    {
      "name": "safePage",
      "update": "min(page, max(0, ceil(length(data('rows')) / pageSize) - 1))"
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
      "name": "rows",
      "source": "hosts",
      "transform": [
        {
          "type": "collect",
          "sort": {
            "field": "r.agent_name",
            "order": "ascending"
          }
        },
        {
          "type": "formula",
          "as": "name",
          "expr": "datum.r.agent_name"
        },
        {
          "type": "formula",
          "as": "os",
          "expr": "isValid(datum.r.os) ? datum.r.os : '—'"
        },
        {
          "type": "formula",
          "as": "scopeLabel",
          "expr": "datum.r.expected === true ? 'Да' : 'Вне реестра'"
        },
        {
          "type": "formula",
          "as": "observed",
          "expr": "isValid(datum.r.observed_at) ? timeFormat(toDate(datum.r.observed_at), '%d.%m %H:%M') : '—'"
        },
        {
          "type": "formula",
          "as": "usersLabel",
          "expr": "datum.healthy && isValid(datum.r.user_count) ? '' + datum.r.user_count : '—'"
        },
        {
          "type": "formula",
          "as": "policyLabel",
          "expr": "datum.r.policy_read_status === 'not_collected' ? 'XP: не собирается' : datum.r.policy_read_status !== 'ok' ? 'Не определена' : datum.r.policy_max_age_unlimited === true ? 'Без ограничения' : isValid(datum.r.policy_max_age_seconds) ? format(datum.r.policy_max_age_seconds / 86400, '.0f') + ' сут.' : 'Не определена'"
        },
        {
          "type": "formula",
          "as": "paper",
          "expr": "datum.healthy ? '#EAF5EE' : '#F1F3F6'"
        },
        {
          "type": "formula",
          "as": "ink",
          "expr": "datum.healthy ? '#166534' : '#526175'"
        },
        {
          "type": "window",
          "ops": [
            "row_number"
          ],
          "as": [
            "row"
          ]
        }
      ]
    },
    {
      "name": "visible",
      "source": "rows",
      "transform": [
        {
          "type": "filter",
          "expr": "datum.row > safePage * pageSize && datum.row <= (safePage + 1) * pageSize"
        },
        {
          "type": "formula",
          "as": "localRow",
          "expr": "datum.row - safePage * pageSize - 1"
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
      "type": "text",
      "encode": {
        "update": {
          "x": {
            "signal": "width * 0.76"
          },
          "y": {
            "signal": "height - 8"
          },
          "fontSize": {
            "value": 12
          },
          "font": {
            "value": "Arial"
          },
          "fill": {
            "value": "#087F8C"
          },
          "cursor": {
            "value": "pointer"
          },
          "text": {
            "signal": "'‹ Назад'"
          }
        }
      },
      "name": "previous"
    },
    {
      "type": "text",
      "encode": {
        "update": {
          "x": {
            "signal": "width * 0.88"
          },
          "y": {
            "signal": "height - 8"
          },
          "fontSize": {
            "value": 12
          },
          "font": {
            "value": "Arial"
          },
          "fill": {
            "value": "#087F8C"
          },
          "cursor": {
            "value": "pointer"
          },
          "text": {
            "signal": "'Далее ›'"
          }
        }
      },
      "name": "next"
    },
    {
      "type": "text",
      "encode": {
        "update": {
          "x": {
            "signal": "0"
          },
          "y": {
            "signal": "height - 8"
          },
          "fontSize": {
            "value": 11
          },
          "font": {
            "value": "Arial"
          },
          "fill": {
            "value": "#526175"
          },
          "text": {
            "signal": "length(data('rows')) === 0 ? 'Нет записей' : 'Страница ' + (safePage + 1) + ' / ' + ceil(length(data('rows')) / pageSize) + ' · записей: ' + length(data('rows'))"
          }
        }
      }
    },
    {
      "type": "rect",
      "encode": {
        "update": {
          "x": {
            "value": 0
          },
          "y": {
            "value": 26
          },
          "width": {
            "signal": "width"
          },
          "height": {
            "value": 38
          },
          "fill": {
            "value": "#172B4D"
          }
        }
      }
    },
    {
      "type": "rect",
      "from": {
        "data": "visible"
      },
      "encode": {
        "update": {
          "x": {
            "value": 0
          },
          "y": {
            "signal": "64 + datum.localRow * 34"
          },
          "width": {
            "signal": "width"
          },
          "height": {
            "value": 33
          },
          "fill": {
            "field": "paper"
          }
        }
      }
    },
    {
      "type": "text",
      "encode": {
        "update": {
          "x": {
            "signal": "6 + width * 0"
          },
          "y": {
            "signal": "49"
          },
          "fontSize": {
            "value": 10
          },
          "font": {
            "value": "Arial"
          },
          "fill": {
            "value": "white"
          },
          "fontWeight": {
            "value": 600
          },
          "text": {
            "signal": "'АРМ'"
          }
        }
      }
    },
    {
      "type": "text",
      "from": {
        "data": "visible"
      },
      "encode": {
        "update": {
          "x": {
            "signal": "6 + width * 0"
          },
          "y": {
            "signal": "64 + (datum.localRow + 0.5) * 34"
          },
          "baseline": {
            "value": "middle"
          },
          "text": {
            "field": "name"
          },
          "fontSize": {
            "value": 11
          },
          "fill": {
            "field": "ink"
          },
          "limit": {
            "signal": "width * 0.17 - 10"
          },
          "tooltip": {
            "signal": "datum.name"
          }
        }
      }
    },
    {
      "type": "text",
      "encode": {
        "update": {
          "x": {
            "signal": "6 + width * 0.17"
          },
          "y": {
            "signal": "49"
          },
          "fontSize": {
            "value": 10
          },
          "font": {
            "value": "Arial"
          },
          "fill": {
            "value": "white"
          },
          "fontWeight": {
            "value": 600
          },
          "text": {
            "signal": "'ОС'"
          }
        }
      }
    },
    {
      "type": "text",
      "from": {
        "data": "visible"
      },
      "encode": {
        "update": {
          "x": {
            "signal": "6 + width * 0.17"
          },
          "y": {
            "signal": "64 + (datum.localRow + 0.5) * 34"
          },
          "baseline": {
            "value": "middle"
          },
          "text": {
            "field": "os"
          },
          "fontSize": {
            "value": 11
          },
          "fill": {
            "field": "ink"
          },
          "limit": {
            "signal": "width * 0.16 - 10"
          },
          "tooltip": {
            "signal": "datum.os"
          }
        }
      }
    },
    {
      "type": "text",
      "encode": {
        "update": {
          "x": {
            "signal": "6 + width * 0.33"
          },
          "y": {
            "signal": "49"
          },
          "fontSize": {
            "value": 10
          },
          "font": {
            "value": "Arial"
          },
          "fill": {
            "value": "white"
          },
          "fontWeight": {
            "value": 600
          },
          "text": {
            "signal": "'В охвате'"
          }
        }
      }
    },
    {
      "type": "text",
      "from": {
        "data": "visible"
      },
      "encode": {
        "update": {
          "x": {
            "signal": "6 + width * 0.33"
          },
          "y": {
            "signal": "64 + (datum.localRow + 0.5) * 34"
          },
          "baseline": {
            "value": "middle"
          },
          "text": {
            "field": "scopeLabel"
          },
          "fontSize": {
            "value": 11
          },
          "fill": {
            "field": "ink"
          },
          "limit": {
            "signal": "width * 0.09 - 10"
          },
          "tooltip": {
            "signal": "datum.scopeLabel"
          }
        }
      }
    },
    {
      "type": "text",
      "encode": {
        "update": {
          "x": {
            "signal": "6 + width * 0.42"
          },
          "y": {
            "signal": "49"
          },
          "fontSize": {
            "value": 10
          },
          "font": {
            "value": "Arial"
          },
          "fill": {
            "value": "white"
          },
          "fontWeight": {
            "value": 600
          },
          "text": {
            "signal": "'Проверка'"
          }
        }
      }
    },
    {
      "type": "text",
      "from": {
        "data": "visible"
      },
      "encode": {
        "update": {
          "x": {
            "signal": "6 + width * 0.42"
          },
          "y": {
            "signal": "64 + (datum.localRow + 0.5) * 34"
          },
          "baseline": {
            "value": "middle"
          },
          "text": {
            "field": "observed"
          },
          "fontSize": {
            "value": 11
          },
          "fill": {
            "field": "ink"
          },
          "limit": {
            "signal": "width * 0.12 - 10"
          },
          "tooltip": {
            "signal": "datum.observed"
          }
        }
      }
    },
    {
      "type": "text",
      "encode": {
        "update": {
          "x": {
            "signal": "6 + width * 0.54"
          },
          "y": {
            "signal": "49"
          },
          "fontSize": {
            "value": 10
          },
          "font": {
            "value": "Arial"
          },
          "fill": {
            "value": "white"
          },
          "fontWeight": {
            "value": 600
          },
          "text": {
            "signal": "'Польз.'"
          }
        }
      }
    },
    {
      "type": "text",
      "from": {
        "data": "visible"
      },
      "encode": {
        "update": {
          "x": {
            "signal": "6 + width * 0.54"
          },
          "y": {
            "signal": "64 + (datum.localRow + 0.5) * 34"
          },
          "baseline": {
            "value": "middle"
          },
          "text": {
            "field": "usersLabel"
          },
          "fontSize": {
            "value": 11
          },
          "fill": {
            "field": "ink"
          },
          "limit": {
            "signal": "width * 0.07 - 10"
          },
          "tooltip": {
            "signal": "datum.usersLabel"
          }
        }
      }
    },
    {
      "type": "text",
      "encode": {
        "update": {
          "x": {
            "signal": "6 + width * 0.61"
          },
          "y": {
            "signal": "49"
          },
          "fontSize": {
            "value": 10
          },
          "font": {
            "value": "Arial"
          },
          "fill": {
            "value": "white"
          },
          "fontWeight": {
            "value": 600
          },
          "text": {
            "signal": "'Макс. срок по политике'"
          }
        }
      }
    },
    {
      "type": "text",
      "from": {
        "data": "visible"
      },
      "encode": {
        "update": {
          "x": {
            "signal": "6 + width * 0.61"
          },
          "y": {
            "signal": "64 + (datum.localRow + 0.5) * 34"
          },
          "baseline": {
            "value": "middle"
          },
          "text": {
            "field": "policyLabel"
          },
          "fontSize": {
            "value": 11
          },
          "fill": {
            "field": "ink"
          },
          "limit": {
            "signal": "width * 0.17 - 10"
          },
          "tooltip": {
            "signal": "datum.policyLabel"
          }
        }
      }
    },
    {
      "type": "text",
      "encode": {
        "update": {
          "x": {
            "signal": "6 + width * 0.78"
          },
          "y": {
            "signal": "49"
          },
          "fontSize": {
            "value": 10
          },
          "font": {
            "value": "Arial"
          },
          "fill": {
            "value": "white"
          },
          "fontWeight": {
            "value": 600
          },
          "text": {
            "signal": "'Состояние сбора'"
          }
        }
      }
    },
    {
      "type": "text",
      "from": {
        "data": "visible"
      },
      "encode": {
        "update": {
          "x": {
            "signal": "6 + width * 0.78"
          },
          "y": {
            "signal": "64 + (datum.localRow + 0.5) * 34"
          },
          "baseline": {
            "value": "middle"
          },
          "text": {
            "field": "stateLabel"
          },
          "fontSize": {
            "value": 11
          },
          "fill": {
            "field": "ink"
          },
          "limit": {
            "signal": "width * 0.22 - 10"
          },
          "tooltip": {
            "signal": "datum.stateLabel"
          }
        }
      }
    },
    {
      "type": "text",
      "encode": {
        "update": {
          "x": {
            "signal": "8"
          },
          "y": {
            "signal": "100"
          },
          "fontSize": {
            "value": 12
          },
          "font": {
            "value": "Arial"
          },
          "fill": {
            "value": "#526175"
          },
          "text": {
            "signal": "length(data('rows')) === 0 ? 'Данные ещё не опубликованы. Проверяем сбор и обработчик состояния.' : ''"
          }
        }
      }
    }
  ]
}
```
