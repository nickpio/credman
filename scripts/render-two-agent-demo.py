#!/usr/bin/env python3
"""Render parent-supplied, secret-free run evidence as an offline monitor.

Usage: python scripts/render-two-agent-demo.py --evidence PATH.json --output PATH.html
Event order is authoritative. Optional result.vault_state is displayed verbatim;
no action names, success states, timings, or security guarantees are inferred.
The producer must exclude credentials and other secrets from all evidence fields.
"""

import argparse
import json
from pathlib import Path


HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none'">
<title>Two agents. One credential vault.</title>
<style>
:root{color-scheme:dark;--ink:var(--foreground,#edf0ed);--dim:var(--muted-foreground,#b0b8b3);--mark:var(--accent,#e4b96c);--line:var(--border,#49534d);--panel:var(--card,#19211d);--canvas:var(--card,#111713);font-family:"Segoe UI",Helvetica,Arial,sans-serif;font-size:16px;line-height:1.5}
*{box-sizing:border-box}body{margin:0;background:var(--canvas);color:var(--ink)}main{max-width:1320px;margin:auto;padding:32px 28px 48px}h1{font-size:clamp(1.7rem,4vw,2.7rem);line-height:1.15;letter-spacing:-.035em;margin:8px 0 12px;font-weight:650}h2{font-size:1rem;margin:0 0 14px}h3{font-size:1.15rem;margin:5px 0}p{margin:6px 0}header{padding-bottom:24px}.eyebrow,.label{font-size:.75rem;letter-spacing:.1em;text-transform:uppercase;color:var(--dim)}.muted,small{color:var(--dim)}#run-title{margin-top:16px;overflow-wrap:anywhere}.lanes{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.2fr) minmax(0,1fr);border:1px solid var(--line);background:var(--panel)}.lane,.vault{padding:22px;min-width:0}.vault{border-inline:1px solid var(--line)}.lane[data-active="true"] h3{color:var(--mark)}.lane[data-active="true"]{outline:2px solid var(--mark);outline-offset:-2px}.lane-action{margin-top:22px;overflow-wrap:anywhere}.role{min-height:3em;overflow-wrap:anywhere}pre,code,time{font-family:"Cascadia Code","DejaVu Sans Mono",monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.82rem;line-height:1.6;margin:0}#vault-state{margin-top:12px;max-height:240px;overflow:auto}.transport{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:20px 0}button,input,summary{font:inherit}button{min-height:44px;background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:4px;padding:8px 14px;cursor:pointer}button:hover:enabled{border-color:var(--mark)}button:disabled{opacity:.5;cursor:default}:focus-visible{outline:3px solid var(--mark);outline-offset:3px}input[type="range"]{accent-color:var(--mark);min-height:44px;width:100%;cursor:pointer}.scrubber{flex:1;min-width:180px;display:flex;align-items:center;gap:12px}.position{white-space:nowrap;font-variant-numeric:tabular-nums}.workspace{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:28px;border-top:1px solid var(--line);padding:24px 0}.timeline{list-style:none;margin:0;padding:0;max-height:470px;overflow:auto}.timeline li+li{margin-top:6px}.event{display:block;width:100%;text-align:left;padding:12px}.event[aria-current="step"]{border-color:var(--mark);box-shadow:inset 0 0 0 1px var(--mark)}.event span{display:block;overflow-wrap:anywhere}.event .event-meta{font-size:.75rem;color:var(--dim);margin-bottom:4px}.inspector{min-width:0}.raw{background:var(--panel);border:1px solid var(--line);padding:16px;max-height:470px;overflow:auto}#selected-meta{margin-bottom:12px;font-size:.85rem;overflow-wrap:anywhere}.lower{border-top:1px solid var(--line);padding-top:24px}.checks{width:100%;border-collapse:collapse;margin-bottom:24px}.checks th,.checks td{text-align:left;vertical-align:top;border-bottom:1px solid var(--line);padding:10px 12px;overflow-wrap:anywhere}.checks th{width:35%;font-weight:400}.checks td{background:var(--panel)}summary{cursor:pointer;min-height:44px;display:list-item;padding:10px 0}details{margin-bottom:24px}details pre{padding:16px;background:var(--panel);border:1px solid var(--line);max-height:360px;overflow:auto}#limits{padding-left:22px}#limits li{margin:8px 0;overflow-wrap:anywhere}footer{border-top:1px solid var(--line);margin-top:24px;padding-top:16px;font-size:.8rem;color:var(--dim)}
@media(max-width:760px){main{padding:24px 16px}.lanes,.workspace{grid-template-columns:1fr}.vault{border-inline:0;border-block:1px solid var(--line)}.role{min-height:0}.lane-action{margin-top:12px}.timeline{max-height:320px}.checks th{width:40%}.transport{gap:8px}.scrubber{flex-basis:100%}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
</style>
</head>
<body>
<main>
<header><div class="eyebrow">Credman / Run monitor</div><h1>Two agents. One credential vault.</h1><p class="muted">Recorded live run / synthetic local application</p><p id="run-title"></p></header>
<section class="lanes" aria-label="Agents and recorded vault state">
<article class="lane" id="lane-a"><div class="label">Agent A</div><h3 id="name-a"></h3><p class="role muted" id="role-a"></p><p class="lane-action" id="action-a"></p><small id="time-a"></small></article>
<article class="vault"><h2>Credential vault</h2><p class="muted">Latest recorded mutation receipt. No decrypted credential values.</p><pre id="vault-state" tabindex="0" aria-label="Recorded vault state"></pre><small id="vault-source"></small></article>
<article class="lane" id="lane-b"><div class="label">Agent B</div><h3 id="name-b"></h3><p class="role muted" id="role-b"></p><p class="lane-action" id="action-b"></p><small id="time-b"></small></article>
</section>
<section class="transport" aria-label="Replay controls">
<button id="previous" type="button">Previous</button><button id="play" type="button" aria-pressed="false">Play</button><button id="next" type="button">Next</button>
<div class="scrubber"><label for="cursor" class="label">Event</label><input id="cursor" type="range" min="0" max="0" value="0" step="1"><output id="position" class="position" for="cursor" aria-live="polite"></output></div>
<small>Replay in recorded order · 1 event / 1.5 s</small>
</section>
<div class="workspace">
<section><h2>Event timeline</h2><p id="empty" class="muted" hidden>No events recorded.</p><ol id="timeline" class="timeline" aria-label="Recorded events"></ol></section>
<section class="inspector"><h2>Selected event / raw JSON</h2><p id="selected-meta" class="muted"></p><pre id="raw" class="raw" tabindex="0" aria-label="Selected event JSON"></pre></section>
</div>
<section class="lower"><h2>Recorded checks</h2><p class="muted">Literal evidence values. No pass/fail interpretation added.</p><table class="checks" aria-label="Recorded check values"><thead><tr><th scope="col">Check</th><th scope="col">Actual value</th></tr></thead><tbody id="checks"></tbody></table><p id="no-checks" class="muted" hidden>No checks recorded.</p>
<details><summary>Provenance / supplied evidence</summary><pre id="provenance" tabindex="0"></pre></details>
<h2>Limitations</h2><ul id="limits"></ul><p id="no-limits" class="muted" hidden>No limitations supplied. This is not a claim that none exist.</p></section>
<footer>Offline evidence replay. Playback makes no requests and does not control agents or the vault. Evidence must be secret-free before rendering.</footer>
</main>
<script id="evidence" type="application/json">__EVIDENCE__</script>
<script>
'use strict';
const evidence = JSON.parse(document.getElementById('evidence').textContent);
const el = id => document.getElementById(id);
const text = (id, value) => { el(id).textContent = value; };
const pretty = value => JSON.stringify(value, null, 2);
const events = evidence.events;
const names = {human:'Human', system:'System'};
let cursor = events.length ? Math.max(0, events.findIndex(event => event.actor === 'a' || event.actor === 'b')) : -1;
let timer = null;
text('run-title', evidence.title);
document.title = evidence.title + ' | Credman run monitor';
for (const participant of evidence.participants) {
  names[participant.id] = participant.name;
  text('name-' + participant.id, participant.name);
  text('role-' + participant.id, participant.role);
}
const buttons = events.map((event, index) => {
  const li = document.createElement('li');
  const button = document.createElement('button');
  button.type = 'button'; button.className = 'event';
  const meta = document.createElement('span'); meta.className = 'event-meta';
  meta.textContent = (index + 1) + ' / ' + names[event.actor] + ' / ' + event.timestamp;
  const action = document.createElement('span'); action.textContent = event.action;
  button.append(meta, action); li.append(button); el('timeline').append(li);
  button.addEventListener('click', () => select(index));
  return button;
});
for (const [key, value] of Object.entries(evidence.checks)) {
  const row = document.createElement('tr');
  const heading = document.createElement('th'); heading.scope = 'row'; heading.textContent = key;
  const cell = document.createElement('td');
  const raw = document.createElement('pre'); raw.textContent = pretty(value);
  cell.append(raw); row.append(heading, cell); el('checks').append(row);
}
el('no-checks').hidden = Object.keys(evidence.checks).length !== 0;
text('provenance', pretty(evidence.provenance));
for (const limit of evidence.limitations) {
  const li = document.createElement('li'); li.textContent = limit; el('limits').append(li);
}
el('no-limits').hidden = evidence.limitations.length !== 0;
el('empty').hidden = events.length !== 0;
el('cursor').max = String(Math.max(0, events.length - 1));
el('cursor').disabled = events.length === 0;
function pause() {
  if (timer !== null) clearInterval(timer);
  timer = null; text('play', 'Play'); el('play').setAttribute('aria-pressed', 'false');
}
function render() {
  const event = events[cursor];
  text('position', events.length ? (cursor + 1) + ' / ' + events.length : '0 / 0');
  el('cursor').value = String(Math.max(0, cursor));
  el('cursor').setAttribute('aria-valuetext', events.length ? 'Event ' + (cursor + 1) + ' of ' + events.length : 'No events');
  el('previous').disabled = cursor <= 0;
  el('next').disabled = cursor >= events.length - 1;
  el('play').disabled = events.length < 2;
  buttons.forEach((button, index) => {
    if (index === cursor) button.setAttribute('aria-current', 'step');
    else button.removeAttribute('aria-current');
  });
  for (const id of ['a', 'b']) {
    let latest = null;
    for (let i = cursor; i >= 0; i--) if (events[i].actor === id) { latest = events[i]; break; }
    el('lane-' + id).dataset.active = String(Boolean(event && event.actor === id));
    text('action-' + id, latest ? latest.action : 'No event yet.');
    text('time-' + id, latest ? latest.timestamp : '');
  }
  let stateIndex = -1;
  for (let i = cursor; i >= 0; i--) {
    if (Object.prototype.hasOwnProperty.call(events[i].result, 'vault_state')) { stateIndex = i; break; }
  }
  text('vault-state', stateIndex < 0 ? 'No explicit vault state recorded.' : pretty(events[stateIndex].result.vault_state));
  text('vault-source', stateIndex < 0 ? '' : 'Recorded at event ' + (stateIndex + 1) + ' / ' + events[stateIndex].timestamp);
  text('selected-meta', event ? names[event.actor] + ' / ' + event.timestamp : 'No event selected.');
  text('raw', event ? pretty(event) : 'No event recorded.');
}
function select(index) { pause(); cursor = index; render(); }
el('previous').addEventListener('click', () => select(Math.max(0, cursor - 1)));
el('next').addEventListener('click', () => select(Math.min(events.length - 1, cursor + 1)));
el('cursor').addEventListener('input', event => select(Number(event.target.value)));
el('play').addEventListener('click', () => {
  if (timer !== null) { pause(); return; }
  if (cursor === events.length - 1) cursor = 0;
  text('play', 'Pause'); el('play').setAttribute('aria-pressed', 'true'); render();
  timer = setInterval(() => {
    cursor++; render();
    if (cursor >= events.length - 1) pause();
  }, 1500);
});
document.addEventListener('visibilitychange', () => { if (document.hidden) pause(); });
render();
</script>
</body>
</html>
'''


def validate(data):
    """Validate the rendering boundary without inspecting or interpreting results."""
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    require(isinstance(data, dict), 'evidence must be an object')
    require(isinstance(data.get('title'), str), 'title must be a string')
    participants = data.get('participants')
    require(isinstance(participants, list) and len(participants) == 2,
            'participants must contain exactly agents a and b')
    for participant in participants:
        require(isinstance(participant, dict), 'each participant must be an object')
        require(participant.get('id') in ('a', 'b'), 'participant id must be a or b')
        require(all(isinstance(participant.get(key), str) for key in ('name', 'role')),
                'participant name and role must be strings')
    require({p['id'] for p in participants} == {'a', 'b'}, 'participant ids must be unique')
    require(isinstance(data.get('events'), list), 'events must be an array')
    for index, event in enumerate(data['events']):
        require(isinstance(event, dict), f'event {index} must be an object')
        require(event.get('actor') in ('a', 'b', 'human', 'system'), f'event {index} has an invalid actor')
        require(all(isinstance(event.get(key), str) for key in ('action', 'timestamp')),
                f'event {index} action and timestamp must be strings')
        require(isinstance(event.get('result'), dict), f'event {index} result must be an object')
    for key in ('checks', 'provenance'):
        require(isinstance(data.get(key), dict), f'{key} must be an object')
    require(isinstance(data.get('limitations'), list)
            and all(isinstance(item, str) for item in data['limitations']),
            'limitations must be an array of strings')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve() in (args.evidence.resolve(), Path(__file__).resolve()):
        parser.error('output must differ from evidence and renderer source')
    try:
        data = json.loads(args.evidence.read_text(encoding='utf-8'),
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite JSON number')))
        validate(data)
        payload = json.dumps(data, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
        payload = payload.replace('&', r'\u0026').replace('<', r'\u003c').replace('>', r'\u003e')
        before, marker, after = HTML.partition('__EVIDENCE__')
        assert marker
        args.output.write_text(before + payload + after, encoding='utf-8')
    except (OSError, ValueError, RecursionError) as error:
        # JSON decoder errors contain positions, not the potentially sensitive input.
        parser.exit(1, f'render failed: {error}\n')
    print(f'Rendered {len(data["events"])} recorded events to {args.output}')


if __name__ == '__main__':
    main()
