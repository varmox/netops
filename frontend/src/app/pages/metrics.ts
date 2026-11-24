import { Component, DestroyRef, OnInit, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed, toObservable } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { combineLatest, forkJoin, switchMap } from 'rxjs';
import { Api, Device, MetricQuery, MetricResult } from '../api';
import { Chart, HEALTH, PALETTE, Spark, formatValue, timeSeriesOptions } from '../charts';
import { Prefs } from '../prefs';
import { refreshTicks } from '../ui';

type Instant = { labels: Record<string, string>; value: number }[];
type Ranged = { labels: Record<string, string>; values: [number, number][] }[];

const RANGES = [
  { label: '1 h', minutes: 60 },
  { label: '6 h', minutes: 360 },
  { label: '24 h', minutes: 1440 },
  { label: '7 d', minutes: 10080 },
];

function inst(r: MetricResult | undefined): Instant {
  return Array.isArray(r) && r.length && 'value' in r[0] ? (r as Instant) : [];
}
function rng(r: MetricResult | undefined): Ranged {
  return Array.isArray(r) && r.length && 'values' in r[0] ? (r as Ranged) : [];
}
function one(r: MetricResult | undefined): number | null {
  const v = inst(r)[0]?.value;
  return v == null || Number.isNaN(v) ? null : v;
}

/** VCF Operations-style overview: scoreboards, heatmap, top-N, signal quality, time series. */
@Component({
  selector: 'app-metrics',
  imports: [ClarityModule, Chart, Spark],
  template: `
    <div class="page-head">
      <h2>Metrics</h2>
      <div class="toolbar">
        <div class="btn-group btn-sm" role="group" aria-label="Time range">
          @for (r of ranges; track r.minutes) {
            <button type="button" class="btn btn-sm" [class.btn-primary]="r.minutes === minutes()"
                    [class.btn-outline]="r.minutes !== minutes()" (click)="minutes.set(r.minutes)">{{ r.label }}</button>
          }
        </div>
        <a class="btn btn-sm btn-link" href="/grafana/d/netops-overview" target="_blank" rel="noopener">
          <cds-icon shape="pop-out"></cds-icon> Grafana
        </a>
      </div>
    </div>
    @if (loading()) { <clr-progress-bar [clrLoop]="true" [clrCompact]="true"></clr-progress-bar> }

    <!-- Scoreboards -->
    <div class="clr-row">
      <div class="clr-col-12 clr-col-sm-6 clr-col-xl-3">
        <div class="card score"><div class="card-block">
          <div class="cap">Health</div>
          <div class="big">
            <span class="dot" [style.background]="health.good"></span>{{ counts().up }}
            <small>healthy</small>
            @if (counts().degraded) { <span class="dot" [style.background]="health.warn"></span>{{ counts().degraded }} }
            @if (counts().down) { <span class="dot" [style.background]="health.bad"></span>{{ counts().down }} }
          </div>
          <div class="sub">Availability {{ rangeLabel() }}: <b>{{ fmt(availability(), '%') }}</b></div>
          <app-spark [values]="sparks().availability" [color]="health.good" />
        </div></div>
      </div>
      <div class="clr-col-12 clr-col-sm-6 clr-col-xl-3">
        <div class="card score"><div class="card-block">
          <div class="cap">Internet</div>
          <div class="big">
            <span class="dot" [style.background]="online() ? health.good : online() === false ? health.bad : health.unknown"></span>
            {{ online() ? 'Online' : online() === false ? 'Offline' : '–' }}
            <small>{{ fmt(inetLatency(), 'ms') }}</small>
          </div>
          <div class="sub">Average latency to 1.1.1.1 and 9.9.9.9</div>
          <app-spark [values]="sparks().internet" [color]="palette[1]" />
        </div></div>
      </div>
      <div class="clr-col-12 clr-col-sm-6 clr-col-xl-3">
        <div class="card score"><div class="card-block">
          <div class="cap">WAN throughput (ether1)</div>
          <div class="big">↓ {{ fmt(wan().rx, 'bps') }} <small>↑ {{ fmt(wan().tx, 'bps') }}</small></div>
          <div class="sub">Line sync 406 / 75 Mbit/s (VDSL)</div>
          <app-spark [values]="sparks().wan" [color]="palette[2]" />
        </div></div>
      </div>
      <div class="clr-col-12 clr-col-sm-6 clr-col-xl-3">
        <div class="card score"><div class="card-block">
          <div class="cap">MikroTik</div>
          <div class="big">{{ fmt(rtr().cpu, '%') }} <small>CPU</small></div>
          <div class="sub">
            <span class="label" [class.label-warning]="(rtr().temp ?? 0) > 70">{{ fmt(rtr().temp, 'C') }}</span>
            <span class="label">RAM {{ fmt(rtr().ram, '%') }}</span>
          </div>
          <app-spark [values]="sparks().cpu" [color]="palette[4]" />
        </div></div>
      </div>
    </div>

    <!-- Heatmap + top latency -->
    <div class="clr-row">
      <div class="clr-col-12 clr-col-lg-7">
        <div class="card"><div class="card-header head">
          <span class="cap">Device heatmap</span>
          <div class="btn-group btn-sm" role="group" aria-label="Color by">
            <button type="button" class="btn btn-sm" [class.btn-primary]="heat() === 'health'" [class.btn-outline]="heat() !== 'health'"
                    (click)="heat.set('health')">Health</button>
            <button type="button" class="btn btn-sm" [class.btn-primary]="heat() === 'latency'" [class.btn-outline]="heat() !== 'latency'"
                    (click)="heat.set('latency')">Latency</button>
          </div>
        </div><div class="card-block">
          <app-chart [options]="treemap()" height="210px" (itemClick)="openDevice($event.data)" />
          <div class="legend muted">
            @if (heat() === 'health') {
              <span><i [style.background]="health.good"></i>up</span><span><i [style.background]="health.warn"></i>degraded</span>
              <span><i [style.background]="health.bad"></i>down</span>
            } @else {
              <span><i [style.background]="health.good"></i>&lt; 10 ms</span><span><i [style.background]="health.warn"></i>10–40 ms</span>
              <span><i [style.background]="health.bad"></i>&gt; 40 ms</span>
            }
            · click a tile to open the device
          </div>
        </div></div>
      </div>
      <div class="clr-col-12 clr-col-lg-5">
        <div class="card"><div class="card-header head"><span class="cap">Top latency (ping)</span></div><div class="card-block">
          @for (d of topLatency(); track d.id) {
            <div class="toprow">
              <span class="name">{{ d.name }}</span>
              <div class="bar"><div [style.width.%]="d.share" [style.background]="latencyColor(d.ms)"></div></div>
              <span class="val">{{ fmt(d.ms, 'ms') }}</span>
              <app-spark [values]="d.spark" [color]="latencyColor(d.ms)" height="24px" />
            </div>
          } @empty { <p class="muted">No data yet.</p> }
        </div></div>
      </div>
    </div>

    <!-- Wi-Fi + interfaces -->
    <div class="clr-row">
      <div class="clr-col-12 clr-col-lg-6">
        <div class="card"><div class="card-header head"><span class="cap">Wi-Fi clients · signal</span>
          <span class="muted">{{ wifi().length }} connected</span></div><div class="card-block">
          <table class="table table-compact table-noborder wifi">
            <thead><tr><th class="left">Client</th><th class="left">Signal</th><th>Rate</th></tr></thead>
            <tbody>
              @for (c of wifi(); track c.mac) {
                <tr>
                  <td class="left">{{ c.name }}</td>
                  <td class="left">
                    <div class="sig"><div [style.width.%]="c.quality" [style.background]="signalColor(c.dbm)"></div></div>
                    <span class="mono">{{ c.dbm }} dBm</span>
                    @if (c.dbm < -70) { <span class="label label-warning">weak</span> }
                  </td>
                  <td>{{ fmt(c.rate, 'bps') }}</td>
                </tr>
              } @empty { <tr><td colspan="3" class="muted">No data (mktxp not running?)</td></tr> }
            </tbody>
          </table>
        </div></div>
      </div>
      <div class="clr-col-12 clr-col-lg-6">
        <div class="card"><div class="card-header head"><span class="cap">Interfaces · now</span></div><div class="card-block">
          <app-chart [options]="interfaces()" height="230px" />
        </div></div>
      </div>
    </div>

    <!-- Time series -->
    <div class="clr-row">
      <div class="clr-col-12 clr-col-xl-6">
        <div class="card"><div class="card-header head"><span class="cap">WAN throughput · {{ rangeLabel() }}</span></div><div class="card-block">
          <app-chart [options]="wanChart()" height="240px" />
        </div></div>
      </div>
      <div class="clr-col-12 clr-col-xl-6">
        <div class="card"><div class="card-header head"><span class="cap">Latency to the internet · {{ rangeLabel() }}</span></div><div class="card-block">
          <app-chart [options]="inetChart()" height="240px" />
        </div></div>
      </div>
      <div class="clr-col-12 clr-col-xl-6">
        <div class="card"><div class="card-header head"><span class="cap">Ping to devices · {{ rangeLabel() }}</span></div><div class="card-block">
          <app-chart [options]="pingChart()" height="240px" />
        </div></div>
      </div>
      <div class="clr-col-12 clr-col-xl-6">
        <div class="card"><div class="card-header head"><span class="cap">MikroTik CPU and temperature · {{ rangeLabel() }}</span></div><div class="card-block">
          <app-chart [options]="routerChart()" height="240px" />
        </div></div>
      </div>
    </div>
  `,
  styles: `
    .toolbar { display: flex; align-items: center; gap: 0.4rem; }
    .card { margin-top: 0.6rem; }
    .cap { font-size: 0.62rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; opacity: 0.75; }
    .head { display: flex; align-items: center; justify-content: space-between; padding: 0.45rem 0.9rem; font-size: 0.75rem; }
    .score .card-block { padding: 0.7rem 0.9rem 0.3rem; }
    .score .big { font-size: 1.55rem; font-weight: 500; line-height: 1.3; display: flex; align-items: center; gap: 0.35rem; flex-wrap: wrap; }
    .score .big small { font-size: 0.75rem; opacity: 0.7; margin-right: 0.4rem; }
    .score .sub { font-size: 0.7rem; opacity: 0.8; min-height: 1.2rem; }
    .dot { width: 0.6rem; height: 0.6rem; border-radius: 50%; display: inline-block; }
    .legend { font-size: 0.68rem; display: flex; gap: 0.8rem; flex-wrap: wrap; margin-top: 0.3rem; }
    .legend i { display: inline-block; width: 0.6rem; height: 0.6rem; border-radius: 2px; margin-right: 0.25rem; vertical-align: -1px; }
    .toprow { display: grid; grid-template-columns: 7rem 1fr 4rem 5rem; align-items: center; gap: 0.5rem; font-size: 0.75rem; padding: 0.2rem 0; }
    .toprow .name { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .toprow .val { text-align: right; font-variant-numeric: tabular-nums; }
    .bar, .sig { height: 0.45rem; border-radius: 3px; background: rgba(128,128,128,0.15); overflow: hidden; }
    .bar div, .sig div { height: 100%; border-radius: 3px; }
    .wifi td { vertical-align: middle; font-size: 0.75rem; white-space: nowrap; }
    .wifi .sig { display: inline-block; width: 6rem; vertical-align: middle; margin-right: 0.4rem; }
  `,
})
export class MetricsPage implements OnInit {
  private api = inject(Api);
  private router = inject(Router);
  private prefs = inject(Prefs);
  private destroyRef = inject(DestroyRef);
  private ticks = refreshTicks();

  protected ranges = RANGES;
  protected health = HEALTH;
  protected palette = PALETTE;
  protected minutes = signal(360);
  private minutes$ = toObservable(this.minutes);
  protected heat = signal<'health' | 'latency'>('health');
  protected loading = signal(true);
  private data = signal<Record<string, MetricResult>>({});
  private devices = signal<Device[]>([]);

  protected rangeLabel = computed(() => RANGES.find((r) => r.minutes === this.minutes())?.label ?? '');
  private dark = computed(() => this.prefs.effectiveTheme() === 'dark');

  protected counts = computed(() => {
    const c = { up: 0, degraded: 0, down: 0 };
    for (const r of inst(this.data()['up'])) {
      if (r.value >= 1) c.up++; else if (r.value > 0) c.degraded++; else c.down++;
    }
    return c;
  });
  protected availability = computed(() => one(this.data()['availability']));
  protected online = computed(() => { const v = one(this.data()['online']); return v == null ? null : v >= 1; });
  protected inetLatency = computed(() => one(this.data()['inetLatency']));
  protected wan = computed(() => ({ rx: one(this.data()['wanRx']), tx: one(this.data()['wanTx']) }));
  protected rtr = computed(() => ({
    cpu: one(this.data()['cpu']), temp: one(this.data()['temp']), ram: one(this.data()['ram']),
  }));

  protected sparks = computed(() => {
    const d = this.data();
    const first = (k: string) => rng(d[k])[0]?.values ?? [];
    return { availability: first('availabilityR'), internet: first('inetLatencyR'), wan: first('wanRxR'), cpu: first('cpuR') };
  });

  protected topLatency = computed(() => {
    const now = inst(this.data()['pingNow']);
    const series = rng(this.data()['pingR']);
    const max = Math.max(1, ...now.map((r) => r.value));
    return now
      .map((r) => {
        const dev = this.devices().find((d) => d.id === r.labels['device']);
        return {
          id: r.labels['device'], name: dev?.name ?? r.labels['device'], ms: r.value, share: (r.value / max) * 100,
          spark: series.find((s) => s.labels['device'] === r.labels['device'])?.values ?? [],
        };
      })
      .sort((a, b) => b.ms - a.ms);
  });

  protected wifi = computed(() => {
    const rates = inst(this.data()['wifiRate']);
    return inst(this.data()['wifi'])
      .map((r) => ({
        mac: r.labels['mac_address'], name: r.labels['dhcp_name'] || r.labels['mac_address'], dbm: r.value,
        quality: Math.max(5, Math.min(100, ((r.value + 90) / 60) * 100)),
        rate: rates.find((x) => x.labels['mac_address'] === r.labels['mac_address'])?.value ?? null,
      }))
      .sort((a, b) => a.dbm - b.dbm);
  });

  protected treemap = computed(() => {
    const ping = inst(this.data()['pingNow']);
    const byLatency = this.heat() === 'latency';
    const data = this.devices().map((d) => {
      const ms = ping.find((p) => p.labels['device'] === d.id)?.value ?? null;
      const color = byLatency ? (ms == null ? HEALTH.unknown : this.latencyColor(ms))
        : ({ up: HEALTH.good, degraded: HEALTH.warn, down: HEALTH.bad, unknown: HEALTH.unknown } as const)[d.state.status];
      return {
        name: d.name, value: 1, id: d.id, itemStyle: { color },
        label: { formatter: `{b|${d.name}}\n{s|${byLatency ? formatValue(ms ?? NaN, 'ms') : d.state.status}}` },
      };
    });
    return {
      tooltip: { formatter: (p: { name: string }) => p.name },
      series: [{
        type: 'treemap', roam: false, nodeClick: false, breadcrumb: { show: false },
        width: '100%', height: '100%', top: 0, left: 0,
        itemStyle: { borderColor: this.dark() ? '#1b2a32' : '#ffffff', borderWidth: 3, gapWidth: 3 },
        label: {
          show: true, color: '#fff',
          rich: { b: { fontSize: 14, fontWeight: 600, color: '#fff' }, s: { fontSize: 12, color: 'rgba(255,255,255,0.9)', padding: [4, 0, 0, 0] } },
          padding: [8, 10],
        },
        data,
      }],
    };
  });

  protected interfaces = computed(() => {
    const rx = inst(this.data()['ifRx']);
    const tx = inst(this.data()['ifTx']);
    const running = new Set(inst(this.data()['ifUp']).filter((r) => r.value >= 1).map((r) => r.labels['name']));
    const names = rx.map((r) => r.labels['name']).filter((n) => running.has(n) && !n.startsWith('lo')).sort();
    const val = (list: Instant, n: string) => list.find((r) => r.labels['name'] === n)?.value ?? 0;
    const grid = this.dark() ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.07)';
    return {
      grid: { left: 8, right: 12, top: 24, bottom: 4, containLabel: true },
      legend: { top: 0, right: 0, itemWidth: 10, itemHeight: 6, textStyle: { fontSize: 11 } },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, valueFormatter: (v: number) => formatValue(v, 'bps') },
      xAxis: { type: 'value', splitLine: { lineStyle: { color: grid } }, axisLabel: { fontSize: 10, formatter: (v: number) => formatValue(v, 'bps') } },
      yAxis: { type: 'category', data: names, axisLabel: { fontSize: 11 } },
      series: [
        { name: 'in', type: 'bar', data: names.map((n) => val(rx, n)), barGap: '10%', itemStyle: { borderRadius: [0, 3, 3, 0] } },
        { name: 'out', type: 'bar', data: names.map((n) => val(tx, n)), itemStyle: { borderRadius: [0, 3, 3, 0] } },
      ],
    };
  });

  protected wanChart = computed(() => timeSeriesOptions([
    { name: 'download', values: rng(this.data()['wanRxR'])[0]?.values ?? [] },
    { name: 'upload', values: rng(this.data()['wanTxR'])[0]?.values ?? [] },
  ], { unit: 'bps', area: true, dark: this.dark() }));

  protected inetChart = computed(() => timeSeriesOptions(
    rng(this.data()['inetTargetsR']).map((s) => ({ name: s.labels['instance'], values: s.values })),
    { unit: 'ms', dark: this.dark() }));

  protected pingChart = computed(() => timeSeriesOptions(
    rng(this.data()['pingR']).map((s) => ({
      name: this.devices().find((d) => d.id === s.labels['device'])?.name ?? s.labels['device'], values: s.values,
    })),
    { unit: 'ms', dark: this.dark() }));

  protected routerChart = computed(() => timeSeriesOptions([
    { name: 'CPU %', values: rng(this.data()['cpuR'])[0]?.values ?? [] },
    { name: '°C', values: rng(this.data()['tempR'])[0]?.values ?? [] },
  ], { dark: this.dark() }));

  ngOnInit(): void {
    combineLatest([this.ticks, this.minutes$]).pipe(
      switchMap(([, m]) => forkJoin([this.api.metrics(this.queries(m)), this.api.devices()])),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe(([data, devices]) => {
      this.data.set(data);
      this.devices.set(devices);
      this.loading.set(false);
    });
  }

  private queries(m: number): Record<string, MetricQuery> {
    const r = (q: string): MetricQuery => ({ q, minutes: m, points: 160 });
    const wanRx = 'rate(mktxp_interface_rx_byte_total{name="ether1"}[5m]) * 8';
    const wanTx = 'rate(mktxp_interface_tx_byte_total{name="ether1"}[5m]) * 8';
    return {
      up: { q: 'netops_device_up' },
      availability: { q: `avg_over_time(avg(netops_device_up)[${m}m:1m]) * 100` },
      availabilityR: r('avg(netops_device_up) * 100'),
      online: { q: 'max(probe_success{probe="internet"})' },
      inetLatency: { q: 'avg(probe_duration_seconds{probe="internet"}) * 1000' },
      inetLatencyR: r('avg(probe_duration_seconds{probe="internet"}) * 1000'),
      inetTargetsR: r('probe_duration_seconds{job="internet"} * 1000'),
      wanRx: { q: wanRx }, wanTx: { q: wanTx }, wanRxR: r(wanRx), wanTxR: r(wanTx),
      cpu: { q: 'max(mktxp_system_cpu_load)' }, cpuR: r('max(mktxp_system_cpu_load)'),
      temp: { q: 'max(mktxp_system_cpu_temperature)' }, tempR: r('max(mktxp_system_cpu_temperature)'),
      ram: { q: '100 * (1 - max(mktxp_system_free_memory) / max(mktxp_system_total_memory))' },
      pingNow: { q: 'netops_check_latency_ms{check="ping"}' }, pingR: r('netops_check_latency_ms{check="ping"}'),
      wifi: { q: 'mktxp_wlan_clients_signal_strength' }, wifiRate: { q: 'mktxp_wlan_clients_tx_rate_bps' },
      ifRx: { q: 'rate(mktxp_interface_rx_byte_total[5m]) * 8' },
      ifTx: { q: 'rate(mktxp_interface_tx_byte_total[5m]) * 8' },
      ifUp: { q: 'mktxp_interface_running' },
    };
  }

  protected fmt(v: number | null, unit: string): string {
    return v == null ? '–' : formatValue(v, unit);
  }

  protected latencyColor(ms: number): string {
    return ms < 10 ? HEALTH.good : ms < 40 ? HEALTH.warn : HEALTH.bad;
  }

  protected signalColor(dbm: number): string {
    return dbm >= -60 ? HEALTH.good : dbm >= -70 ? HEALTH.warn : HEALTH.bad;
  }

  protected openDevice(data: unknown): void {
    const id = (data as { id?: string })?.id;
    if (id) this.router.navigate(['/devices', id]);
  }
}
