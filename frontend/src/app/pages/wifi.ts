import { HttpClient } from '@angular/common/http';
import { DecimalPipe } from '@angular/common';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import {
  ClarityModule, ClrDatagridComparatorInterface, ClrDatagridNumericFilterInterface, ClrDatagridStringFilterInterface,
} from '@clr/angular';
import { firstValueFrom } from 'rxjs';
import { Chart, PALETTE } from '../charts';
import { errorText } from '../auth';

interface Radio {
  name: string; ssid: string; frequency: number; channel: number; phy: string; width_mhz: number;
  dfs: boolean; indoor: boolean; band: string; tx_power: number | null; peers: number; authorized: number;
}
interface Client {
  interface: string; mac: string; device_id: string | null; name: string; signal: number; band: string;
  phy: string; phy_label: string; uptime_s: number; tx_mbps: number; rx_mbps: number; issues: string[];
}
interface Neighbor {
  bssid: string; ssid: string; frequency: number; channel: number; band: string; width_mhz: number;
  signal: number; security: string; stations: number | null; note: string;
}
interface Finding { level: 'info' | 'warning' | 'danger'; radio: string; title: string; detail: string }
interface PlanCand {
  channel: number; frequency: number; width_mhz: number; dfs: boolean; note: string;
  networks: number; congestion: number; current: boolean; recommended: boolean;
}
interface BandPlan {
  band: string; current: Radio | null; recommended: PlanCand; change: boolean;
  candidates: PlanCand[]; reason: string;
}
interface WifiPlan { bands: BandPlan[]; command: string; rollback: string }
interface WifiSnap {
  available: boolean; error: string | null; time: number | null;
  radios: Radio[]; clients: Client[]; findings: Finding[]; score: number | null;
  neighbors: Neighbor[]; scan_time: number | null; plan: WifiPlan | null;
}

interface Ap { ssid: string; freq: number; width: number; signal: number; yours: boolean; ch: number }

@Component({
  selector: 'app-wifi',
  imports: [ClarityModule, RouterLink, DecimalPipe, Chart],
  template: `
    <div class="page-head">
      <h2>Wi-Fi <span class="muted">· RF optimizer</span></h2>
      <div class="head-actions">
        <button class="btn btn-sm btn-outline" [disabled]="busy()" (click)="load()">
          <cds-icon shape="refresh"></cds-icon> {{ busy() ? 'Reading…' : 'Refresh' }}</button>
        <button class="btn btn-sm btn-primary" [disabled]="scanning()" (click)="scan()" title="Briefly interrupts Wi-Fi while each radio hops channels">
          <cds-icon shape="radar"></cds-icon> {{ scanning() ? 'Scanning…' : 'Scan neighbours' }}</button>
      </div>
    </div>
    <p class="muted">Live radios and associated clients read from the router, plus the networks around you.
      Channel, width, signal and PHY rate per client, with the things worth fixing called out. Read-only.</p>

    @if (snap(); as s) {
      @if (!s.available) {
        <clr-alert clrAlertType="info" [clrAlertClosable]="false"><clr-alert-item>
          <span class="alert-text">{{ s.error || 'No Wi-Fi data.' }} Turn on the <strong>RF optimizer</strong>
            feature and make sure the router vault is unlocked.</span>
        </clr-alert-item></clr-alert>
      } @else {
        <div class="clr-row">
          <div class="clr-col-6 clr-col-md-3"><div class="card stat"><div class="card-block">
            <div class="n" [class.bad]="(s.score ?? 100) < 70">{{ s.score }}<small>/100</small></div>
            <div class="l">Wi-Fi health · {{ scoreLabel(s.score) }}</div></div></div></div>
          @for (r of s.radios; track r.name) {
            <div class="clr-col-6 clr-col-md-3"><div class="card stat"><div class="card-block">
              <div class="n">{{ r.band }}<small> GHz · ch {{ r.channel }}</small></div>
              <div class="l">{{ r.ssid }} · {{ r.width_mhz }} MHz · {{ r.peers }} client(s)
                @if (r.dfs) { <span class="label label-warning">DFS</span> }
                @if (r.tx_power !== null) { · {{ r.tx_power }} dBm }</div>
            </div></div></div>
          }
        </div>

        @for (f of s.findings; track f.title) {
          <clr-alert [clrAlertType]="f.level" [clrAlertClosable]="false" clrAlertSize="sm">
            <clr-alert-item><span class="alert-text"><strong>{{ f.title }}</strong> — {{ f.detail }}</span></clr-alert-item>
          </clr-alert>
        }
        @if (msg(); as m) {
          <clr-alert clrAlertType="danger" [clrAlertClosable]="true" (clrAlertClosedChange)="msg.set(null)" clrAlertSize="sm">
            <clr-alert-item><span class="alert-text">{{ m }}</span></clr-alert-item></clr-alert>
        }

        @if (s.plan; as plan) {
          <h3>Channel plan <span class="muted">· recommended settings</span></h3>
          <p class="muted">Ranked from the networks around you — lower congestion is better. The pick is the
            solid green bar; your current channel is outlined in blue. Applying is still a manual step: copy the
            command below and run it on the router.
            @if (!s.scan_time) { <strong>Scan neighbours first</strong> so the ranking has data to work with. }</p>
          @for (b of planCharts(); track b.band) {
            <div class="card plan"><div class="card-block">
              <div class="plan-head">
                <span class="band">{{ b.band }} GHz</span>
                @if (b.current) {
                  <span class="cur">now ch {{ b.current.channel }} · {{ b.current.width_mhz }} MHz</span>
                } @else { <span class="cur">radio off</span> }
                <span class="arrow">→</span>
                <span class="rec">ch {{ b.recommended.channel }} · {{ b.recommended.width_mhz }} MHz</span>
                @if (b.change) { <span class="label label-warning">change</span> }
                @else { <span class="label label-success">already optimal</span> }
              </div>
              <p class="reason">{{ b.reason }}</p>
              <app-chart [options]="b.chart" height="190px" />
            </div></div>
          }
          @if (plan.command) {
            <div class="card apply"><div class="card-block">
              <div class="cl">Apply — run on the router (the dashboard can't change Wi-Fi settings itself):</div>
              <pre class="cmd">ssh mikrotik '{{ plan.command }}'</pre>
              <div class="cl">Roll back to router-managed auto:</div>
              <pre class="cmd">ssh mikrotik '{{ plan.rollback }}'</pre>
            </div></div>
          }
        }

        <h3>Spectrum</h3>
        @if (s.neighbors.length || s.radios.length) {
          <p class="muted">Each hump is one network, centred on its channel and as wide as its channel width;
            taller = stronger. Yours are drawn bold. @if (s.scan_time) { Neighbours scanned {{ ago(s.scan_time) }}. }
            @else { Press <strong>Scan neighbours</strong> to fill in the networks around you. }</p>
          <div class="clr-row">
            <div class="clr-col-12 clr-col-lg-6">
              <div class="card"><div class="card-block"><app-chart [options]="spectrum24()" height="260px" /></div></div>
            </div>
            <div class="clr-col-12 clr-col-lg-6">
              <div class="card"><div class="card-block"><app-chart [options]="spectrum5()" height="260px" /></div></div>
            </div>
          </div>

          <p class="muted">How crowded each channel is — yours in bold blue. On 2.4 GHz only 1 / 6 / 11
            don't overlap, so you want yours on the emptiest of those three.</p>
          <div class="clr-row">
            <div class="clr-col-12 clr-col-lg-6">
              <div class="card"><div class="card-block"><app-chart [options]="occ24()" height="200px" /></div></div>
            </div>
            <div class="clr-col-12 clr-col-lg-6">
              <div class="card"><div class="card-block"><app-chart [options]="occ5()" height="200px" /></div></div>
            </div>
          </div>
        }

        @if (s.neighbors.length) {
          <h3>Neighbouring networks ({{ s.neighbors.length }})</h3>
          <clr-datagrid>
            <clr-dg-column [clrDgField]="'ssid'">SSID
              <clr-dg-string-filter [clrDgStringFilter]="ssidFilter"></clr-dg-string-filter>
            </clr-dg-column>
            <clr-dg-column [clrDgField]="'band'">Band</clr-dg-column>
            <clr-dg-column [clrDgField]="'channel'">Channel
              <clr-dg-numeric-filter [clrDgNumericFilter]="chFilter"></clr-dg-numeric-filter>
            </clr-dg-column>
            <clr-dg-column [clrDgField]="'width_mhz'">Width</clr-dg-column>
            <clr-dg-column [clrDgField]="'signal'" [clrDgSortOrder]="-1">Signal</clr-dg-column>
            <clr-dg-column [clrDgField]="'security'">
              <ng-container *clrDgHideableColumn="{ hidden: true }">Security</ng-container>
            </clr-dg-column>
            <clr-dg-row *clrDgItems="let n of s.neighbors" [clrDgItem]="n">
              <clr-dg-cell>{{ n.ssid }}
                @if (n.note) { <span class="label label-info">{{ n.note }}</span> }
                <div class="mono sub">{{ n.bssid }}</div></clr-dg-cell>
              <clr-dg-cell>{{ n.band }} GHz</clr-dg-cell>
              <clr-dg-cell>{{ n.channel }}</clr-dg-cell>
              <clr-dg-cell>{{ n.width_mhz }} MHz</clr-dg-cell>
              <clr-dg-cell>
                <div class="sig"><span class="sig-bar" [style.width.%]="sigPct(n.signal)" [style.background]="sigColor(n.signal)"></span></div>
                <span class="mono sub">{{ n.signal }} dBm</span></clr-dg-cell>
              <clr-dg-cell class="mono sub">{{ n.security }}</clr-dg-cell>
            </clr-dg-row>
            <clr-dg-placeholder>No neighbouring networks — run a scan.</clr-dg-placeholder>
            <clr-dg-footer>
              <clr-dg-pagination #npg [clrDgPageSize]="10">
                <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50]">per page</clr-dg-page-size>
                {{ npg.firstItem + 1 }}–{{ npg.lastItem + 1 }} of {{ npg.totalItems }}
              </clr-dg-pagination>
            </clr-dg-footer>
          </clr-datagrid>
        }

        <h3>Your clients ({{ s.clients.length }})</h3>
        <clr-datagrid [clrDgLoading]="busy()">
          <clr-dg-column [clrDgField]="'name'">Device</clr-dg-column>
          <clr-dg-column [clrDgField]="'band'">Band</clr-dg-column>
          <clr-dg-column [clrDgField]="'phy_label'">
            <ng-container *clrDgHideableColumn="{ hidden: false }">PHY</ng-container>
          </clr-dg-column>
          <clr-dg-column [clrDgField]="'signal'" [clrDgSortOrder]="-1">Signal</clr-dg-column>
          <clr-dg-column [clrDgSortBy]="rateSort" class="right">
            <ng-container *clrDgHideableColumn="{ hidden: false }">Tx / Rx</ng-container>
          </clr-dg-column>
          <clr-dg-column>
            <ng-container *clrDgHideableColumn="{ hidden: false }">Notes</ng-container>
          </clr-dg-column>
          <clr-dg-row *clrDgItems="let c of s.clients" [clrDgItem]="c">
            <clr-dg-cell>
              @if (c.device_id) { <a [routerLink]="['/devices', c.device_id]">{{ c.name }}</a> }
              @else { {{ c.name }} }
              <div class="mono sub">{{ c.mac }}</div>
            </clr-dg-cell>
            <clr-dg-cell>{{ c.band }} GHz</clr-dg-cell>
            <clr-dg-cell>{{ c.phy_label }}</clr-dg-cell>
            <clr-dg-cell>
              <div class="sig"><span class="sig-bar" [style.width.%]="sigPct(c.signal)" [style.background]="sigColor(c.signal)"></span></div>
              <span class="mono sub">{{ c.signal }} dBm</span>
            </clr-dg-cell>
            <clr-dg-cell class="right mono">{{ c.tx_mbps | number: '1.0-0' }} / {{ c.rx_mbps | number: '1.0-0' }}</clr-dg-cell>
            <clr-dg-cell>
              @for (i of c.issues; track i) { <span class="label" [class.label-warning]="i !== 'legacy device (airtime-expensive)'">{{ i }}</span> }
            </clr-dg-cell>
          </clr-dg-row>
          <clr-dg-placeholder>No associated clients.</clr-dg-placeholder>

          <ng-template [(clrIfDetail)]="clientDetail" let-c>
            <clr-dg-detail>
              <clr-dg-detail-header>{{ c.name }} <span class="muted">· {{ c.band }} GHz · {{ c.phy_label }}</span></clr-dg-detail-header>
              <clr-dg-detail-body>
                <dl class="detail-kv">
                  <dt>MAC</dt><dd class="mono">{{ c.mac }}</dd>
                  <dt>Interface</dt><dd class="mono">{{ c.interface }}</dd>
                  <dt>Signal</dt><dd>{{ c.signal }} dBm</dd>
                  <dt>Uptime</dt><dd>{{ fmtUptime(c.uptime_s) }}</dd>
                  <dt>Tx / Rx</dt><dd>{{ c.tx_mbps | number: '1.0-0' }} / {{ c.rx_mbps | number: '1.0-0' }} Mbit/s</dd>
                  <dt>Device</dt>
                  <dd>@if (c.device_id) { <a [routerLink]="['/devices', c.device_id]">open device page</a> } @else { not in inventory }</dd>
                  @if (c.issues.length) {
                    <dt>Issues</dt>
                    <dd>@for (i of c.issues; track i) { <span class="label" [class.label-warning]="i !== 'legacy device (airtime-expensive)'">{{ i }}</span> }</dd>
                  }
                </dl>
              </clr-dg-detail-body>
            </clr-dg-detail>
          </ng-template>

          <clr-dg-footer>
            <clr-dg-pagination #cpg [clrDgPageSize]="25">
              <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50]">per page</clr-dg-page-size>
              {{ cpg.firstItem + 1 }}–{{ cpg.lastItem + 1 }} of {{ cpg.totalItems }}
            </clr-dg-pagination>
          </clr-dg-footer>
        </clr-datagrid>
        <p class="muted">Snapshot taken {{ ago(s.time) }}.</p>
      }
    } @else { <clr-progress-bar [clrLoop]="true"></clr-progress-bar> }
  `,
  styles: `
    h2 .muted { font-weight: 400; font-size: 1rem; }
    .head-actions { display: flex; gap: 0.6rem; align-items: center; }
    .sub { font-size: 0.72rem; opacity: 0.7; }
    .sig { width: 72px; height: 6px; border-radius: 3px; background: var(--clr-color-neutral-300, #e0e0e0); overflow: hidden; display: inline-block; vertical-align: middle; margin-right: 0.4rem; }
    .sig-bar { display: block; height: 100%; }
    .label { margin: 0 0.2rem 0.2rem 0; }
    .card.plan { margin-top: 0.5rem; }
    .plan-head { display: flex; align-items: center; flex-wrap: wrap; gap: 0.5rem; }
    .plan-head .band { font-size: 1.05rem; font-weight: 600; }
    .plan-head .cur { opacity: 0.7; }
    .plan-head .arrow { opacity: 0.5; }
    .plan-head .rec { font-weight: 600; color: #3a7d00; }
    .reason { margin: 0.3rem 0 0.4rem; font-size: 0.85rem; }
    .card.apply .cl { font-size: 0.8rem; font-weight: 600; margin-bottom: 0.2rem; }
    .cmd { background: var(--clr-color-neutral-100, #f3f3f3); border-radius: 4px; padding: 0.5rem 0.7rem;
      font-size: 0.78rem; overflow-x: auto; margin: 0 0 0.7rem; white-space: pre; }
    .detail-kv { display: grid; grid-template-columns: max-content 1fr; gap: 0.35rem 1rem; margin: 0; }
    .detail-kv dt { font-weight: 600; opacity: 0.7; }
    .detail-kv dd { margin: 0; }
  `,
})
export class WifiPage implements OnInit {
  private http = inject(HttpClient);
  protected snap = signal<WifiSnap | null>(null);
  protected busy = signal(false);
  protected scanning = signal(false);
  protected msg = signal<string | null>(null);
  protected clientDetail: Client | null = null;

  // Datagrid sort/filter helpers (Clarity advanced datagrid).
  protected rateSort: ClrDatagridComparatorInterface<Client> = {
    compare: (a, b) => Math.max(a.tx_mbps, a.rx_mbps) - Math.max(b.tx_mbps, b.rx_mbps),
  };
  protected ssidFilter: ClrDatagridStringFilterInterface<Neighbor> = {
    accepts: (n, search) => (n.ssid + ' ' + n.bssid).toLowerCase().includes(search.toLowerCase()),
  };
  protected chFilter: ClrDatagridNumericFilterInterface<Neighbor> = {
    accepts: (n, low, high) => (low == null || n.channel >= low) && (high == null || n.channel <= high),
  };

  protected spectrum24 = computed(() => this.spectrum('2.4'));
  protected spectrum5 = computed(() => this.spectrum('5'));
  protected occ24 = computed(() => this.occupancy('2.4'));
  protected occ5 = computed(() => this.occupancy('5'));
  // One chart per band, rebuilt only when the snapshot changes (stable refs keep ECharts from re-rendering each CD).
  protected planCharts = computed(() =>
    (this.snap()?.plan?.bands ?? []).map((b) => ({ ...b, chart: this.planChart(b) })));

  ngOnInit(): void {
    this.load();
  }

  protected load(): void {
    this.busy.set(true);
    this.http.get<WifiSnap>('/api/wifi').subscribe({
      next: (s) => { this.snap.set(s); this.busy.set(false); },
      error: () => this.busy.set(false),
    });
  }

  protected async scan(): Promise<void> {
    this.scanning.set(true);
    try {
      await firstValueFrom(this.http.post('/api/wifi/scan', {}));
      this.load();
    } catch (e) {
      this.msg.set(errorText(e));
    } finally {
      this.scanning.set(false);
    }
  }

  /** The WiFi-analyzer spectrum: one smooth hump per network, centred on its channel, width = channel width. */
  private spectrum(band: '2.4' | '5') {
    const s = this.snap();
    const FLOOR = -95;
    const range = band === '2.4' ? [2400, 2490] : [5140, 5900];
    const aps: Ap[] = [];
    (s?.neighbors || []).filter((n) => n.band === band).forEach((n) =>
      aps.push({ ssid: n.ssid, freq: n.frequency, width: n.width_mhz, signal: n.signal, yours: false, ch: n.channel }));
    (s?.radios || []).filter((r) => r.band === band).forEach((r) =>
      aps.push({ ssid: r.ssid + ' (you)', freq: r.frequency, width: r.width_mhz, signal: -35, yours: true, ch: r.channel }));

    const series = aps.map((a, i) => {
      const half = Math.max(10, a.width / 2);
      const color = a.yours ? '#0079ad' : PALETTE[i % PALETTE.length];
      return {
        name: `${a.ssid} · ch ${a.ch} · ${a.width}MHz`, type: 'line', smooth: true,
        // a symbol only at the peak (0-size on the two baseline points) gives the SSID label an anchor to draw on.
        symbol: 'circle', symbolSize: (v: number[]) => (Array.isArray(v) && v[1] === FLOOR ? 0 : a.yours ? 8 : 6),
        itemStyle: { color },
        lineStyle: { width: a.yours ? 2.6 : 1.2, color, opacity: a.yours ? 1 : 0.85 },
        areaStyle: { color, opacity: a.yours ? 0.2 : 0.07 },
        emphasis: { focus: 'series' }, z: a.yours ? 5 : 1,
        labelLayout: { hideOverlap: true },        // keep the strongest name when humps crowd together
        data: [
          [a.freq - half, FLOOR],
          { value: [a.freq, a.signal], label: {
            show: true, position: 'top', distance: 4, formatter: a.ssid,
            fontSize: 10, fontWeight: a.yours ? 700 : 400, color } },
          [a.freq + half, FLOOR],
        ],
      };
    });

    return {
      animation: false,
      title: { text: `${band} GHz spectrum`, left: 'center', top: 4, textStyle: { fontSize: 13, fontWeight: 600 } },
      grid: { left: 8, right: 16, top: 34, bottom: 26, containLabel: true },
      tooltip: { trigger: 'item', confine: true, formatter: (p: { seriesName: string; value: number[] | number }) =>
        `${p.seriesName}<br>${(Array.isArray(p.value) ? p.value[1] : p.value)} dBm` },
      xAxis: { type: 'value', min: range[0], max: range[1], name: `${band} GHz (MHz)`, nameLocation: 'middle',
        nameGap: 28, axisLabel: { fontSize: 10 }, splitLine: { show: false } },
      yAxis: { type: 'value', min: FLOOR, max: -15, axisLabel: { formatter: '{value} dBm', fontSize: 10 } },
      series,
    };
  }

  /** The congestion ranking behind a band's recommendation: lower bar = clearer channel. */
  private planChart(b: BandPlan) {
    const cats = b.candidates.map((c) => 'ch ' + c.channel);
    const data = b.candidates.map((c) => ({
      value: c.congestion,
      itemStyle: {
        color: c.recommended ? '#60b515' : c.dfs ? '#c47400' : '#49afd9',
        borderColor: c.current ? '#0079ad' : 'transparent', borderWidth: c.current ? 2 : 0,
        borderRadius: [3, 3, 0, 0],
      },
    }));
    return {
      animation: false,
      title: { text: `${b.band} GHz — channel congestion`, left: 'center', top: 4, textStyle: { fontSize: 13, fontWeight: 600 } },
      grid: { left: 8, right: 12, top: 34, bottom: 24, containLabel: true },
      tooltip: {
        trigger: 'item', confine: true,
        formatter: (p: { dataIndex: number }) => {
          const c = b.candidates[p.dataIndex];
          return `<strong>channel ${c.channel}</strong> · ${c.width_mhz} MHz<br>congestion ${c.congestion}` +
            `<br>${c.networks} network(s) overlapping` +
            (c.note ? `<br><span style="opacity:.7">${c.note}</span>` : '') +
            (c.recommended ? '<br>★ recommended' : '') + (c.current ? '<br>● current' : '');
        },
      },
      xAxis: { type: 'category', data: cats, axisLabel: { fontSize: 10 } },
      yAxis: { type: 'value', minInterval: 1, name: 'congestion', nameTextStyle: { fontSize: 10 },
        axisLabel: { fontSize: 10 }, splitLine: { show: true } },
      series: [{
        type: 'bar', data, barMaxWidth: 46,
        label: { show: true, position: 'top', fontSize: 10, formatter: (p: { value: number }) => p.value },
      }],
    };
  }

  /** Count of networks sitting on each channel, with your own channel highlighted. */
  private occupancy(band: '2.4' | '5') {
    const s = this.snap();
    const aps: { ch: number; ssid: string; yours: boolean }[] = [];
    (s?.neighbors || []).filter((n) => n.band === band).forEach((n) => aps.push({ ch: n.channel, ssid: n.ssid, yours: false }));
    (s?.radios || []).filter((r) => r.band === band).forEach((r) => aps.push({ ch: r.channel, ssid: r.ssid, yours: true }));

    const byCh = new Map<string, { ssid: string; yours: boolean }[]>();
    const yoursCh = new Set<number>();
    aps.forEach((a) => {
      (byCh.get(String(a.ch)) ?? byCh.set(String(a.ch), []).get(String(a.ch))!).push(a);
      if (a.yours) yoursCh.add(a.ch);
    });

    const cats = band === '2.4'
      ? Array.from({ length: 11 }, (_, i) => String(i + 1))
      : [...new Set(aps.map((a) => a.ch))].sort((x, y) => x - y).map(String);

    const data = cats.map((c) => ({
      value: byCh.get(c)?.length ?? 0,
      itemStyle: { color: yoursCh.has(+c) ? '#0079ad' : '#49afd9', borderRadius: [3, 3, 0, 0] },
    }));

    return {
      animation: false,
      title: { text: `${band} GHz — networks per channel`, left: 'center', top: 4, textStyle: { fontSize: 13, fontWeight: 600 } },
      grid: { left: 8, right: 12, top: 34, bottom: 26, containLabel: true },
      tooltip: {
        trigger: 'item', confine: true,
        formatter: (p: { name: string }) => {
          const list = byCh.get(p.name) || [];
          return `<strong>channel ${p.name}</strong><br>` +
            (list.length ? list.map((x) => (x.yours ? '● ' : '') + x.ssid).join('<br>') : 'empty');
        },
      },
      xAxis: { type: 'category', data: cats, name: `${band} GHz channel`, nameLocation: 'middle', nameGap: 24, axisLabel: { fontSize: 10 } },
      yAxis: { type: 'value', minInterval: 1, axisLabel: { fontSize: 10 }, splitLine: { show: true } },
      series: [{
        type: 'bar', data, barMaxWidth: 30,
        label: { show: true, position: 'top', fontSize: 10, formatter: (p: { value: number }) => p.value || '' },
      }],
    };
  }

  protected scoreLabel(n: number | null): string {
    if (n === null) return '—';
    return n >= 85 ? 'good' : n >= 70 ? 'fair' : n >= 50 ? 'poor' : 'bad';
  }

  protected sigPct(dbm: number): number {
    return Math.max(0, Math.min(100, Math.round(((dbm + 90) / 60) * 100)));
  }

  protected sigColor(dbm: number): string {
    return dbm >= -55 ? '#62a420' : dbm >= -67 ? '#60b515' : dbm >= -75 ? '#efc006' : '#e12200';
  }

  protected fmtUptime(s: number): string {
    if (!s) return '—';
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
  }

  protected ago(t: number | null): string {
    if (!t) return 'just now';
    const s = Math.max(0, Math.round(Date.now() / 1000 - t));
    return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : `${Math.round(s / 3600)}h ago`;
  }
}
