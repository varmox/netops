import { HttpClient } from '@angular/common/http';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { firstValueFrom } from 'rxjs';
import { errorText } from '../auth';
import { Chart } from '../charts';
import { AgoPipe, BytesPipe } from '../ui';

interface MapNode {
  id: string; name: string; category: string; ip?: string; mac?: string; vendor?: string;
  type?: string; status?: string; port?: string | null; device_id?: string | null;
}
interface Graph {
  time: number | null; topology?: string;
  counts?: { devices: number; unknown: number; ports: number };
  nodes: MapNode[]; links: { source: string; target: string }[];
}
interface Flow { source: string; target: string; conns: number; bytes: number }
interface Ext { device: string; device_name: string; bytes: number; conns: number; top: [string, number][] }
interface Traffic { time: number | null; flows: Flow[]; external: Ext[]; counts?: { flows: number; internal: number; external: number; conntrack: number } }

const CATS = ['router', 'port', 'device', 'unknown', 'internet'];
const STATUS_COLOR: Record<string, string> = { up: '#62a420', down: '#e12200', degraded: '#efc006', unknown: '#8c8c8c' };
const CAT_COLOR: Record<string, string> = { router: '#0079ad', port: '#49afd9', internet: '#8939ad', unknown: '#8c8c8c' };
const CAT_SIZE: Record<string, number> = { router: 46, internet: 34, port: 16, device: 28, unknown: 24 };

@Component({
  selector: 'app-map',
  imports: [ClarityModule, Chart, AgoPipe, BytesPipe],
  template: `
    <div class="page-head">
      <h2>Network map</h2>
      <div class="head-actions">
        <div class="btn-group btn-sm">
          <button class="btn" [class.btn-primary]="layer() === 'physical'" [class.btn-outline]="layer() !== 'physical'" (click)="layer.set('physical')">Physical</button>
          <button class="btn" [class.btn-primary]="layer() === 'traffic'" [class.btn-outline]="layer() !== 'traffic'" (click)="layer.set('traffic')">Traffic</button>
        </div>
        <button class="btn btn-sm btn-outline" [disabled]="busy()" (click)="rescan()">
          <cds-icon shape="refresh"></cds-icon> {{ busy() ? 'Scanning…' : 'Rescan' }}</button>
      </div>
    </div>

    @if (graph(); as g) {
      @if (g.nodes.length > 1) {
        @if (layer() === 'physical') {
          <p class="muted">{{ g.counts?.devices }} devices ({{ g.counts?.unknown }} unknown) on {{ g.counts?.ports }} ports ·
            from {{ topologyLabel(g.topology) }} · built {{ g.time | ago }}. Drag nodes, scroll to zoom, click a known device.</p>
          <div class="legend">
            <span><i class="dot" style="background:#0079ad"></i> router</span><span><i class="dot" style="background:#49afd9"></i> port</span>
            <span><i class="dot" style="background:#62a420"></i> up</span><span><i class="dot" style="background:#e12200"></i> down</span>
            <span><i class="dot" style="background:#8c8c8c"></i> unknown</span>
          </div>
        } @else {
          <p class="muted">Who talks to whom, from the router's connection tracking. Arrows point from source to
            destination; thicker = more bytes. External traffic collapses into the Internet node.
            @if (traffic(); as t) { {{ t.counts?.internal }} internal · {{ t.counts?.external }} to internet · built {{ t.time | ago }}. }</p>
        }
        <div class="card"><div class="card-block">
          <app-chart [options]="options()" height="620px" (itemClick)="open($event)" />
        </div></div>

        @if (layer() === 'traffic' && traffic()?.external?.length) {
          <h3>Top talkers to the internet</h3>
          <clr-datagrid>
            <clr-dg-column>Device</clr-dg-column><clr-dg-column>Traffic</clr-dg-column><clr-dg-column>Connections</clr-dg-column><clr-dg-column>Top destinations</clr-dg-column>
            @for (e of traffic()!.external; track e.device) {
              <clr-dg-row><clr-dg-cell>{{ e.device_name }}</clr-dg-cell><clr-dg-cell>{{ e.bytes | bytes }}</clr-dg-cell>
                <clr-dg-cell>{{ e.conns }}</clr-dg-cell>
                <clr-dg-cell class="mono">@for (d of e.top; track d[0]) { <span class="dst">{{ d[0] }}</span> }</clr-dg-cell></clr-dg-row>
            }
          </clr-datagrid>
        }
      } @else {
        <clr-alert clrAlertType="info" [clrAlertClosable]="false"><clr-alert-item>
          <span class="alert-text">No map yet. Turn on the <strong>Network map</strong> feature, then press <strong>Rescan</strong>.</span>
        </clr-alert-item></clr-alert>
      }
    }
    @if (msg(); as m) { <clr-alert clrAlertType="danger" [clrAlertClosable]="true" (clrAlertClosedChange)="msg.set(null)"><clr-alert-item><span class="alert-text">{{ m }}</span></clr-alert-item></clr-alert> }
  `,
  styles: `
    .head-actions { display: flex; gap: 0.6rem; align-items: center; }
    .dst { margin-right: 0.6rem; }
  `,
})
export class MapPage implements OnInit {
  private http = inject(HttpClient);
  private router = inject(Router);
  protected graph = signal<Graph | null>(null);
  protected traffic = signal<Traffic | null>(null);
  protected layer = signal<'physical' | 'traffic'>('physical');
  protected busy = signal(false);
  protected msg = signal<string | null>(null);

  protected options = computed(() => (this.layer() === 'traffic' ? this.trafficOption() : this.physicalOption()));

  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    this.http.get<Graph>('/api/netmap').subscribe((g) => this.graph.set(g));
    this.http.get<Traffic>('/api/netmap/traffic').subscribe((t) => this.traffic.set(t));
  }

  protected topologyLabel(t?: string): string {
    return { router: 'the router (ports)', leases: 'DHCP leases', inventory: 'the inventory' }[t ?? ''] ?? t ?? '—';
  }

  protected async rescan(): Promise<void> {
    this.busy.set(true);
    try {
      await firstValueFrom(this.http.post('/api/netmap/scan', {}));
      setTimeout(() => { this.load(); this.busy.set(false); }, 4000);
    } catch (e) {
      this.msg.set(errorText(e));
      this.busy.set(false);
    }
  }

  protected open(ev: { name: string; data: unknown }): void {
    const n = ev.data as MapNode | undefined;
    if (n?.device_id) this.router.navigate(['/devices', n.device_id]);
  }

  private physicalOption() {
    const g = this.graph();
    if (!g) return {};
    const color = (n: MapNode) =>
      n.category === 'device' || n.category === 'unknown' ? STATUS_COLOR[n.status ?? 'unknown'] : CAT_COLOR[n.category];
    return {
      tooltip: { formatter: (p: { dataType: string; data: MapNode }) => this.nodeTip(p) },
      series: [{
        type: 'graph', layout: 'force', roam: true, draggable: true, zoom: 1.1,
        force: { repulsion: 190, edgeLength: [40, 130], gravity: 0.08 },
        label: { show: true, position: 'right', fontSize: 11 }, emphasis: { focus: 'adjacency' },
        categories: CATS.map((name) => ({ name })),
        lineStyle: { color: 'source', opacity: 0.5, width: 1.3 },
        data: g.nodes.map((n) => ({ ...n, category: CATS.indexOf(n.category), symbolSize: CAT_SIZE[n.category] ?? 22, itemStyle: { color: color(n) } })),
        links: g.links.map((l) => ({ source: l.source, target: l.target })),
      }],
    };
  }

  private trafficOption() {
    const g = this.graph();
    const t = this.traffic();
    if (!g || !t) return {};
    // Traffic view uses the device/router/internet nodes (ports aren't traffic endpoints).
    const nodes = g.nodes.filter((n) => n.category !== 'port');
    const used = new Set<string>();
    t.flows.forEach((f) => { used.add(f.source); used.add(f.target); });
    const color = (n: MapNode) =>
      n.category === 'device' || n.category === 'unknown' ? STATUS_COLOR[n.status ?? 'unknown'] : CAT_COLOR[n.category];
    const max = Math.max(1, ...t.flows.map((f) => f.bytes));
    const width = (b: number) => 1 + 6 * (Math.log10(b + 1) / Math.log10(max + 1));
    return {
      tooltip: {
        formatter: (p: { dataType: string; data: MapNode & Flow }) =>
          p.dataType === 'edge'
            ? `${this.name(p.data.source)} → ${this.name(p.data.target)}<br>${this.fmtBytes(p.data.bytes)} · ${p.data.conns} connections`
            : this.nodeTip(p),
      },
      series: [{
        type: 'graph', layout: 'force', roam: true, draggable: true, zoom: 1.1,
        force: { repulsion: 220, edgeLength: [60, 160], gravity: 0.06 },
        label: { show: true, position: 'right', fontSize: 11 }, emphasis: { focus: 'adjacency' },
        categories: CATS.map((name) => ({ name })),
        edgeSymbol: ['none', 'arrow'], edgeSymbolSize: 7,
        data: nodes.map((n) => ({
          ...n, category: CATS.indexOf(n.category), symbolSize: CAT_SIZE[n.category] ?? 22,
          itemStyle: { color: color(n), opacity: used.has(n.id) ? 1 : 0.35 },
        })),
        links: t.flows.map((f) => ({ source: f.source, target: f.target, bytes: f.bytes, conns: f.conns, lineStyle: { width: width(f.bytes), opacity: 0.6, curveness: 0.1 } })),
      }],
    };
  }

  private name(id: string): string {
    return this.graph()?.nodes.find((n) => n.id === id)?.name ?? id;
  }

  private nodeTip(p: { dataType: string; data: MapNode }): string {
    if (p.dataType !== 'node') return '';
    const n = p.data;
    const rows = [['IP', n.ip], ['MAC', n.mac], ['Vendor', n.vendor], ['Type', n.type], ['Status', n.status], ['Port', n.port]]
      .filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`);
    return `<strong>${n.name}</strong>` + (rows.length ? '<br>' + rows.join('<br>') : '');
  }

  private fmtBytes(n: number): string {
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
  }
}
