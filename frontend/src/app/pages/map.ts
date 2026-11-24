import { HttpClient } from '@angular/common/http';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { firstValueFrom } from 'rxjs';
import { errorText } from '../auth';
import { Chart } from '../charts';
import { AgoPipe, BytesPipe } from '../ui';

interface MapNode {
  id: string; name: string; category: string; ip?: string; mac?: string; vendor?: string;
  type?: string; status?: string; port?: string | null; port_manual?: boolean; device_id?: string | null;
}
interface Graph {
  time: number | null; topology?: string; iface_options?: string[];
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
const ICONS: Record<string, string> = {
  mikrotik: 'router', zyxel: 'router', linux: 'host', tv: 'display', speaker: 'volume-up',
  camera: 'video-camera', phone: 'mobile',
};

@Component({
  selector: 'app-map',
  imports: [ClarityModule, FormsModule, Chart, AgoPipe, BytesPipe],
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
          <!-- ===== Static physical topology, grouped by interface ===== -->
          <p class="muted">Which device hangs off which router interface · from {{ topologyLabel(g.topology) }} · built {{ g.time | ago }}.
            @if (phys()?.unassignedCount) { <strong>{{ phys()!.unassignedCount }}</strong> device(s) have no detected interface — click the port tag to set it. }
          </p>
          @if (phys(); as p) {
            <div class="card"><div class="card-block topo-wrap">
              <div class="topo">
                <div class="node net"><cds-icon shape="network-globe" size="20"></cds-icon> Internet</div>
                <div class="drop"></div>
                @if (p.router; as r) {
                  <div class="node router" [class.clickable]="r.device_id" (click)="openNode(r)">
                    <cds-icon shape="router" size="26"></cds-icon>
                    <div class="meta"><div class="nm">{{ r.name }}</div><div class="sub mono">{{ r.ip }}</div></div>
                    <span class="dot" [style.background]="statusColor(r.status)"></span>
                  </div>
                }
                <div class="drop"></div>
                <div class="ifaces">
                  @for (grp of p.groups; track grp.name) {
                    <div class="iface-col" [class.unassigned]="grp.unassigned">
                      <div class="iface-name">{{ grp.name }}</div>
                      <div class="devs">
                        @for (d of grp.devices; track d.id) {
                          <div class="dev s-{{ d.status }}">
                            <cds-icon [shape]="icon(d)" size="18"></cds-icon>
                            <div class="meta" [class.clickable]="d.device_id" (click)="openNode(d)">
                              <div class="nm">{{ d.name }}</div>
                              <div class="sub mono">{{ d.ip }}{{ d.vendor && !d.device_id ? ' · ' + d.vendor : '' }}</div>
                            </div>
                            @if (d.device_id) {
                              @if (editing() === d.id) {
                                <span class="iface-edit">
                                  <input class="clr-input" list="iface-opts" [(ngModel)]="ifaceInput" placeholder="ether3" (keyup.enter)="saveIface(d)" (keyup.escape)="editing.set(null)" />
                                  <button class="btn btn-sm btn-link in" (click)="saveIface(d)">Save</button>
                                  <button class="btn btn-sm btn-link in" (click)="editing.set(null)">✕</button>
                                </span>
                              } @else {
                                <button class="pill" [class.set]="d.port" (click)="editIface(d)"
                                        [title]="d.port_manual ? 'Set manually — click to change' : 'Click to set the interface'">
                                  {{ d.port || 'set port' }}@if (d.port_manual) { <span class="star">∗</span> }
                                </button>
                              }
                            }
                          </div>
                        }
                      </div>
                    </div>
                  }
                </div>
              </div>
            </div></div>
            <datalist id="iface-opts">@for (o of g.iface_options || []; track o) { <option [value]="o"></option> }</datalist>
            <p class="muted sm">Status colour on the left edge · <span class="star">∗</span> = interface set manually.
              Click a known device to open it.</p>
          }
        } @else {
          <!-- ===== Traffic (who talks to whom) ===== -->
          <p class="muted">Who talks to whom, from the router's connection tracking. Arrows point source → destination;
            thicker = more bytes. External traffic collapses into the Internet node.
            @if (traffic(); as t) { {{ t.counts?.internal }} internal · {{ t.counts?.external }} to internet · built {{ t.time | ago }}. }</p>
          <div class="card"><div class="card-block">
            <app-chart [options]="options()" height="620px" (itemClick)="open($event)" />
          </div></div>
          @if (traffic()?.external?.length) {
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
    .sm { font-size: 0.78rem; }
    .star { color: #0079ad; font-weight: 700; }

    .topo-wrap { overflow-x: auto; }
    .topo { display: flex; flex-direction: column; align-items: center; min-width: min-content; padding: 0.5rem 0 1rem; }
    .node { display: inline-flex; align-items: center; gap: 0.6rem; padding: 0.55rem 1rem; border-radius: 0.5rem;
      border: 1px solid var(--clr-color-neutral-400, #cbd4d8); background: var(--clr-color-neutral-0, #fff); }
    .node.net { background: rgba(137,57,173,0.08); border-color: rgba(137,57,173,0.3); font-weight: 600; }
    .node.router { border-color: #0079ad; box-shadow: 0 1px 5px rgba(0,0,0,0.08); }
    .node .meta .nm { font-weight: 600; } .node .sub { font-size: 0.72rem; opacity: 0.6; }
    .node .dot { width: 0.6rem; height: 0.6rem; border-radius: 50%; }
    .drop { width: 2px; height: 22px; background: var(--clr-color-neutral-400, #cbd4d8); }

    .ifaces { display: flex; gap: 1.6rem; justify-content: center; align-items: flex-start; position: relative; padding-top: 22px; }
    .ifaces::before { content: ''; position: absolute; top: 0; left: 8%; right: 8%; height: 2px; background: var(--clr-color-neutral-400, #cbd4d8); }
    .iface-col { display: flex; flex-direction: column; align-items: center; gap: 0.6rem; position: relative; min-width: 160px; max-width: 220px; }
    .iface-col::before { content: ''; position: absolute; top: -22px; left: 50%; width: 2px; height: 22px; background: var(--clr-color-neutral-400, #cbd4d8); }
    .iface-name { font-family: var(--clr-font-mono, monospace); font-size: 0.8rem; font-weight: 600; padding: 0.2rem 0.7rem;
      border-radius: 1rem; background: rgba(0,121,173,0.1); color: #0079ad; white-space: nowrap; }
    .iface-col.unassigned .iface-name { background: rgba(230,161,0,0.16); color: #946f00; }
    .devs { display: flex; flex-direction: column; gap: 0.5rem; width: 100%; }
    .dev { display: flex; align-items: center; gap: 0.5rem; padding: 0.45rem 0.6rem; border-radius: 0.4rem;
      background: var(--clr-color-neutral-100, #f3f3f3); border-left: 3px solid #8c8c8c; }
    .dev.s-up { border-left-color: #62a420; } .dev.s-down { border-left-color: #e12200; } .dev.s-degraded { border-left-color: #e6a100; }
    .dev cds-icon { opacity: 0.8; flex: none; }
    .dev .meta { flex: 1; min-width: 0; } .dev .nm { font-weight: 600; font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .dev .sub { font-size: 0.7rem; opacity: 0.6; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .clickable { cursor: pointer; } .clickable:hover .nm { text-decoration: underline; }
    .pill { border: 1px dashed var(--clr-color-neutral-500, #9aa5ad); background: transparent; border-radius: 1rem;
      font-size: 0.66rem; line-height: 1.3; padding: 0.05rem 0.5rem; cursor: pointer; color: var(--clr-color-neutral-600, #777); white-space: nowrap; }
    .pill.set { border-style: solid; border-color: #0079ad; color: #0079ad; font-family: var(--clr-font-mono, monospace); }
    .iface-edit { display: flex; align-items: center; gap: 0.1rem; }
    .iface-edit .clr-input { width: 5.4rem; height: 1.5rem; font-size: 0.75rem; }
    .btn-link.in { min-height: auto; margin: 0; padding: 0 0.25rem; }
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
  protected editing = signal<string | null>(null);
  protected ifaceInput = '';

  /** Devices grouped by interface, named interfaces first, "Unassigned" last. */
  protected phys = computed(() => {
    const g = this.graph();
    if (!g) return null;
    const router = g.nodes.find((n) => n.category === 'router') ?? null;
    const devices = g.nodes.filter((n) => n.category === 'device' || n.category === 'unknown');
    const by = new Map<string, MapNode[]>();
    for (const d of devices) {
      const k = d.port || '';
      if (!by.has(k)) by.set(k, []);
      by.get(k)!.push(d);
    }
    const named = [...by.entries()].filter(([k]) => k)
      .sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }))
      .map(([name, devs]) => ({ name, devices: devs, unassigned: false }));
    const un = by.get('') ?? [];
    const groups = un.length ? [...named, { name: 'Unassigned', devices: un, unassigned: true }] : named;
    return { router, groups, unassignedCount: un.filter((d) => d.device_id).length };
  });

  protected options = computed(() => (this.layer() === 'traffic' ? this.trafficOption() : {}));

  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    this.http.get<Graph>('/api/netmap').subscribe((g) => this.graph.set(g));
    this.http.get<Traffic>('/api/netmap/traffic').subscribe((t) => this.traffic.set(t));
  }

  protected topologyLabel(t?: string): string {
    return { router: 'the router (bridge/ARP)', leases: 'DHCP leases', inventory: 'the inventory' }[t ?? ''] ?? t ?? '—';
  }

  protected icon(n: MapNode): string {
    return ICONS[n.type ?? ''] ?? (n.category === 'unknown' ? 'unknown-status' : 'devices');
  }

  protected statusColor(s?: string): string {
    return STATUS_COLOR[s ?? 'unknown'];
  }

  protected openNode(n: MapNode | null): void {
    if (n?.device_id) this.router.navigate(['/devices', n.device_id]);
  }

  protected editIface(d: MapNode): void {
    this.ifaceInput = d.port || '';
    this.editing.set(d.id);
  }

  protected saveIface(d: MapNode): void {
    this.http.post('/api/netmap/interface', { device_id: d.device_id, interface: this.ifaceInput.trim() || null }).subscribe({
      next: () => { this.editing.set(null); this.load(); },
      error: (e) => { this.editing.set(null); this.msg.set(errorText(e)); },
    });
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

  private trafficOption() {
    const g = this.graph();
    const t = this.traffic();
    if (!g || !t) return {};
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
