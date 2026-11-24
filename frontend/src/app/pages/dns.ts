import { HttpClient } from '@angular/common/http';
import { DatePipe, DecimalPipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { ClarityModule, ClrDatagridStringFilterInterface } from '@clr/angular';
import { firstValueFrom } from 'rxjs';
import { errorText } from '../auth';

interface DnsOverview {
  available: boolean;
  error?: string;
  protection_enabled?: boolean;
  dns_addresses?: string[];
  queries?: number;
  blocked?: number;
  blocked_pct?: number;
  top_blocked?: Record<string, number>[];
  top_queried?: Record<string, number>[];
  lists?: { name: string; enabled: boolean; rules: number; url: string }[];
}
interface Client { client: string; device_name: string; queries: number }
interface LogRow { time: string; device_name: string; domain: string; type: string; blocked: boolean; reason: string; elapsed_ms: number }

@Component({
  selector: 'app-dns',
  imports: [ClarityModule, DatePipe, DecimalPipe],
  template: `
    <div class="page-head"><h2>DNS filtering</h2></div>
    <p class="muted">The network's resolver (AdGuard Home) blocks ad, tracker and malware domains and keeps a
      per-device query log. This is the raw material for spotting a device talking to somewhere it shouldn't.</p>

    @if (ov(); as o) {
      @if (!o.available) {
        <clr-alert clrAlertType="info" [clrAlertClosable]="false"><clr-alert-item>
          <span class="alert-text">AdGuard Home isn't reachable. Start the optional <code>adguard</code> container
            and set <code>ADGUARD_USER</code> / <code>ADGUARD_PASSWORD</code>. {{ o.error }}</span>
        </clr-alert-item></clr-alert>
      } @else {
        <div class="clr-row">
          <div class="clr-col-12 clr-col-md-3"><div class="card stat"><div class="card-block">
            <div class="n">{{ o.queries | number }}</div><div class="l">DNS queries</div></div></div></div>
          <div class="clr-col-12 clr-col-md-3"><div class="card stat"><div class="card-block">
            <div class="n">{{ o.blocked_pct }}<small>%</small></div><div class="l">{{ o.blocked | number }} blocked</div></div></div></div>
          <div class="clr-col-12 clr-col-md-6"><div class="card"><div class="card-block">
            <clr-toggle-wrapper>
              <input type="checkbox" clrToggle [checked]="o.protection_enabled" (change)="toggle(!o.protection_enabled)" />
              <label>Filtering {{ o.protection_enabled ? 'on' : 'off' }}</label>
            </clr-toggle-wrapper>
            <div class="muted">Resolver: {{ (o.dns_addresses || []).join(', ') }}</div>
          </div></div></div>
        </div>

        <div class="clr-row">
          <div class="clr-col-12 clr-col-md-6"><div class="card"><div class="card-header">Most blocked</div>
            <div class="card-block"><table class="table table-compact table-noborder"><tbody>
              @for (d of flat(o.top_blocked); track d.k) { <tr><td class="left mono">{{ d.k }}</td><td class="right">{{ d.v | number }}</td></tr> }
            </tbody></table></div></div></div>
          <div class="clr-col-12 clr-col-md-6"><div class="card"><div class="card-header">Most queried</div>
            <div class="card-block"><table class="table table-compact table-noborder"><tbody>
              @for (d of flat(o.top_queried); track d.k) { <tr><td class="left mono">{{ d.k }}</td><td class="right">{{ d.v | number }}</td></tr> }
            </tbody></table></div></div></div>
        </div>

        <h3>By device</h3>
        <clr-datagrid>
          <clr-dg-column [clrDgField]="'device_name'">Device</clr-dg-column>
          <clr-dg-column [clrDgField]="'client'">Client</clr-dg-column>
          <clr-dg-column [clrDgField]="'queries'" [clrDgSortOrder]="-1">Queries</clr-dg-column>
          <clr-dg-row *clrDgItems="let c of clients()" [clrDgItem]="c">
            <clr-dg-cell>{{ c.device_name }}</clr-dg-cell>
            <clr-dg-cell class="mono">{{ c.client }}</clr-dg-cell>
            <clr-dg-cell>{{ c.queries | number }}</clr-dg-cell>
          </clr-dg-row>
          <clr-dg-placeholder>No per-client data yet.</clr-dg-placeholder>
          <clr-dg-footer>
            <clr-dg-pagination #bpg [clrDgPageSize]="10">
              <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50]">per page</clr-dg-page-size>
              {{ bpg.firstItem + 1 }}–{{ bpg.lastItem + 1 }} of {{ bpg.totalItems }}
            </clr-dg-pagination>
          </clr-dg-footer>
        </clr-datagrid>

        <h3>Recent queries</h3>
        <clr-datagrid>
          <clr-dg-column [clrDgField]="'time'">Time</clr-dg-column>
          <clr-dg-column [clrDgField]="'device_name'">Device</clr-dg-column>
          <clr-dg-column [clrDgField]="'domain'">Domain
            <clr-dg-string-filter [clrDgStringFilter]="domainFilter"></clr-dg-string-filter>
          </clr-dg-column>
          <clr-dg-column [clrDgField]="'type'">
            <ng-container *clrDgHideableColumn="{ hidden: false }">Type</ng-container>
          </clr-dg-column>
          <clr-dg-column [clrDgField]="'blocked'">Result</clr-dg-column>
          <clr-dg-row *clrDgItems="let q of log()" [clrDgItem]="q">
            <clr-dg-cell>{{ q.time | date: 'HH:mm:ss' }}</clr-dg-cell>
            <clr-dg-cell>{{ q.device_name }}</clr-dg-cell>
            <clr-dg-cell class="mono">{{ q.domain }}</clr-dg-cell>
            <clr-dg-cell>{{ q.type }}</clr-dg-cell>
            <clr-dg-cell>@if (q.blocked) { <span class="label label-danger">blocked</span> } @else { <span class="label label-success">ok</span> }</clr-dg-cell>
          </clr-dg-row>
          <clr-dg-placeholder>No queries logged.</clr-dg-placeholder>

          <ng-template [(clrIfDetail)]="logDetail" let-q>
            <clr-dg-detail>
              <clr-dg-detail-header>{{ q.domain }}</clr-dg-detail-header>
              <clr-dg-detail-body>
                <dl class="detail-kv">
                  <dt>Time</dt><dd>{{ q.time | date: 'medium' }}</dd>
                  <dt>Device</dt><dd>{{ q.device_name }}</dd>
                  <dt>Query type</dt><dd class="mono">{{ q.type }}</dd>
                  <dt>Result</dt><dd>@if (q.blocked) { <span class="label label-danger">blocked</span> } @else { <span class="label label-success">allowed</span> }</dd>
                  @if (q.reason) { <dt>Reason</dt><dd class="mono">{{ q.reason }}</dd> }
                  <dt>Resolved in</dt><dd>{{ q.elapsed_ms | number: '1.0-1' }} ms</dd>
                </dl>
              </clr-dg-detail-body>
            </clr-dg-detail>
          </ng-template>

          <clr-dg-footer>
            <clr-dg-pagination #qpg [clrDgPageSize]="20">
              <clr-dg-page-size [clrPageSizeOptions]="[20, 50, 100]">per page</clr-dg-page-size>
              {{ qpg.firstItem + 1 }}–{{ qpg.lastItem + 1 }} of {{ qpg.totalItems }}
            </clr-dg-pagination>
          </clr-dg-footer>
        </clr-datagrid>
      }
    }
    @if (msg(); as m) { <clr-alert [clrAlertType]="m.t" [clrAlertClosable]="true"><clr-alert-item><span class="alert-text">{{ m.x }}</span></clr-alert-item></clr-alert> }
  `,
  styles: `
    .table.table-noborder td { padding: 0.2rem 0.5rem; }
    .detail-kv { display: grid; grid-template-columns: max-content 1fr; gap: 0.35rem 1rem; margin: 0; }
    .detail-kv dt { font-weight: 600; opacity: 0.7; }
    .detail-kv dd { margin: 0; }
  `,
})
export class DnsPage implements OnInit {
  private http = inject(HttpClient);
  protected ov = signal<DnsOverview | null>(null);
  protected clients = signal<Client[]>([]);
  protected log = signal<LogRow[]>([]);
  protected msg = signal<{ t: 'success' | 'danger'; x: string } | null>(null);
  protected logDetail: LogRow | null = null;
  protected domainFilter: ClrDatagridStringFilterInterface<LogRow> = {
    accepts: (q, search) => q.domain.toLowerCase().includes(search.toLowerCase()),
  };

  ngOnInit(): void {
    this.load();
  }

  protected flat(rows?: Record<string, number>[]): { k: string; v: number }[] {
    return (rows || []).map((r) => { const [k, v] = Object.entries(r)[0]; return { k, v }; });
  }

  private load(): void {
    this.http.get<DnsOverview>('/api/dns/overview').subscribe((o) => {
      this.ov.set(o);
      if (o.available) {
        this.http.get<Client[]>('/api/dns/clients').subscribe((c) => this.clients.set(c));
        this.http.get<LogRow[]>('/api/dns/querylog?limit=100').subscribe((l) => this.log.set(l));
      }
    });
  }

  protected async toggle(enabled: boolean): Promise<void> {
    try {
      await firstValueFrom(this.http.post('/api/dns/protection', { enabled }));
      this.load();
    } catch (e) {
      this.msg.set({ t: 'danger', x: errorText(e) });
    }
  }
}
