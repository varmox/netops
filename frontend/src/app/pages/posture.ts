import { HttpClient } from '@angular/common/http';
import { Component, OnInit, inject, signal } from '@angular/core';
import { ClarityModule } from '@clr/angular';
import { firstValueFrom } from 'rxjs';
import { errorText } from '../auth';
import { AgoPipe } from '../ui';

interface Cert { host: string; port: number; device_name: string; subject_cn: string; issuer_cn: string; self_signed: boolean; expires: number | null; tls_version: string; error: string | null }
interface Eol { device_name: string; product: string; cycle: string; status: string; days_left: number | null; latest: string | null }
interface Exposure { kind: string; port: string; proto: string; to: string; label: string; level: string }
interface Hit { time: number; src: string; port: number; service: string; device_name: string | null }
interface CredResult { host: string; port: number; service: string; username: string; device_name: string }

@Component({
  selector: 'app-posture',
  imports: [ClarityModule, AgoPipe],
  template: `
    <div class="page-head"><h2>Security posture</h2></div>
    @if (msg(); as m) { <clr-alert [clrAlertType]="m.t" [clrAlertClosable]="true" (clrAlertClosedChange)="msg.set(null)"><clr-alert-item><span class="alert-text">{{ m.x }}</span></clr-alert-item></clr-alert> }

    <!-- Certificates -->
    <div class="sec"><div class="sec-head"><h3>Certificates</h3>
      <button class="btn btn-sm btn-outline" (click)="scan('certs')">Scan now</button></div>
      <clr-datagrid>
        <clr-dg-column>Device</clr-dg-column><clr-dg-column>Endpoint</clr-dg-column><clr-dg-column>Issuer</clr-dg-column>
        <clr-dg-column>TLS</clr-dg-column><clr-dg-column>Expires</clr-dg-column>
        @for (c of certs(); track c.host + c.port) {
          <clr-dg-row><clr-dg-cell>{{ c.device_name }}</clr-dg-cell><clr-dg-cell class="mono">{{ c.host }}:{{ c.port }}</clr-dg-cell>
            <clr-dg-cell>{{ c.error ? '—' : (c.self_signed ? 'self-signed' : c.issuer_cn) }}</clr-dg-cell>
            <clr-dg-cell><span class="label" [class.label-warning]="weakTls(c.tls_version)">{{ c.error ? 'error' : c.tls_version }}</span></clr-dg-cell>
            <clr-dg-cell>@if (c.expires) { <span [class.danger]="days(c.expires) < 21">{{ daysLabel(c.expires) }}</span> } @else { — }</clr-dg-cell></clr-dg-row>
        }
        <clr-dg-placeholder>No TLS endpoints scanned yet.</clr-dg-placeholder>
      </clr-datagrid>
    </div>

    <!-- End of life -->
    <div class="sec"><div class="sec-head"><h3>Firmware / OS lifecycle</h3>
      <button class="btn btn-sm btn-outline" (click)="scan('lifecycle')">Refresh</button></div>
      <p class="muted">End-of-life devices stop getting security updates and are the usual botnet recruits.
        Add <code>eol_product</code> / <code>eol_cycle</code> to a device's facts to track it.</p>
      <clr-datagrid>
        <clr-dg-column>Device</clr-dg-column><clr-dg-column>Product</clr-dg-column><clr-dg-column>Status</clr-dg-column><clr-dg-column>Latest</clr-dg-column>
        @for (e of eol(); track e.device_name + e.product) {
          <clr-dg-row><clr-dg-cell>{{ e.device_name }}</clr-dg-cell><clr-dg-cell>{{ e.product }} {{ e.cycle }}</clr-dg-cell>
            <clr-dg-cell><span class="label" [class.label-danger]="e.status === 'eol'" [class.label-warning]="e.status === 'warn'">
              {{ e.status === 'eol' ? 'end of life' : e.status === 'warn' ? (e.days_left + ' days left') : 'supported' }}</span></clr-dg-cell>
            <clr-dg-cell>{{ e.latest || '—' }}</clr-dg-cell></clr-dg-row>
        }
        <clr-dg-placeholder>No lifecycle data.</clr-dg-placeholder>
      </clr-datagrid>
    </div>

    <!-- Internet exposure -->
    <div class="sec"><div class="sec-head"><h3>Internet exposure</h3>
      <button class="btn btn-sm btn-outline" (click)="scan('exposure')">Scan now</button></div>
      @if (upnp() !== null) {
        <clr-alert [clrAlertType]="upnp() ? 'warning' : 'success'" [clrAlertClosable]="false"><clr-alert-item>
          <span class="alert-text">UPnP is {{ upnp() ? 'ENABLED — devices can open their own holes to the internet' : 'disabled' }}.</span>
        </clr-alert-item></clr-alert>
      }
      <clr-datagrid>
        <clr-dg-column>Kind</clr-dg-column><clr-dg-column>Port</clr-dg-column><clr-dg-column>To</clr-dg-column><clr-dg-column>What</clr-dg-column>
        @for (e of exposures(); track e.kind + e.port + e.to) {
          <clr-dg-row><clr-dg-cell><span class="label" [class.label-warning]="e.level === 'warning'">{{ e.kind }}</span></clr-dg-cell>
            <clr-dg-cell class="mono">{{ e.port }}/{{ e.proto }}</clr-dg-cell><clr-dg-cell class="mono">{{ e.to }}</clr-dg-cell>
            <clr-dg-cell>{{ e.label }}</clr-dg-cell></clr-dg-row>
        }
        <clr-dg-placeholder>Nothing reachable from the internet (or no MikroTik configured).</clr-dg-placeholder>
      </clr-datagrid>
    </div>

    <!-- Honeypot -->
    <div class="sec"><div class="sec-head"><h3>Honeypot</h3></div>
      <p class="muted">Fake Telnet/SMB/RDP services. Nothing here offers them, so any connection is suspicious.
        Listening: @for (l of listening(); track l.port) { <span class="label">{{ l.port }}/{{ l.service }}</span> }</p>
      <clr-datagrid>
        <clr-dg-column>When</clr-dg-column><clr-dg-column>Source</clr-dg-column><clr-dg-column>Port</clr-dg-column><clr-dg-column>Service</clr-dg-column>
        @for (h of hits(); track $index) {
          <clr-dg-row><clr-dg-cell>{{ h.time | ago }}</clr-dg-cell><clr-dg-cell>{{ h.device_name || h.src }}</clr-dg-cell>
            <clr-dg-cell class="mono">{{ h.port }}</clr-dg-cell><clr-dg-cell>{{ h.service }}</clr-dg-cell></clr-dg-row>
        }
        <clr-dg-placeholder>No honeypot hits — good.</clr-dg-placeholder>
      </clr-datagrid>
    </div>

    <!-- Default credential audit -->
    <div class="sec"><div class="sec-head"><h3>Default-password audit</h3></div>
      <p class="muted">Checks whether your own devices still accept documented factory logins (the Mirai vector).
        It reports which devices are vulnerable and changes nothing. LAN-only, rate-limited.</p>
      @if (!credEnabled()) {
        <clr-alert clrAlertType="info" [clrAlertClosable]="false"><clr-alert-item>
          <span class="alert-text">Disabled. Set <code>CREDCHECK_ENABLED=true</code> to allow it.</span></clr-alert-item></clr-alert>
      } @else {
        <button class="btn btn-sm btn-warning-outline" [disabled]="credBusy()" (click)="runCred()">
          {{ credBusy() ? 'Checking…' : 'Run audit' }}</button>
        <clr-datagrid>
          <clr-dg-column>Device</clr-dg-column><clr-dg-column>Endpoint</clr-dg-column><clr-dg-column>Service</clr-dg-column><clr-dg-column>Accepted user</clr-dg-column>
          @for (r of credResults(); track r.host + r.port) {
            <clr-dg-row><clr-dg-cell>{{ r.device_name }}</clr-dg-cell><clr-dg-cell class="mono">{{ r.host }}:{{ r.port }}</clr-dg-cell>
              <clr-dg-cell>{{ r.service }}</clr-dg-cell><clr-dg-cell><span class="label label-danger">{{ r.username }}</span></clr-dg-cell></clr-dg-row>
          }
          <clr-dg-placeholder>{{ credRan() ? 'No device accepted a factory login — good.' : 'Not run yet.' }}</clr-dg-placeholder>
        </clr-datagrid>
      }
    </div>
  `,
  styles: `.sec{margin-bottom:1.6rem}.sec-head{display:flex;align-items:center;gap:1rem}.sec-head h3{margin:0.6rem 0}.danger{color:var(--clr-color-danger-700,#c21d00);font-weight:600}`,
})
export class PosturePage implements OnInit {
  private http = inject(HttpClient);
  protected certs = signal<Cert[]>([]);
  protected eol = signal<Eol[]>([]);
  protected exposures = signal<Exposure[]>([]);
  protected upnp = signal<boolean | null>(null);
  protected hits = signal<Hit[]>([]);
  protected listening = signal<{ port: number; service: string }[]>([]);
  protected credEnabled = signal(false);
  protected credResults = signal<CredResult[]>([]);
  protected credBusy = signal(false);
  protected credRan = signal(false);
  protected msg = signal<{ t: 'success' | 'danger'; x: string } | null>(null);

  ngOnInit(): void {
    this.load();
  }

  protected weakTls = (v: string) => ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'].includes(v);
  protected days = (exp: number) => Math.round((exp * 1000 - Date.now()) / 86400000);
  protected daysLabel = (exp: number) => { const d = this.days(exp); return d < 0 ? `expired ${-d}d ago` : `in ${d} days`; };

  private load(): void {
    this.http.get<{ certs: Cert[] }>('/api/certs').subscribe((d) => this.certs.set(d.certs || []));
    this.http.get<{ devices: Eol[] }>('/api/lifecycle').subscribe((d) => this.eol.set(d.devices || []));
    this.http.get<{ upnp_enabled: boolean | null; exposures: Exposure[] }>('/api/exposure').subscribe((d) => {
      this.exposures.set(d.exposures || []); this.upnp.set(d.upnp_enabled);
    });
    this.http.get<{ summary: { listening: { port: number; service: string }[] }; hits: Hit[] }>('/api/honeypot').subscribe((d) => {
      this.hits.set(d.hits || []); this.listening.set(d.summary?.listening || []);
    });
    this.http.get<{ enabled: boolean; last: { results: CredResult[] } }>('/api/credcheck').subscribe((d) => {
      this.credEnabled.set(d.enabled); this.credResults.set(d.last?.results || []);
    });
  }

  protected async scan(what: string): Promise<void> {
    try {
      await firstValueFrom(this.http.post(`/api/${what}/scan`, {}));
      this.msg.set({ t: 'success', x: 'Scan started; refresh in a moment.' });
      setTimeout(() => this.load(), 4000);
    } catch (e) {
      this.msg.set({ t: 'danger', x: errorText(e) });
    }
  }

  protected async runCred(): Promise<void> {
    this.credBusy.set(true);
    try {
      const r = await firstValueFrom(this.http.post<{ vulnerable: number; results: CredResult[] }>('/api/credcheck/run', { confirm: true }));
      this.credResults.set(r.results); this.credRan.set(true);
      this.msg.set({ t: r.vulnerable ? 'danger' : 'success', x: r.vulnerable ? `${r.vulnerable} device(s) still accept a factory login.` : 'No device accepted a factory login.' });
    } catch (e) {
      this.msg.set({ t: 'danger', x: errorText(e) });
    }
    this.credBusy.set(false);
  }
}
