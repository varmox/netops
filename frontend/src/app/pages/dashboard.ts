import { HttpClient } from '@angular/common/http';
import { DatePipe, DecimalPipe } from '@angular/common';
import { Component, DestroyRef, OnInit, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { firstValueFrom, forkJoin, switchMap } from 'rxjs';
import { Alerts, alertStatus } from '../alerts';
import { Api, Device, Summary } from '../api';
import { Prefs } from '../prefs';
import { AgoPipe, BytesPipe, StatusLabel, refreshTicks } from '../ui';

@Component({
  selector: 'app-dashboard',
  imports: [ClarityModule, RouterLink, StatusLabel, AgoPipe, BytesPipe, DatePipe, DecimalPipe],
  template: `
    <div class="page-head">
      <h2>Dashboard</h2>
      <span class="muted">{{ prefs.autoRefresh() ? 'refreshes every ' + prefs.refreshSeconds() + ' s' : 'auto refresh off' }}</span>
    </div>

    @if (summary(); as s) {
      <div class="clr-row">
        <div class="clr-col-12 clr-col-md-4">
          <div class="card stat"><div class="card-block">
            <div class="n">{{ s.status.up }}<small>/{{ s.devices }}</small></div>
            <div class="l">devices up</div>
            <clr-progress-bar [clrValue]="s.status.up" [clrMax]="s.devices || 1"
                              [clrColor]="s.status.down ? 'danger' : s.status.degraded ? 'warning' : 'success'"></clr-progress-bar>
          </div></div>
        </div>
        <div class="clr-col-12 clr-col-md-4">
          <div class="card stat"><div class="card-block">
            <div class="n">{{ s.backups.ok }}<small>/{{ s.backups.devices }}</small></div>
            <div class="l">config backups OK · daily {{ s.settings.backup_time }}</div>
            <clr-progress-bar [clrValue]="s.backups.ok" [clrMax]="s.backups.devices || 1"
                              [clrColor]="s.backups.failed ? 'danger' : 'success'"></clr-progress-bar>
          </div></div>
        </div>
        <div class="clr-col-12 clr-col-md-4">
          <div class="card stat"><div class="card-block">
            <div class="n">{{ diskUsed() | number: '1.0-0' }}<small>%</small></div>
            <div class="l">disk used · {{ s.disk.free | bytes }} free</div>
            <clr-progress-bar [clrValue]="diskUsed()" [clrMax]="100"
                              [clrColor]="diskUsed() > 90 ? 'danger' : diskUsed() > 75 ? 'warning' : 'success'"></clr-progress-bar>
          </div></div>
        </div>
      </div>
    } @else {
      <clr-progress-bar [clrLoop]="true"></clr-progress-bar>
    }

    <h3>Devices</h3>
    <div class="clr-row">
      @for (d of devices(); track d.id) {
        <div class="clr-col-12 clr-col-md-6 clr-col-xl-4">
          <div class="card dev">
            <div class="card-header">
              <a [routerLink]="['/devices', d.id]">{{ d.name }}</a>
              <app-status [status]="d.state.status" />
            </div>
            <div class="card-block">
              <div class="card-text muted">{{ d.role }} · <span class="mono">{{ d.host }}</span></div>
              <div class="checks">
                @for (c of d.state.checks; track c.check) {
                  <clr-tooltip>
                    <span clrTooltipTrigger class="label" [class.label-success]="c.ok" [class.label-danger]="!c.ok" tabindex="0">
                      {{ c.check }}@if (c.latency_ms !== null) {&nbsp;<span class="badge">{{ c.latency_ms | number: '1.0-0' }} ms</span>}
                    </span>
                    <clr-tooltip-content clrPosition="top-right" clrSize="sm" *clrIfOpen>{{ c.detail }}</clr-tooltip-content>
                  </clr-tooltip>
                }
              </div>
            </div>
            <div class="card-footer muted">
              @if (d.backup) {
                Backup: @if (d.state.backup_ok === false) { <span class="bad">failed</span> }
                @else if (d.state.backup_last_ok) { {{ d.state.backup_last_ok | ago }} } @else { none yet }
              } @else { watch only }
              · checked {{ d.state.last_check | ago }}
            </div>
          </div>
        </div>
      }
    </div>

    @if (report(); as r) {
      <h3>This week <button class="btn btn-link btn-sm" (click)="sendReport()" [disabled]="reportBusy()">Send to ntfy</button></h3>
      <div class="clr-row">
        <div class="clr-col-6 clr-col-md-2"><div class="card stat"><div class="card-block">
          <div class="n" [class.bad]="r.findings_open.critical">{{ r.findings_open.critical + r.findings_open.high }}</div>
          <div class="l">open critical/high</div></div></div></div>
        <div class="clr-col-6 clr-col-md-2"><div class="card stat"><div class="card-block">
          <div class="n">{{ r.updates_applied }}</div><div class="l">actions applied</div></div></div></div>
        <div class="clr-col-6 clr-col-md-2"><div class="card stat"><div class="card-block">
          <div class="n">{{ r.new_devices.length }}</div><div class="l">new devices</div></div></div></div>
        <div class="clr-col-6 clr-col-md-2"><div class="card stat"><div class="card-block">
          <div class="n" [class.bad]="r.honeypot_hits">{{ r.honeypot_hits }}</div><div class="l">honeypot hits</div></div></div></div>
        <div class="clr-col-6 clr-col-md-2"><div class="card stat"><div class="card-block">
          <div class="n" [class.bad]="r.upnp_enabled && r.exposures">{{ r.exposures }}</div><div class="l">internet exposures</div></div></div></div>
        @if (r.compliance) { <div class="clr-col-6 clr-col-md-2"><div class="card stat"><div class="card-block">
          <div class="n">{{ complianceScore(r) }}<small>%</small></div><div class="l">STIG compliance</div></div></div></div> }
      </div>
    }

    <h3>Latest alerts <a routerLink="/alerts" class="btn btn-link btn-sm">All alerts</a></h3>
    @for (a of alerts.visible().slice(0, 5); track a.id) {
      <clr-alert [clrAlertType]="status(a)" [clrAlertSizeSmall]="true" [clrAlertClosable]="false">
        <clr-alert-item>
          <span class="alert-text"><strong>{{ a.title }}</strong> · {{ a.message }}
            <span class="muted"> · {{ a.time * 1000 | date: 'dd.MM. HH:mm' }}</span></span>
        </clr-alert-item>
      </clr-alert>
    } @empty {
      <p class="muted">No alerts in the last 24 hours.</p>
    }
  `,
  styles: `
    .dev .card-header { display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; }
    .checks { display: flex; flex-wrap: wrap; gap: 0.35rem; margin-top: 0.6rem; }
    .card-footer { font-size: 0.78rem; }
    h3 .btn { vertical-align: middle; }
  `,
})
export class DashboardPage implements OnInit {
  private api = inject(Api);
  private destroyRef = inject(DestroyRef);
  private ticks = refreshTicks();
  protected alerts = inject(Alerts);
  protected prefs = inject(Prefs);
  private http = inject(HttpClient);
  protected summary = signal<Summary | null>(null);
  protected devices = signal<Device[]>([]);
  protected report = signal<WeeklyReport | null>(null);
  protected reportBusy = signal(false);
  protected status = alertStatus;
  protected diskUsed = computed(() => {
    const d = this.summary()?.disk;
    return d && d.total ? ((d.total - d.free) / d.total) * 100 : 0;
  });

  ngOnInit(): void {
    this.ticks.pipe(
      switchMap(() => forkJoin([this.api.summary(), this.api.devices()])),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe(([s, d]) => { this.summary.set(s); this.devices.set(d); });
    this.http.get<WeeklyReport>('/api/report').subscribe((r) => this.report.set(r && r.time ? r : null));
  }

  protected complianceScore(r: WeeklyReport): number {
    const p = r.compliance?.profiles ?? {};
    const scores = Object.values(p).map((x) => x.score);
    return scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
  }

  protected async sendReport(): Promise<void> {
    this.reportBusy.set(true);
    try {
      this.report.set(await firstValueFrom(this.http.post<WeeklyReport>('/api/report/run', {})));
    } finally {
      this.reportBusy.set(false);
    }
  }
}

interface WeeklyReport {
  time: number;
  findings_open: { critical: number; high: number; medium: number; low: number };
  updates_applied: number;
  new_devices: { id: string; name: string }[];
  honeypot_hits: number;
  exposures: number;
  upnp_enabled: boolean | null;
  compliance: { profiles: Record<string, { score: number }> } | null;
}
