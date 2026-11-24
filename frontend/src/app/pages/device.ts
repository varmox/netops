import { HttpClient } from '@angular/common/http';
import { DatePipe, KeyValuePipe } from '@angular/common';
import { Component, DestroyRef, OnInit, inject, input, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { switchMap } from 'rxjs';
import { AlertPref, Api, BackupVersion, Device, DeviceCredentials, Discovery, versionDate } from '../api';
import { TimelineEvent } from './timeline';
import { AgoPipe, BytesPipe, StatusLabel, refreshTicks } from '../ui';

interface Line {
  text: string;
  cls: string;
}

interface Reliability {
  window_days: number;
  availability: number;
  incidents: number;
  mttr_s: number | null;
  mtbf_s: number | null;
  currently_down: boolean;
  latency: { check: string; p5: number | null; p50: number | null; p95: number | null }[];
}

@Component({
  selector: 'app-device',
  imports: [ClarityModule, FormsModule, RouterLink, StatusLabel, AgoPipe, BytesPipe, DatePipe, KeyValuePipe],
  template: `
    <a routerLink="/devices" class="muted">← Devices</a>
    @if (device(); as d) {
      <div class="page-head">
        <h2>{{ d.name }} <app-status [status]="d.state.status" /></h2>
        <div class="btn-group">
          <button class="btn btn-sm btn-outline" (click)="check()" [disabled]="checking()">
            <cds-icon shape="refresh"></cds-icon> Check now
          </button>
          @if (d.backup) {
            <button class="btn btn-sm btn-primary" (click)="backup()" [disabled]="backingUp() || d.state.backup_running">
              <cds-icon shape="backup"></cds-icon> Back up now
            </button>
          }
        </div>
      </div>
      <p class="muted">{{ d.role }} · <span class="mono">{{ d.host }}</span> · {{ d.type }}</p>

      @if (backingUp() || checking()) {
        <clr-progress-bar [clrLoop]="true"></clr-progress-bar>
      }
      @if (message(); as m) {
        <clr-alert [clrAlertType]="m.type" [clrAlertClosable]="true" (clrAlertClosedChange)="message.set(null)">
          <clr-alert-item><span class="alert-text">{{ m.text }}</span></clr-alert-item>
        </clr-alert>
      }
      @if (d.state.backup_error) {
        <clr-alert clrAlertType="danger" [clrAlertClosable]="false">
          <clr-alert-item><span class="alert-text">Last backup failed: {{ d.state.backup_error }}</span></clr-alert-item>
        </clr-alert>
      }

      <clr-tabs>
        <clr-tab>
          <button clrTabLink>Overview</button>
          <clr-tab-content *clrIfActive="true">
            <div class="clr-row">
              <div class="clr-col-12 clr-col-lg-6">
                <h4>Health checks</h4>
                <table class="table table-compact">
                  <thead><tr><th class="left">Check</th><th>Result</th><th>Latency</th><th class="left">Detail</th></tr></thead>
                  <tbody>
                    @for (c of d.state.checks; track c.check) {
                      <tr>
                        <td class="left mono">{{ c.check }}</td>
                        <td><span class="label" [class.label-success]="c.ok" [class.label-danger]="!c.ok">{{ c.ok ? 'OK' : 'FAIL' }}</span></td>
                        <td>{{ c.latency_ms !== null ? (c.latency_ms.toFixed(1) + ' ms') : '–' }}</td>
                        <td class="left">{{ c.detail }}</td>
                      </tr>
                    }
                  </tbody>
                </table>
                <p class="muted">Status since {{ d.state.since | ago }} · last check {{ d.state.last_check | ago }}</p>
              </div>
              <div class="clr-col-12 clr-col-lg-6">
                <h4>Facts</h4>
                <clr-stack-view>
                  @for (f of d.facts | keyvalue; track f.key) {
                    <clr-stack-block><clr-stack-label>{{ f.key }}</clr-stack-label><clr-stack-content>{{ f.value }}</clr-stack-content></clr-stack-block>
                  }
                  @for (l of d.links | keyvalue; track l.key) {
                    <clr-stack-block><clr-stack-label>{{ l.key }}</clr-stack-label>
                      <clr-stack-content><a [href]="l.value" target="_blank" rel="noopener">{{ l.value }}</a></clr-stack-content></clr-stack-block>
                  }
                  @if (d.backup) {
                    <clr-stack-block><clr-stack-label>Backup method</clr-stack-label>
                      <clr-stack-content class="mono">{{ d.backup.method }}{{ d.backup.binary ? ' + binary' : '' }}</clr-stack-content></clr-stack-block>
                  }
                </clr-stack-view>
                @if (d.notes) { <p>{{ d.notes }}</p> }
              </div>
            </div>

            <div class="disc-head">
              <h4>Discovered hardware</h4>
              @if (discovery(); as dc) {
                @for (s of dc.sources; track s) { <span class="label label-info">{{ s }}</span> }
                @if (dc.time) { <span class="muted">· probed {{ dc.time | ago }}</span> }
              }
              <button class="btn btn-sm btn-outline disc-btn" [disabled]="discovering()" (click)="discover()">
                <cds-icon shape="radar"></cds-icon> {{ discovering() ? 'Probing…' : 'Scan now' }}
              </button>
            </div>
            <p class="muted">Read-only probe: SSH where we have credentials (model, serial, CPU/RAM, OS/firmware, uptime),
              SNMP if it answers, then MAC vendor and open-port banners from the last LAN scan.</p>
            @if (discovery(); as dc) {
              @if (dc.vault_locked) {
                <clr-alert clrAlertType="warning" [clrAlertClosable]="false" clrAlertSize="sm"><clr-alert-item>
                  <span class="alert-text">The vault is locked, so the SSH probe was skipped. Unlock it (Vault) and scan again for full hardware details.</span>
                </clr-alert-item></clr-alert>
              }
              @if (dc.facts | keyvalue; as facts) {
                @if (facts.length) {
                  <clr-stack-view>
                    @for (f of facts; track f.key) {
                      <clr-stack-block><clr-stack-label>{{ f.key }}</clr-stack-label><clr-stack-content>{{ f.value }}</clr-stack-content></clr-stack-block>
                    }
                  </clr-stack-view>
                } @else if (dc.time) {
                  <p class="muted">Nothing could be discovered — no SSH credentials, no SNMP response, and no LAN-scan data for this host.</p>
                } @else {
                  <p class="muted">Not probed yet. Press <strong>Scan now</strong>.</p>
                }
              }
            }

            <div class="disc-head">
              <h4>Credentials</h4>
              @if (creds(); as c) {
                @if (!c.vault.initialized) { <span class="label">vault not set up</span> }
                @else if (c.vault.unlocked) { <span class="label label-success">vault unlocked</span> }
                @else { <span class="label label-warning">vault locked</span> }
              }
            </div>
            @if (creds(); as c) {
              @if (!c.managed) {
                <p class="muted">Defined in <span class="mono">config/devices.yml</span> — its credentials come from there
                  (a <span class="mono">/secrets</span> file, an env var, or a vault secret the config references). Add a device
                  from the <a routerLink="/devices">Devices</a> page to manage its credentials here.</p>
              } @else if (!c.vault.initialized) {
                <clr-alert clrAlertType="info" [clrAlertClosable]="false" clrAlertSize="sm"><clr-alert-item>
                  <span class="alert-text">Credentials are kept in the encrypted vault. Set it up on the
                    <a routerLink="/vault">Vault page</a> first, then come back here.</span></clr-alert-item></clr-alert>
              } @else {
                @if (!c.vault.unlocked) {
                  <clr-alert clrAlertType="warning" [clrAlertClosable]="false" clrAlertSize="sm"><clr-alert-item>
                    <span class="alert-text">The vault is locked. <a routerLink="/vault">Unlock it</a> to add or change credentials.</span>
                  </clr-alert-item></clr-alert>
                }
                <p class="muted">Stored in the vault and wired into this device's connection config automatically.
                  Values are write-only — they're never shown again. SSH user: <span class="mono">{{ c.ssh_user || '—' }}</span>.</p>
                <clr-stack-view>
                  @for (s of c.slots; track s.slot) {
                    <clr-stack-block>
                      <clr-stack-label>{{ slotLabel(s.slot) }}</clr-stack-label>
                      <clr-stack-content>
                        @if (s.set) {
                          <span class="label label-success">set</span>
                          @if (s.referenced) { <span class="label label-info">in use</span> }
                        } @else { <span class="muted">not set</span> }
                        @if (c.vault.unlocked) {
                          <button class="btn btn-sm btn-link in" (click)="openCred(s.slot)">{{ s.set ? 'Replace' : 'Set' }}</button>
                          @if (s.set) { <button class="btn btn-sm btn-link in danger" (click)="clearCred(s.slot)">Clear</button> }
                        }
                      </clr-stack-content>
                    </clr-stack-block>
                  }
                </clr-stack-view>
              }
            }

            <h4>Alerting</h4>
            <div class="alertpref">
              <clr-toggle-wrapper>
                <input type="checkbox" clrToggle name="alertPref" [disabled]="savingAlert()"
                       [ngModel]="d.alert_on_down" (ngModelChange)="setAlert(d, $event)" />
                <label>Push a notification when this device goes down or degrades</label>
              </clr-toggle-wrapper>
              @if (d.alert_overridden) {
                <span class="muted">Set manually · default is
                  <strong>{{ d.alert_default ? 'alerts (infrastructure)' : 'silent (tracked only)' }}</strong>.</span>
                <button class="btn btn-sm btn-link" [disabled]="savingAlert()" (click)="setAlert(d, null)">Reset to default</button>
              } @else {
                <span class="muted">Using the default:
                  <strong>{{ d.alert_default ? 'alerts because this is infrastructure' : 'silent — still tracked for uptime, just no push' }}</strong>.</span>
              }
            </div>
          </clr-tab-content>
        </clr-tab>

        <clr-tab>
          <button clrTabLink>Reliability</button>
          <clr-tab-content *clrIfActive>
            @if (reliability(); as r) {
              <div class="clr-row">
                <div class="clr-col-6 clr-col-md-3"><div class="card stat"><div class="card-block">
                  <div class="n">{{ (r.availability * 100).toFixed(2) }}<small>%</small></div>
                  <div class="l">availability · {{ r.window_days }}d</div></div></div></div>
                <div class="clr-col-6 clr-col-md-3"><div class="card stat"><div class="card-block">
                  <div class="n">{{ r.mttr_s === null ? '–' : dur(r.mttr_s) }}</div><div class="l">MTTR (mean time to recovery)</div></div></div></div>
                <div class="clr-col-6 clr-col-md-3"><div class="card stat"><div class="card-block">
                  <div class="n">{{ r.mtbf_s === null ? '–' : dur(r.mtbf_s) }}</div><div class="l">MTBF (mean time between)</div></div></div></div>
                <div class="clr-col-6 clr-col-md-3"><div class="card stat"><div class="card-block">
                  <div class="n" [class.bad]="r.currently_down">{{ r.incidents }}</div><div class="l">incidents{{ r.currently_down ? ' · down now' : '' }}</div></div></div></div>
              </div>
              <h4>Latency percentiles ({{ r.window_days }}d)</h4>
              <table class="table table-compact">
                <thead><tr><th class="left">Check</th><th>p5</th><th>p50 (median)</th><th>p95</th></tr></thead>
                <tbody>
                  @for (l of r.latency; track l.check) {
                    <tr><td class="left mono">{{ l.check }}</td>
                      <td>{{ l.p5 ?? '–' }}{{ l.p5 != null ? ' ms' : '' }}</td>
                      <td>{{ l.p50 ?? '–' }}{{ l.p50 != null ? ' ms' : '' }}</td>
                      <td>{{ l.p95 ?? '–' }}{{ l.p95 != null ? ' ms' : '' }}</td></tr>
                  } @empty { <tr><td colspan="4" class="muted">No latency samples yet (Prometheus fills these over time).</td></tr> }
                </tbody>
              </table>
              <p class="muted">Downtime incidents come from the health watcher; percentiles are computed by Prometheus.</p>
            } @else { <clr-progress-bar [clrLoop]="true"></clr-progress-bar> }
          </clr-tab-content>
        </clr-tab>

        @if (d.backup) {
          <clr-tab>
            <button clrTabLink>Config history ({{ versions().length }})</button>
            <clr-tab-content *clrIfActive>
              <p class="muted">
                Select a version to read it, or switch on "Changes" to compare it with the one before.
                <clr-signpost>
                  <clr-signpost-content *clrIfOpen>
                    <h4>When is a version stored?</h4>
                    <p>Every backup run compares the config with the latest version. Only real changes create a new
                      version; timestamps and live counters are ignored. Up to 60 versions are kept.</p>
                  </clr-signpost-content>
                </clr-signpost>
              </p>
              <clr-datagrid>
                <clr-dg-column>Version</clr-dg-column>
                <clr-dg-column>Changes</clr-dg-column>
                <clr-dg-column>Files</clr-dg-column>
                <clr-dg-row *clrDgItems="let v of versions(); let i = index" [clrDgItem]="v">
                  <clr-dg-cell>{{ date(v.version) | date: 'dd.MM.yyyy HH:mm' }} @if (i === 0) { <span class="label label-info">latest</span> }</clr-dg-cell>
                  <clr-dg-cell>
                    @if (v.diffstat) { <span class="diff-add">+{{ v.diffstat.added }}</span> / <span class="diff-del">−{{ v.diffstat.removed }}</span> }
                    @else { <span class="muted">first version</span> }
                  </clr-dg-cell>
                  <clr-dg-cell>
                    @for (f of v.files; track f.name) {
                      <a [href]="api.fileUrl(d.id, f.name)" class="mono" title="Download">{{ f.name.split('.').pop() }}</a>
                      <span class="muted"> ({{ f.size | bytes }})</span>&nbsp;
                    }
                  </clr-dg-cell>
                </clr-dg-row>

                <ng-template [clrIfDetail]="null" (clrIfDetailChange)="openVersion($event)" let-v>
                  <clr-dg-detail>
                    <clr-dg-detail-header>{{ v.primary }}</clr-dg-detail-header>
                    <clr-dg-detail-body>
                      <clr-toggle-wrapper>
                        <input type="checkbox" clrToggle name="showDiff" [disabled]="!v.previous"
                               [ngModel]="showDiff()" (ngModelChange)="showDiff.set($event); openVersion(v)" />
                        <label>Changes to the previous version</label>
                      </clr-toggle-wrapper>
                      @if (loadingFile()) { <clr-progress-bar [clrLoop]="true"></clr-progress-bar> }
                      <pre class="config">@for (l of lines(); track $index) {<span [class]="l.cls">{{ l.text }}</span>
}</pre>
                    </clr-dg-detail-body>
                  </clr-dg-detail>
                </ng-template>

                <clr-dg-placeholder>No backups yet. Use "Back up now".</clr-dg-placeholder>
                <clr-dg-footer>{{ versions().length }} versions</clr-dg-footer>
              </clr-datagrid>
            </clr-tab-content>
          </clr-tab>
        }

        <clr-tab>
          <button clrTabLink>Timeline ({{ timeline().length }})</button>
          <clr-tab-content *clrIfActive>
            <p class="muted">Config changes, findings, certificate changes, exposure, honeypot hits and
              end-of-life for this device, newest first.</p>
            <ul class="tl">
              @for (e of timeline(); track $index) {
                <li class="tl-item">
                  <span class="label" [class.label-warning]="e.level === 'warning'" [class.label-danger]="e.level === 'critical'">{{ e.kind }}</span>
                  <span class="tl-title">{{ e.title }}</span>
                  <span class="tl-detail">{{ e.detail }}</span>
                  <span class="tl-time">{{ e.time * 1000 | date: 'dd.MM HH:mm' }}</span>
                </li>
              } @empty { <li class="muted">Nothing recorded yet.</li> }
            </ul>
          </clr-tab-content>
        </clr-tab>
      </clr-tabs>

      <!-- Set / generate a credential -->
      <clr-modal [(clrModalOpen)]="credOpen" [clrModalClosable]="!credSaving()" clrModalSize="md">
        <h3 class="modal-title">{{ slotLabel(credSlot) }}</h3>
        <div class="modal-body">
          @if (credPublicKey(); as pk) {
            <p>Keypair generated and the private key stored in the vault. Add this <strong>public key</strong> to the device
              so it accepts the connection:</p>
            <pre class="cmd">{{ pk }}</pre>
            <p class="muted sm">Linux: append it to <span class="mono">~/.ssh/authorized_keys</span> of the SSH user.
              MikroTik: <span class="mono">/user/ssh-keys import public-key-file=…</span>.</p>
          } @else {
            <form clrForm clrLayout="vertical">
              <clr-input-container>
                <label>SSH user</label>
                <input clrInput name="cuser" [(ngModel)]="credUser" placeholder="netops" />
                <clr-control-helper>The login this credential belongs to.</clr-control-helper>
              </clr-input-container>
              @if (credSlot === 'ssh-key') {
                <clr-checkbox-wrapper>
                  <input type="checkbox" clrCheckbox name="cgen" [(ngModel)]="credGenerate" />
                  <label>Generate a new ed25519 keypair (recommended)</label>
                </clr-checkbox-wrapper>
              }
              @if (credSlot === 'password' || !credGenerate) {
                <clr-textarea-container>
                  <label>{{ credSlot === 'password' ? 'Password' : 'Private key (OpenSSH / PEM)' }}</label>
                  <textarea clrTextarea name="cval" [(ngModel)]="credValue" rows="4"
                            placeholder="{{ credSlot === 'password' ? '' : '-----BEGIN OPENSSH PRIVATE KEY-----' }}"></textarea>
                </clr-textarea-container>
              }
            </form>
            @if (credError(); as e) {
              <clr-alert clrAlertType="danger" [clrAlertClosable]="false" clrAlertSize="sm">
                <clr-alert-item><span class="alert-text">{{ e }}</span></clr-alert-item></clr-alert>
            }
          }
        </div>
        <div class="modal-footer">
          @if (credPublicKey()) {
            <button type="button" class="btn btn-primary" (click)="credOpen = false">Done</button>
          } @else {
            <button type="button" class="btn btn-outline" [disabled]="credSaving()" (click)="credOpen = false">Cancel</button>
            <button type="button" class="btn btn-primary" [disabled]="credSaving() || !credValid()" (click)="saveCred()">
              {{ credSaving() ? 'Saving…' : 'Save' }}
            </button>
          }
        </div>
      </clr-modal>
    } @else {
      <clr-progress-bar [clrLoop]="true"></clr-progress-bar>
    }
  `,
  styles: `
    h2 app-status { font-size: 0.8rem; vertical-align: middle; margin-left: 0.4rem; }
    .table th, .table td { vertical-align: middle; }
    clr-toggle-wrapper { margin-bottom: 0.5rem; }
    .alertpref { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.4rem 0.8rem; }
    .alertpref clr-toggle-wrapper { margin-bottom: 0; flex-basis: 100%; }
    .disc-head { display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem; margin-top: 1rem; }
    .disc-head h4 { margin: 0; }
    .disc-head .disc-btn { margin-left: auto; }
    .btn-link.in { min-height: auto; margin: 0 0 0 0.4rem; padding: 0; }
    .btn-link.in.danger { color: var(--clr-color-danger-700, #c21d00); }
    .cmd { background: var(--clr-color-neutral-100, #f3f3f3); border-radius: 4px; padding: 0.5rem 0.7rem;
      font-size: 0.74rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
    .sm { font-size: 0.78rem; }
    .tl { list-style: none; padding: 0; margin: 0; }
    .tl-item { display: flex; gap: 0.6rem; align-items: baseline; padding: 0.4rem 0; border-bottom: 1px solid var(--clr-color-neutral-300, #e0e0e0); }
    .tl-title { font-weight: 600; }
    .tl-detail { color: var(--clr-color-neutral-700, #555); font-size: 0.85rem; flex: 1; min-width: 0; }
    .tl-time { color: var(--clr-color-neutral-600, #777); font-size: 0.78rem; }
  `,
})
export class DevicePage implements OnInit {
  readonly id = input.required<string>();
  protected api = inject(Api);
  private http = inject(HttpClient);
  private destroyRef = inject(DestroyRef);
  private ticks = refreshTicks();
  protected device = signal<Device | null>(null);
  protected timeline = signal<TimelineEvent[]>([]);
  protected reliability = signal<Reliability | null>(null);
  protected versions = signal<BackupVersion[]>([]);
  protected lines = signal<Line[]>([]);
  protected showDiff = signal(false);
  protected loadingFile = signal(false);
  protected checking = signal(false);
  protected backingUp = signal(false);
  protected savingAlert = signal(false);
  protected discovery = signal<Discovery | null>(null);
  protected discovering = signal(false);
  protected creds = signal<DeviceCredentials | null>(null);
  // Credential modal state.
  protected credOpen = false;
  protected credSlot = 'ssh-key';
  protected credUser = '';
  protected credValue = '';
  protected credGenerate = true;
  protected credSaving = signal(false);
  protected credError = signal<string | null>(null);
  protected credPublicKey = signal<string | null>(null);
  protected message = signal<{ type: 'success' | 'danger' | 'info'; text: string } | null>(null);
  protected date = versionDate;

  ngOnInit(): void {
    this.ticks.pipe(switchMap(() => this.api.device(this.id())), takeUntilDestroyed(this.destroyRef))
      .subscribe((d) => this.device.set(d));
    this.loadVersions();
    this.api.discovery(this.id()).subscribe({ next: (dc) => this.discovery.set(dc), error: () => {} });
    this.loadCreds();
    this.http.get<TimelineEvent[]>(`/api/devices/${this.id()}/timeline`).subscribe((t) => this.timeline.set(t));
    this.http.get<Reliability>(`/api/devices/${this.id()}/reliability`).subscribe((r) => this.reliability.set(r));
  }

  private loadCreds(): void {
    this.api.credentials(this.id()).subscribe({ next: (c) => this.creds.set(c), error: () => {} });
  }

  protected slotLabel(slot: string): string {
    return slot === 'ssh-key' ? 'SSH private key' : slot === 'password' ? 'Password' : slot;
  }

  protected openCred(slot: string): void {
    this.credSlot = slot;
    this.credUser = this.creds()?.ssh_user ?? '';
    this.credValue = '';
    this.credGenerate = slot === 'ssh-key';
    this.credError.set(null);
    this.credPublicKey.set(null);
    this.credOpen = true;
  }

  protected credValid(): boolean {
    if (this.credSlot === 'ssh-key' && this.credGenerate) return true;
    return !!this.credValue.trim();
  }

  protected saveCred(): void {
    if (!this.credValid()) return;
    this.credSaving.set(true);
    this.credError.set(null);
    const generate = this.credSlot === 'ssh-key' && this.credGenerate;
    const body = {
      slot: this.credSlot,
      user: this.credUser.trim() || undefined,
      ...(generate ? { generate: true } : { value: this.credValue }),
    };
    this.api.setCredential(this.id(), body).subscribe({
      next: (r) => {
        this.credSaving.set(false);
        this.loadCreds();
        if (r.public_key) this.credPublicKey.set(r.public_key);
        else this.credOpen = false;
      },
      error: (e) => {
        this.credSaving.set(false);
        this.credError.set(e.status === 409 ? (e.error?.detail ?? 'Unlock the vault first.') : (e.error?.detail ?? 'Could not save the credential.'));
      },
    });
  }

  protected clearCred(slot: string): void {
    this.api.clearCredential(this.id(), slot).subscribe({
      next: () => this.loadCreds(),
      error: () => this.message.set({ type: 'danger', text: 'Could not clear the credential.' }),
    });
  }

  /** Run a hardware/firmware probe now and show the result. */
  protected discover(): void {
    this.discovering.set(true);
    this.api.discover(this.id()).subscribe({
      next: (dc) => { this.discovery.set(dc); this.discovering.set(false); },
      error: (e) => {
        this.discovering.set(false);
        this.message.set({ type: 'danger', text: e.status === 409 ? 'Unlock the vault to probe over SSH.' : (e.error?.detail ?? 'Probe failed.') });
      },
    });
  }

  protected dur(s: number): string {
    if (s < 90) return `${Math.round(s)}s`;
    if (s < 5400) return `${Math.round(s / 60)}m`;
    if (s < 172800) return `${(s / 3600).toFixed(1)}h`;
    return `${(s / 86400).toFixed(1)}d`;
  }

  private loadVersions(): void {
    this.api.backups(this.id()).subscribe({ next: (v) => this.versions.set(v), error: () => this.versions.set([]) });
  }

  /** Flip (or, with on=null, reset) whether this device pages. Optimistic, reconciled from the response. */
  protected setAlert(d: Device, on: boolean | null): void {
    this.savingAlert.set(true);
    if (on !== null) this.device.set({ ...d, alert_on_down: on, alert_overridden: true });
    this.api.setAlert(d.id, on).subscribe({
      next: (r: AlertPref) => { this.device.update((x) => x && { ...x, ...r }); this.savingAlert.set(false); },
      error: () => {
        this.device.set(d);
        this.savingAlert.set(false);
        this.message.set({ type: 'danger', text: 'Could not save the alert setting.' });
      },
    });
  }

  protected check(): void {
    this.checking.set(true);
    this.api.checkNow(this.id()).subscribe({
      next: (state) => { this.device.update((d) => d && { ...d, state }); this.checking.set(false); },
      error: () => this.checking.set(false),
    });
  }

  protected backup(): void {
    this.backingUp.set(true);
    this.api.backupNow(this.id()).subscribe({
      next: (r) => {
        this.backingUp.set(false);
        this.message.set({ type: r.changed ? 'success' : 'info',
          text: r.changed ? `New version ${r.version} stored.` : 'Config unchanged since the last version.' });
        this.loadVersions();
      },
      error: (e) => {
        this.backingUp.set(false);
        this.message.set({ type: 'danger', text: `Backup failed: ${e.error?.detail ?? e.message}` });
      },
    });
  }

  /** Detail pane opened (or toggle flipped): load the file or the diff. */
  protected openVersion(v: BackupVersion | null): void {
    if (!v) return;
    this.loadingFile.set(true);
    const diff = this.showDiff() && v.previous;
    const req = diff ? this.api.diff(this.id(), v.previous!, v.version) : this.api.file(this.id(), v.primary);
    req.subscribe((text) => {
      this.loadingFile.set(false);
      this.lines.set((text || '(no textual difference)').split('\n').map((t) => ({
        text: t,
        cls: !diff ? '' : t.startsWith('@@') ? 'diff-hunk' : t.startsWith('+') ? 'diff-add' : t.startsWith('-') ? 'diff-del' : '',
      })));
    });
  }
}
