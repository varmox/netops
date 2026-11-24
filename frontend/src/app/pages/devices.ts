import { KeyValuePipe } from '@angular/common';
import { Component, DestroyRef, OnInit, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ClarityModule, ClrDatagridComparatorInterface, ClrDatagridFilterInterface } from '@clr/angular';
import { Subject, firstValueFrom, switchMap } from 'rxjs';
import { Api, Device, DeviceSpec, Status } from '../api';
import { AgoPipe, StatusLabel, mergeById, refreshTicks } from '../ui';
import { VaultService } from '../vault';

const SEVERITY: Record<Status, number> = { down: 0, degraded: 1, unknown: 2, up: 3 };
const STATUSES: Status[] = ['down', 'degraded', 'up', 'unknown'];

/** Down first, then degraded, unknown, up. */
class StatusComparator implements ClrDatagridComparatorInterface<Device> {
  compare(a: Device, b: Device): number {
    return SEVERITY[a.state.status] - SEVERITY[b.state.status];
  }
}

function pingMs(d: Device): number | null {
  return d.state.checks.find((c) => c.check === 'ping')?.latency_ms ?? null;
}

class PingComparator implements ClrDatagridComparatorInterface<Device> {
  compare(a: Device, b: Device): number {
    return (pingMs(a) ?? Infinity) - (pingMs(b) ?? Infinity);
  }
}

/** Column filter: tick the states to show. */
@Component({
  selector: 'app-status-filter',
  imports: [ClarityModule, FormsModule],
  template: `
    <clr-checkbox-container>
      <label>Show status</label>
      @for (s of statuses; track s) {
        <clr-checkbox-wrapper>
          <input type="checkbox" clrCheckbox [name]="'f-' + s" [ngModel]="selected.has(s)" (ngModelChange)="toggle(s, $event)" />
          <label>{{ s }}</label>
        </clr-checkbox-wrapper>
      }
    </clr-checkbox-container>
  `,
})
export class StatusFilter implements ClrDatagridFilterInterface<Device> {
  readonly changes = new Subject<boolean>();
  protected statuses = STATUSES;
  protected selected = new Set<Status>();

  isActive(): boolean {
    return this.selected.size > 0;
  }

  accepts(d: Device): boolean {
    return this.selected.has(d.state.status);
  }

  protected toggle(s: Status, on: boolean): void {
    if (on) this.selected.add(s); else this.selected.delete(s);
    this.changes.next(true);
  }
}

@Component({
  selector: 'app-devices',
  imports: [ClarityModule, FormsModule, RouterLink, StatusLabel, StatusFilter, AgoPipe, KeyValuePipe],
  template: `
    <div class="page-head">
      <h2>Devices</h2>
      <div class="head-right">
        <span class="muted">Inventory: <span class="mono">config/devices.yml</span></span>
        <button class="btn btn-sm btn-primary" (click)="openCreate()"><cds-icon shape="plus"></cds-icon> Add device</button>
      </div>
    </div>

    @if (bulk(); as b) {
      <div class="bulk">
        <span>{{ b.label }} {{ b.done }}/{{ b.total }}</span>
        <clr-progress-bar [clrValue]="b.done" [clrMax]="b.total" [clrLabeled]="false"
                          [clrColor]="b.failed ? 'danger' : 'success'"></clr-progress-bar>
      </div>
    }

    <clr-datagrid [(clrDgSelected)]="selected" [clrDgLoading]="loading()">
      <clr-dg-action-bar>
        <div class="btn-group" role="group" aria-label="Actions for selected devices">
          <button type="button" class="btn btn-sm btn-secondary" (click)="checkSelected()" [disabled]="!selected.length || !!bulk()">
            <cds-icon shape="refresh"></cds-icon> Check ({{ selected.length }})
          </button>
          <button type="button" class="btn btn-sm btn-secondary" (click)="backupSelected()"
                  [disabled]="!backupable().length || !!bulk()">
            <cds-icon shape="backup"></cds-icon> Back up ({{ backupable().length }})
          </button>
        </div>
      </clr-dg-action-bar>

      <clr-dg-column [clrDgSortBy]="statusSort" [clrDgSortOrder]="1">
        Status
        <clr-dg-filter [clrDgFilter]="statusFilter"><app-status-filter #statusFilter /></clr-dg-filter>
      </clr-dg-column>
      <clr-dg-column [clrDgField]="'name'">Name</clr-dg-column>
      <clr-dg-column [clrDgField]="'role'">
        <ng-container *clrDgHideableColumn="{ hidden: false }">Role</ng-container>
      </clr-dg-column>
      <clr-dg-column [clrDgField]="'host'">Address</clr-dg-column>
      <clr-dg-column [clrDgField]="'type'">
        <ng-container *clrDgHideableColumn="{ hidden: true }">Type</ng-container>
      </clr-dg-column>
      <clr-dg-column>
        <ng-container *clrDgHideableColumn="{ hidden: false }">Checks</ng-container>
      </clr-dg-column>
      <clr-dg-column [clrDgSortBy]="pingSort">
        <ng-container *clrDgHideableColumn="{ hidden: false }">Ping</ng-container>
      </clr-dg-column>
      <clr-dg-column>
        <ng-container *clrDgHideableColumn="{ hidden: false }">Config backup</ng-container>
      </clr-dg-column>

      <clr-dg-row *clrDgItems="let d of devices()" [clrDgItem]="d">
        <clr-dg-action-overflow>
          <a class="action-item" [routerLink]="['/devices', d.id]">Open</a>
          <button class="action-item" (click)="check(d)">Check now</button>
          @if (d.backup) { <button class="action-item" (click)="backup([d], 'Backing up')">Back up now</button> }
          @if (d.managed) {
            <button class="action-item" (click)="openEdit(d)">Edit</button>
            <button class="action-item" (click)="askDelete(d)">Delete</button>
          }
        </clr-dg-action-overflow>
        <clr-dg-cell><app-status [status]="d.state.status" /></clr-dg-cell>
        <clr-dg-cell><a [routerLink]="['/devices', d.id]">{{ d.name }}</a>
          @if (d.managed) { <span class="label label-info" title="Added in the UI — editable here">added</span> }</clr-dg-cell>
        <clr-dg-cell>{{ d.role }}</clr-dg-cell>
        <clr-dg-cell class="mono">{{ d.host }}</clr-dg-cell>
        <clr-dg-cell>{{ d.type }}</clr-dg-cell>
        <clr-dg-cell>
          <span class="label" [class.label-success]="passed(d) === d.state.checks.length" [class.label-danger]="passed(d) === 0"
                [class.label-warning]="passed(d) > 0 && passed(d) < d.state.checks.length">
            {{ passed(d) }}/{{ d.state.checks.length }}
          </span>
        </clr-dg-cell>
        <clr-dg-cell>{{ ping(d) }}</clr-dg-cell>
        <clr-dg-cell>
          @if (!d.backup) { <span class="muted">watch only</span> }
          @else if (d.state.backup_running) { <span class="spinner spinner-inline"></span> running }
          @else if (d.state.backup_ok === false) { <span class="label label-danger">failed</span> }
          @else if (d.state.backup_last_ok) { {{ d.state.backup_last_ok | ago }} }
          @else { <span class="muted">none yet</span> }
        </clr-dg-cell>
      </clr-dg-row>

      <!-- Detail pane: the row's checks and facts beside the list -->
      <ng-template [(clrIfDetail)]="detail" let-d>
        <clr-dg-detail>
          <clr-dg-detail-header>{{ d.name }} <app-status [status]="d.state.status" /></clr-dg-detail-header>
          <clr-dg-detail-body>
            <p class="muted">{{ d.role }} · <span class="mono">{{ d.host }}</span></p>
            <table class="table table-compact">
              <thead><tr><th class="left">Check</th><th>Result</th><th>Latency</th></tr></thead>
              <tbody>
                @for (c of d.state.checks; track c.check) {
                  <tr>
                    <td class="left mono">{{ c.check }}</td>
                    <td><span class="label" [class.label-success]="c.ok" [class.label-danger]="!c.ok">{{ c.detail }}</span></td>
                    <td>{{ c.latency_ms !== null ? c.latency_ms.toFixed(1) + ' ms' : '–' }}</td>
                  </tr>
                }
              </tbody>
            </table>
            @if (hasFacts(d)) {
              <clr-stack-view>
                @for (f of d.facts | keyvalue; track f.key) {
                  <clr-stack-block><clr-stack-label>{{ f.key }}</clr-stack-label><clr-stack-content>{{ f.value }}</clr-stack-content></clr-stack-block>
                }
              </clr-stack-view>
            }
            @if (d.notes) { <p>{{ d.notes }}</p> }
            <a class="btn btn-sm btn-primary" [routerLink]="['/devices', d.id]">Open device</a>
          </clr-dg-detail-body>
        </clr-dg-detail>
      </ng-template>

      <clr-dg-placeholder>No device matches the filter.</clr-dg-placeholder>
      <clr-dg-footer>
        <clr-dg-pagination #pagination [clrDgPageSize]="10">
          <clr-dg-page-size [clrPageSizeOptions]="[5, 10, 25, 50]">Devices per page</clr-dg-page-size>
          {{ pagination.firstItem + 1 }}–{{ pagination.lastItem + 1 }} of {{ pagination.totalItems }} devices
        </clr-dg-pagination>
      </clr-dg-footer>
    </clr-datagrid>

    <!-- Add / edit a managed device -->
    <clr-modal [(clrModalOpen)]="formOpen" [clrModalClosable]="!saving()" clrModalSize="lg">
      <h3 class="modal-title">{{ editing() ? 'Edit device' : 'Add device' }}</h3>
      <div class="modal-body">
        @if (result(); as res) {
          @if (res.publicKey) {
            <p><strong>{{ form.name }}</strong> added, and a keypair was stored in the vault. Install this
              <strong>public key</strong> on the device so it accepts the connection:</p>
            <pre class="cmd">{{ res.publicKey }}</pre>
            <p class="muted sm">Linux: append to <span class="mono">~/.ssh/authorized_keys</span> of the SSH user ·
              MikroTik: <span class="mono">/user/ssh-keys import public-key-file=…</span></p>
          } @else if (res.credError) {
            <clr-alert clrAlertType="warning" [clrAlertClosable]="false" clrAlertSize="sm"><clr-alert-item>
              <span class="alert-text"><strong>{{ form.name }}</strong> was added, but the credential wasn't saved:
                {{ res.credError }}. You can set it on the device's page.</span></clr-alert-item></clr-alert>
          } @else {
            <p><strong>{{ form.name }}</strong> added.</p>
          }
        } @else {
        <form clrForm clrLayout="horizontal" (ngSubmit)="submit()">
          <clr-input-container>
            <label>ID</label>
            <input clrInput name="id" [(ngModel)]="form.id" [disabled]="editing()" placeholder="nas-01" required />
            <clr-control-helper>Lowercase letters, digits, hyphens. Can't be changed later.</clr-control-helper>
          </clr-input-container>
          <clr-input-container>
            <label>Name</label>
            <input clrInput name="name" [(ngModel)]="form.name" placeholder="Synology NAS" required />
          </clr-input-container>
          <clr-select-container>
            <label>Type</label>
            <select clrSelect name="type" [(ngModel)]="form.type">
              @for (t of types; track t) { <option [value]="t">{{ t }}</option> }
            </select>
            <clr-control-helper>mikrotik / linux enable the richest hardware discovery.</clr-control-helper>
          </clr-select-container>
          <clr-input-container>
            <label>Address</label>
            <input clrInput name="host" [(ngModel)]="form.host" placeholder="192.168.1.50 or a hostname" required />
          </clr-input-container>
          <clr-input-container>
            <label>Role</label>
            <input clrInput name="role" [(ngModel)]="form.role" placeholder="Backup NAS" />
          </clr-input-container>

          <div class="clr-form-control checks-row">
            <label class="clr-control-label">Checks</label>
            <div class="clr-control-container">
              <clr-checkbox-wrapper>
                <input type="checkbox" clrCheckbox name="ping" [(ngModel)]="chkPing" /> <label>Ping</label>
              </clr-checkbox-wrapper>
              <div class="inline-field">
                <label>TCP port</label>
                <input class="clr-input" type="number" name="tcp" [(ngModel)]="chkTcp" placeholder="none" min="1" max="65535" />
              </div>
              <div class="inline-field wide">
                <label>HTTP(S) URL</label>
                <input class="clr-input" name="http" [(ngModel)]="chkHttp" placeholder="https://host/" />
              </div>
            </div>
          </div>

          <clr-select-container>
            <label>Alerting</label>
            <select clrSelect name="alert" [(ngModel)]="form.alert">
              <option [ngValue]="null">Default (only infrastructure pages)</option>
              <option [ngValue]="true">Always page when down</option>
              <option [ngValue]="false">Never page (track only)</option>
            </select>
          </clr-select-container>
          <clr-checkbox-container>
            <label>Protected</label>
            <clr-checkbox-wrapper>
              <input type="checkbox" clrCheckbox name="protected" [(ngModel)]="form.protected" />
              <label>Never quarantine (infrastructure)</label>
            </clr-checkbox-wrapper>
          </clr-checkbox-container>
          <clr-textarea-container>
            <label>Notes</label>
            <textarea clrTextarea name="notes" [(ngModel)]="form.notes" rows="2"></textarea>
          </clr-textarea-container>

          @if (!editing()) {
            <div class="cred-divider">Credentials <span class="muted">· optional, stored in the vault</span></div>
            @if (vaultReady()) {
              <clr-input-container>
                <label>SSH user</label>
                <input clrInput name="cuser" [(ngModel)]="credUser" placeholder="netops" />
              </clr-input-container>
              <clr-select-container>
                <label>Credential</label>
                <select clrSelect name="ctype" [(ngModel)]="credType">
                  <option value="none">None — add later</option>
                  <option value="ssh-generate">Generate SSH keypair</option>
                  <option value="ssh-paste">Paste SSH private key</option>
                  <option value="password">Password</option>
                </select>
                <clr-control-helper>Wired into this device automatically. Values are write-only.</clr-control-helper>
              </clr-select-container>
              @if (credType === 'ssh-paste' || credType === 'password') {
                <clr-textarea-container>
                  <label>{{ credType === 'password' ? 'Password' : 'Private key' }}</label>
                  <textarea clrTextarea name="cval" [(ngModel)]="credValue" rows="3"
                            placeholder="{{ credType === 'password' ? '' : '-----BEGIN OPENSSH PRIVATE KEY-----' }}"></textarea>
                </clr-textarea-container>
              }
            } @else {
              <div class="clr-form-control">
                <label class="clr-control-label">Credential</label>
                <div class="clr-control-container">
                  <span class="muted sm">The vault is {{ vaultStatusText() }}. Set it up on the
                    <a routerLink="/vault" (click)="formOpen = false">Vault page</a>, then add credentials from the device's page.</span>
                </div>
              </div>
            }
          }
        </form>
        @if (formError(); as e) {
          <clr-alert clrAlertType="danger" [clrAlertClosable]="false" clrAlertSize="sm">
            <clr-alert-item><span class="alert-text">{{ e }}</span></clr-alert-item></clr-alert>
        }
        <p class="muted sm">Saved to the <span class="mono">/data</span> store — <span class="mono">config/devices.yml</span> is never touched.</p>
        }
      </div>
      <div class="modal-footer">
        @if (result()) {
          <button type="button" class="btn btn-primary" (click)="closeResult()">Done</button>
        } @else {
          <button type="button" class="btn btn-outline" [disabled]="saving()" (click)="formOpen = false">Cancel</button>
          <button type="button" class="btn btn-primary" [disabled]="saving() || !valid()" (click)="submit()">
            {{ saving() ? 'Saving…' : (editing() ? 'Save changes' : 'Add device') }}
          </button>
        }
      </div>
    </clr-modal>

    <!-- Delete confirmation -->
    <clr-modal [(clrModalOpen)]="deleteOpen" clrModalSize="sm">
      <h3 class="modal-title">Delete device</h3>
      <div class="modal-body">
        <p>Remove <strong>{{ toDelete()?.name }}</strong> from the inventory?</p>
        <p class="muted sm">This only removes the UI-added device from the <span class="mono">/data</span> store. It does not touch
          <span class="mono">devices.yml</span> and nothing is changed on the device itself.</p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" [disabled]="saving()" (click)="deleteOpen = false">Cancel</button>
        <button type="button" class="btn btn-danger" [disabled]="saving()" (click)="doDelete()">{{ saving() ? 'Deleting…' : 'Delete' }}</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .bulk { display: flex; align-items: center; gap: 0.8rem; margin-bottom: 0.5rem; }
    .bulk clr-progress-bar { flex: 1; }
    clr-dg-detail-header app-status { font-size: 0.75rem; margin-left: 0.4rem; }
    .head-right { display: flex; align-items: center; gap: 0.8rem; }
    .sm { font-size: 0.78rem; }
    .checks-row .clr-control-container { display: flex; flex-wrap: wrap; align-items: center; gap: 0.3rem 1rem; }
    .inline-field { display: flex; align-items: center; gap: 0.4rem; }
    .inline-field.wide { flex: 1; min-width: 12rem; }
    .inline-field.wide input { flex: 1; }
    .inline-field label { font-size: 0.76rem; opacity: 0.8; margin: 0; }
    .cred-divider { margin: 1rem 0 0.4rem; font-weight: 600; border-top: 1px solid var(--clr-color-neutral-300, #e0e0e0); padding-top: 0.7rem; }
    .cred-divider .muted { font-weight: 400; font-size: 0.78rem; }
    .cmd { background: var(--clr-color-neutral-100, #f3f3f3); border-radius: 4px; padding: 0.5rem 0.7rem;
      font-size: 0.74rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  `,
})
export class DevicesPage implements OnInit {
  private api = inject(Api);
  private destroyRef = inject(DestroyRef);
  private ticks = refreshTicks();
  protected devices = signal<Device[]>([]);
  protected loading = signal(true);
  protected selected: Device[] = [];
  protected detail: Device | null = null;
  protected bulk = signal<{ label: string; done: number; total: number; failed: number } | null>(null);
  protected statusSort = new StatusComparator();
  protected pingSort = new PingComparator();

  // Add/edit form state.
  protected readonly types = ['generic', 'linux', 'mikrotik', 'zyxel', 'tv', 'speaker', 'camera', 'phone', 'printer', 'switch'];
  protected formOpen = false;
  protected deleteOpen = false;
  protected editing = signal(false);
  protected saving = signal(false);
  protected formError = signal<string | null>(null);
  protected toDelete = signal<Device | null>(null);
  protected form = this.blankForm();
  protected chkPing = true;
  protected chkTcp: number | null = null;
  protected chkHttp = '';
  private formLinks: Record<string, string> = {};
  private formFacts: Record<string, string> = {};
  // Credential setup during create (chained after the device is created).
  private vault = inject(VaultService);
  protected credType: 'none' | 'ssh-generate' | 'ssh-paste' | 'password' = 'none';
  protected credUser = '';
  protected credValue = '';
  protected result = signal<{ publicKey: string | null; credError: string | null } | null>(null);

  protected vaultReady(): boolean {
    const s = this.vault.status();
    return !!(s?.initialized && s?.unlocked);
  }

  protected vaultStatusText(): string {
    const s = this.vault.status();
    return !s?.initialized ? 'not set up' : !s.unlocked ? 'locked' : 'ready';
  }

  private blankForm() {
    return { id: '', name: '', type: 'generic', host: '', role: '', notes: '', protected: false, alert: null as boolean | null };
  }

  ngOnInit(): void {
    this.ticks.pipe(switchMap(() => this.api.devices()), takeUntilDestroyed(this.destroyRef)).subscribe((d) => {
      this.devices.set(mergeById(this.devices(), d));
      this.loading.set(false);
    });
  }

  protected backupable(): Device[] {
    return this.selected.filter((d) => d.backup);
  }

  // ---- add / edit / delete a managed device ----

  protected openCreate(): void {
    this.form = this.blankForm();
    this.chkPing = true; this.chkTcp = null; this.chkHttp = '';
    this.formLinks = {}; this.formFacts = {};
    this.credType = 'none'; this.credUser = ''; this.credValue = '';
    this.result.set(null);
    this.vault.refresh().subscribe({ error: () => {} });   // so the credential options reflect the live vault state
    this.editing.set(false); this.formError.set(null); this.formOpen = true;
  }

  protected openEdit(d: Device): void {
    this.form = { id: d.id, name: d.name, type: d.type, host: d.host, role: d.role, notes: d.notes,
      protected: d.protected, alert: d.alert_overridden ? d.alert_on_down : null };
    this.chkPing = d.checks.some((c) => c.type === 'ping');
    this.chkTcp = (d.checks.find((c) => c.type === 'tcp')?.target as number) ?? null;
    this.chkHttp = (d.checks.find((c) => c.type === 'http')?.target as string) ?? '';
    this.formLinks = { ...d.links }; this.formFacts = { ...d.facts };
    this.editing.set(true); this.formError.set(null); this.formOpen = true;
  }

  protected valid(): boolean {
    if (!(this.form.id.trim() && this.form.name.trim() && this.form.host.trim())) return false;
    if (!this.editing() && this.vaultReady() && (this.credType === 'ssh-paste' || this.credType === 'password')) {
      return !!this.credValue.trim();
    }
    return true;
  }

  private buildSpec(): DeviceSpec {
    const checks: { type: string; target?: string | number }[] = [];
    if (this.chkPing) checks.push({ type: 'ping' });
    if (this.chkTcp) checks.push({ type: 'tcp', target: Number(this.chkTcp) });
    if (this.chkHttp.trim()) checks.push({ type: 'http', target: this.chkHttp.trim() });
    return { ...this.form, id: this.form.id.trim(), checks, links: this.formLinks, facts: this.formFacts };
  }

  protected submit(): void {
    if (!this.valid()) return;
    this.saving.set(true); this.formError.set(null);
    const spec = this.buildSpec();
    if (this.editing()) {
      this.api.updateDevice(spec.id, spec).subscribe({
        next: () => { this.saving.set(false); this.formOpen = false; this.reload(); },
        error: (e) => { this.saving.set(false); this.formError.set(e.error?.detail ?? 'Could not save the device.'); },
      });
      return;
    }
    this.api.createDevice(spec).subscribe({
      next: () => this.afterCreate(spec.id),
      error: (e) => { this.saving.set(false); this.formError.set(e.error?.detail ?? 'Could not save the device.'); },
    });
  }

  /** Device created — optionally store its credential, then show the result (public key / note). */
  private afterCreate(id: string): void {
    this.reload();
    if (this.credType === 'none' || !this.vaultReady()) {
      this.saving.set(false); this.formOpen = false;
      return;
    }
    const slot = this.credType === 'password' ? 'password' : 'ssh-key';
    const body: { slot: string; value?: string; generate?: boolean; user?: string } = {
      slot, user: this.credUser.trim() || undefined,
      ...(this.credType === 'ssh-generate' ? { generate: true } : { value: this.credValue }),
    };
    this.api.setCredential(id, body).subscribe({
      next: (r) => { this.saving.set(false); this.result.set({ publicKey: r.public_key, credError: null }); this.reload(); },
      error: (e) => { this.saving.set(false); this.result.set({ publicKey: null, credError: e.error?.detail ?? 'the vault may be locked' }); },
    });
  }

  protected closeResult(): void {
    this.formOpen = false; this.result.set(null); this.reload();
  }

  protected askDelete(d: Device): void {
    this.toDelete.set(d); this.deleteOpen = true;
  }

  protected doDelete(): void {
    const d = this.toDelete();
    if (!d) return;
    this.saving.set(true);
    this.api.deleteDevice(d.id).subscribe({
      next: () => { this.saving.set(false); this.deleteOpen = false; this.reload(); },
      error: () => { this.saving.set(false); this.deleteOpen = false; },
    });
  }

  private reload(): void {
    this.api.devices().subscribe((d) => this.devices.set(d));
  }

  protected hasFacts(d: Device): boolean {
    return Object.keys(d.facts ?? {}).length > 0;
  }

  protected passed(d: Device): number {
    return d.state.checks.filter((c) => c.ok).length;
  }

  protected ping(d: Device): string {
    const ms = pingMs(d);
    return ms != null ? `${ms.toFixed(1)} ms` : '–';
  }

  protected check(d: Device): void {
    this.api.checkNow(d.id).subscribe((state) => Object.assign(d, { state }));
  }

  protected async checkSelected(): Promise<void> {
    await this.run(this.selected, 'Checking', async (d) => {
      Object.assign(d, { state: await firstValueFrom(this.api.checkNow(d.id)) });
    });
  }

  protected backupSelected(): void {
    this.backup(this.backupable(), 'Backing up');
  }

  /** One device after the other, so the routers aren't hit in parallel. */
  protected async backup(list: Device[], label: string): Promise<void> {
    await this.run(list, label, async (d) => { await firstValueFrom(this.api.backupNow(d.id)); });
    this.api.devices().subscribe((fresh) => this.devices.set(mergeById(this.devices(), fresh)));
  }

  private async run(list: Device[], label: string, fn: (d: Device) => Promise<void>): Promise<void> {
    const state = { label, done: 0, total: list.length, failed: 0 };
    this.bulk.set({ ...state });
    for (const d of list) {
      try { await fn(d); } catch { state.failed++; }
      state.done++;
      this.bulk.set({ ...state });
    }
    setTimeout(() => this.bulk.set(null), 1500);
  }
}
