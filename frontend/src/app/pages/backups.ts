import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ClarityModule, ClrDatagridComparatorInterface, ClrDatagridStringFilterInterface } from '@clr/angular';
import { firstValueFrom } from 'rxjs';
import { Api, Device, InboxFile, Summary, versionDate } from '../api';
import { AgoPipe, BytesPipe } from '../ui';

interface RunResult {
  device: Device;
  state: 'waiting' | 'running' | 'unchanged' | 'changed' | 'failed';
  detail?: string;
}

@Component({
  selector: 'app-backups',
  imports: [ClarityModule, FormsModule, RouterLink, AgoPipe, BytesPipe, DatePipe],
  template: `
    <div class="page-head">
      <h2>Backups</h2>
      <button class="btn btn-sm btn-primary" (click)="openRun()"><cds-icon shape="backup"></cds-icon> Back up now…</button>
    </div>

    @if (summary(); as s) {
      <div class="disk">
        <span>Backup storage: {{ s.disk.total - s.disk.free | bytes }} of {{ s.disk.total | bytes }} used</span>
        <clr-progress-bar [clrValue]="s.disk.total - s.disk.free" [clrMax]="s.disk.total" [clrCompact]="true"></clr-progress-bar>
      </div>
    }

    <h3>Device configs</h3>
    <clr-datagrid>
      <clr-dg-column [clrDgField]="'name'">Device
        <clr-dg-string-filter [clrDgStringFilter]="nameFilter"></clr-dg-string-filter>
      </clr-dg-column>
      <clr-dg-column [clrDgField]="'backup.method'">Method</clr-dg-column>
      <clr-dg-column [clrDgSortBy]="lastRunSort">Last successful run</clr-dg-column>
      <clr-dg-column [clrDgSortBy]="resultSort">Result</clr-dg-column>
      <clr-dg-column [clrDgSortBy]="versionSort">Latest version</clr-dg-column>
      <clr-dg-row *clrDgItems="let d of withBackup()" [clrDgItem]="d">
        <clr-dg-cell><a [routerLink]="['/devices', d.id]">{{ d.name }}</a></clr-dg-cell>
        <clr-dg-cell class="mono">{{ d.backup?.method }}</clr-dg-cell>
        <clr-dg-cell>{{ d.state.backup_last_ok | ago }}</clr-dg-cell>
        <clr-dg-cell>
          @if (d.state.backup_running) { <span class="spinner spinner-inline"></span> running }
          @else if (d.state.backup_ok === true) { <span class="label label-success">OK</span> }
          @else if (d.state.backup_ok === false) {
            <clr-signpost>
              <span class="label label-danger" clrSignpostTrigger>failed</span>
              <clr-signpost-content *clrIfOpen>{{ d.state.backup_error }}</clr-signpost-content>
            </clr-signpost>
          }
          @else { <span class="muted">not run yet</span> }
        </clr-dg-cell>
        <clr-dg-cell>
          @if (d.latest_backup; as lb) { {{ date(lb.version) | date: 'dd.MM.yyyy HH:mm' }} } @else { <span class="muted">none</span> }
        </clr-dg-cell>
      </clr-dg-row>

      <ng-template [(clrIfDetail)]="cfgDetail" let-d>
        <clr-dg-detail>
          <clr-dg-detail-header>{{ d.name }}</clr-dg-detail-header>
          <clr-dg-detail-body>
            <dl class="detail-kv">
              <dt>Method</dt><dd class="mono">{{ d.backup?.method }}</dd>
              <dt>Target</dt><dd class="mono">{{ d.host }}</dd>
              <dt>Last success</dt><dd>@if (d.state.backup_last_ok) { {{ d.state.backup_last_ok | ago }} } @else { never }</dd>
              <dt>Last result</dt>
              <dd>
                @if (d.state.backup_ok === true) { <span class="label label-success">OK</span> }
                @else if (d.state.backup_ok === false) { <span class="label label-danger">failed</span> }
                @else { <span class="muted">not run yet</span> }
              </dd>
              @if (d.state.backup_error) { <dt>Error</dt><dd class="mono">{{ d.state.backup_error }}</dd> }
              <dt>Latest version</dt>
              <dd>@if (d.latest_backup; as lb) { {{ date(lb.version) | date: 'dd.MM.yyyy HH:mm' }} · {{ lb.files.length }} file(s) } @else { none }</dd>
            </dl>
            <p><a [routerLink]="['/devices', d.id]">Full version history →</a></p>
          </clr-dg-detail-body>
        </clr-dg-detail>
      </ng-template>

      <clr-dg-placeholder>No device has config backup enabled.</clr-dg-placeholder>
      <clr-dg-footer>
        <span class="footer-note">Daily automatic run · a new version only when the config changed</span>
        <clr-dg-pagination #dpg [clrDgPageSize]="10">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50]">per page</clr-dg-page-size>
          {{ dpg.firstItem + 1 }}–{{ dpg.lastItem + 1 }} of {{ dpg.totalItems }}
        </clr-dg-pagination>
      </clr-dg-footer>
    </clr-datagrid>

    <h3>SFTP inbox</h3>
    <p class="muted">
      Files uploaded to <span class="mono">sftp -P 2222 backup&#64;&lt;docker-host&gt;</span> into <span class="mono">inbox/</span>,
      for example the Zyxel's official backup file. All stored versions are readable there under <span class="mono">backups/</span>.
    </p>
    <clr-datagrid>
      <clr-dg-column [clrDgField]="'name'">File
        <clr-dg-string-filter [clrDgStringFilter]="fileFilter"></clr-dg-string-filter>
      </clr-dg-column>
      <clr-dg-column [clrDgField]="'size'">Size</clr-dg-column>
      <clr-dg-column [clrDgField]="'modified'" [clrDgSortOrder]="-1">Uploaded</clr-dg-column>
      <clr-dg-row *clrDgItems="let f of inbox()" [clrDgItem]="f">
        <clr-dg-cell class="mono">{{ f.name }}</clr-dg-cell>
        <clr-dg-cell>{{ f.size | bytes }}</clr-dg-cell>
        <clr-dg-cell>{{ f.modified | date: 'dd.MM.yyyy HH:mm' }}</clr-dg-cell>
      </clr-dg-row>
      <clr-dg-placeholder>Nothing uploaded yet.</clr-dg-placeholder>
      <clr-dg-footer>
        <clr-dg-pagination #ipg [clrDgPageSize]="10">
          <clr-dg-page-size [clrPageSizeOptions]="[10, 25, 50]">per page</clr-dg-page-size>
          {{ ipg.firstItem + 1 }}–{{ ipg.lastItem + 1 }} of {{ ipg.totalItems }}
        </clr-dg-pagination>
      </clr-dg-footer>
    </clr-datagrid>

    <!-- Back up now: pick devices, then watch the progress -->
    <clr-modal [(clrModalOpen)]="modalOpen" [clrModalClosable]="!running()" clrModalSize="md">
      <h3 class="modal-title">Back up now</h3>
      <div class="modal-body">
        @if (!results().length) {
          <clr-checkbox-container>
            <label>Devices</label>
            @for (d of withBackup(); track d.id) {
              <clr-checkbox-wrapper>
                <input type="checkbox" clrCheckbox [name]="'pick-' + d.id" [ngModel]="picked().has(d.id)"
                       (ngModelChange)="pick(d.id, $event)" />
                <label>{{ d.name }} <span class="muted mono">({{ d.backup?.method }})</span></label>
              </clr-checkbox-wrapper>
            }
          </clr-checkbox-container>
        } @else {
          <clr-progress-bar [clrValue]="finished()" [clrMax]="results().length" [clrLabeled]="true"
                            [clrDisplayval]="finished() + ' / ' + results().length"
                            [clrColor]="failed() ? 'danger' : 'success'"></clr-progress-bar>
          <ul class="list-unstyled results">
            @for (r of results(); track r.device.id) {
              <li>
                @switch (r.state) {
                  @case ('running') { <span class="spinner spinner-inline"></span> }
                  @case ('changed') { <span class="label label-success">new version</span> }
                  @case ('unchanged') { <span class="label label-info">unchanged</span> }
                  @case ('failed') { <span class="label label-danger">failed</span> }
                  @default { <span class="label">waiting</span> }
                }
                {{ r.device.name }} @if (r.detail) { <span class="muted">– {{ r.detail }}</span> }
              </li>
            }
          </ul>
        }
      </div>
      <div class="modal-footer">
        @if (!results().length) {
          <button type="button" class="btn btn-outline" (click)="modalOpen = false">Cancel</button>
          <button type="button" class="btn btn-primary" [disabled]="!picked().size" (click)="run()">Back up {{ picked().size }}</button>
        } @else {
          <button type="button" class="btn btn-primary" [disabled]="running()" (click)="closeRun()">Close</button>
        }
      </div>
    </clr-modal>
  `,
  styles: `
    .disk { max-width: 32rem; margin-bottom: 0.5rem; font-size: 0.8rem; }
    .results li { margin: 0.35rem 0; }
    .footer-note { margin-right: auto; opacity: 0.8; }
    .detail-kv { display: grid; grid-template-columns: max-content 1fr; gap: 0.35rem 1rem; margin: 0 0 0.6rem; }
    .detail-kv dt { font-weight: 600; opacity: 0.7; }
    .detail-kv dd { margin: 0; }
  `,
})
export class BackupsPage implements OnInit {
  private api = inject(Api);
  protected withBackup = signal<Device[]>([]);
  protected inbox = signal<InboxFile[]>([]);
  protected summary = signal<Summary | null>(null);
  protected modalOpen = false;
  protected picked = signal(new Set<string>());
  protected results = signal<RunResult[]>([]);
  protected running = signal(false);
  protected date = versionDate;
  protected cfgDetail: Device | null = null;

  // Datagrid sort/filter helpers.
  protected nameFilter: ClrDatagridStringFilterInterface<Device> = {
    accepts: (d, s) => d.name.toLowerCase().includes(s.toLowerCase()),
  };
  protected fileFilter: ClrDatagridStringFilterInterface<InboxFile> = {
    accepts: (f, s) => f.name.toLowerCase().includes(s.toLowerCase()),
  };
  protected lastRunSort: ClrDatagridComparatorInterface<Device> = {
    compare: (a, b) => (a.state.backup_last_ok ?? 0) - (b.state.backup_last_ok ?? 0),
  };
  protected resultSort: ClrDatagridComparatorInterface<Device> = {
    compare: (a, b) => this.resultRank(a) - this.resultRank(b),
  };
  protected versionSort: ClrDatagridComparatorInterface<Device> = {
    compare: (a, b) => (a.latest_backup?.version ?? '').localeCompare(b.latest_backup?.version ?? ''),
  };

  /** Failures first, then running, OK, never-run — so problems sort to the top. */
  private resultRank(d: Device): number {
    if (d.state.backup_ok === false) return 0;
    if (d.state.backup_running) return 1;
    if (d.state.backup_ok === true) return 2;
    return 3;
  }

  ngOnInit(): void {
    this.reload();
    this.api.inbox().subscribe((f) => this.inbox.set(f));
    this.api.summary().subscribe((s) => this.summary.set(s));
  }

  private reload(): void {
    this.api.devices().subscribe((d) => this.withBackup.set(d.filter((x) => x.backup)));
  }

  protected finished(): number {
    return this.results().filter((r) => !['waiting', 'running'].includes(r.state)).length;
  }

  protected failed(): number {
    return this.results().filter((r) => r.state === 'failed').length;
  }

  protected openRun(): void {
    this.picked.set(new Set(this.withBackup().map((d) => d.id)));
    this.results.set([]);
    this.modalOpen = true;
  }

  protected pick(id: string, on: boolean): void {
    this.picked.update((s) => { const n = new Set(s); if (on) n.add(id); else n.delete(id); return n; });
  }

  /** One device after the other, so the routers aren't hit in parallel. */
  protected async run(): Promise<void> {
    const list = this.withBackup().filter((d) => this.picked().has(d.id));
    this.results.set(list.map((device) => ({ device, state: 'waiting' })));
    this.running.set(true);
    for (const [i, d] of list.entries()) {
      this.update(i, { state: 'running' });
      try {
        const r = await firstValueFrom(this.api.backupNow(d.id));
        this.update(i, { state: r.changed ? 'changed' : 'unchanged' });
      } catch (e: any) {
        this.update(i, { state: 'failed', detail: e?.error?.detail ?? e?.message });
      }
    }
    this.running.set(false);
    this.reload();
  }

  protected closeRun(): void {
    this.modalOpen = false;
    this.results.set([]);
  }

  private update(i: number, patch: Partial<RunResult>): void {
    this.results.update((list) => list.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  }
}
