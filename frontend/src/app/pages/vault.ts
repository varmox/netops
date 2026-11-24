import { HttpClient } from '@angular/common/http';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { firstValueFrom } from 'rxjs';
import { errorText } from '../auth';
import { AgoPipe } from '../ui';
import { VaultService } from '../vault';

interface SecretRow {
  name: string;
  kind: string;
  description: string;
  updated: number;
}

@Component({
  selector: 'app-vault',
  imports: [ClarityModule, FormsModule, AgoPipe],
  template: `
    <div class="page-head">
      <h2>Vault</h2>
      @if (vs.status()?.unlocked) {
        <button class="btn btn-sm btn-outline" (click)="lock()"><cds-icon shape="lock"></cds-icon> Lock now</button>
      }
    </div>
    <p class="muted">Device credentials (SSH keys, API tokens, passwords), encrypted with a key derived from your vault
      passphrase. After every restart the vault is locked until you unlock it here; scans and backups that need
      credentials wait until then. Values can be set or replaced, never read back.</p>
    @if (message(); as m) {
      <clr-alert [clrAlertType]="m.type" [clrAlertClosable]="true" (clrAlertClosedChange)="message.set(null)">
        <clr-alert-item><span class="alert-text">{{ m.text }}</span></clr-alert-item>
      </clr-alert>
    }

    @if (vs.status(); as s) {
      @if (!s.initialized) {
        <div class="card narrow"><div class="card-header">Set up the vault</div><div class="card-block">
          <clr-alert clrAlertType="warning" [clrAlertClosable]="false">
            <clr-alert-item><span class="alert-text">There is no way to recover the vault without this passphrase. Store it
              in your password manager.</span></clr-alert-item>
          </clr-alert>
          <form (ngSubmit)="init()" #f="ngForm">
            <clr-password-container><label>Vault passphrase</label>
              <input clrPassword name="p1" [(ngModel)]="p1" required autocomplete="new-password" />
              <clr-control-helper>At least 15 characters, different from your login password.</clr-control-helper>
            </clr-password-container>
            <clr-password-container><label>Repeat</label>
              <input clrPassword name="p2" [(ngModel)]="p2" required autocomplete="new-password" />
            </clr-password-container>
            <button type="submit" class="btn btn-primary" [disabled]="busy() || !f.valid">{{ busy() ? 'Deriving key…' : 'Create vault' }}</button>
          </form>
        </div></div>
      } @else if (!s.unlocked) {
        <div class="card narrow"><div class="card-header"><cds-icon shape="lock"></cds-icon> Vault is locked</div><div class="card-block">
          <form (ngSubmit)="unlock()" #u="ngForm">
            <clr-password-container><label>Vault passphrase</label>
              <input clrPassword name="up" [(ngModel)]="p1" required autofocus autocomplete="current-password" />
            </clr-password-container>
            <button type="submit" class="btn btn-primary" [disabled]="busy() || !u.valid">{{ busy() ? 'Unlocking…' : 'Unlock' }}</button>
          </form>
        </div></div>
      } @else {
        <div class="status"><span class="label label-success"><cds-icon shape="unlock"></cds-icon> unlocked {{ s.unlocked_at | ago }}</span>
          <span class="muted">{{ s.secrets }} secrets</span></div>

        <clr-datagrid>
          <clr-dg-column [clrDgField]="'name'">Name</clr-dg-column>
          <clr-dg-column [clrDgField]="'kind'">Kind</clr-dg-column>
          <clr-dg-column>Description</clr-dg-column>
          <clr-dg-column [clrDgField]="'updated'">Updated</clr-dg-column>
          <clr-dg-row *clrDgItems="let x of secrets()" [clrDgItem]="x">
            <clr-dg-action-overflow>
              <button class="action-item" (click)="edit(x)">Replace value</button>
              <button class="action-item" (click)="remove(x.name)">Delete</button>
            </clr-dg-action-overflow>
            <clr-dg-cell class="mono">{{ x.name }}</clr-dg-cell>
            <clr-dg-cell><span class="label">{{ x.kind }}</span></clr-dg-cell>
            <clr-dg-cell>{{ x.description }}</clr-dg-cell>
            <clr-dg-cell>{{ x.updated | ago }}</clr-dg-cell>
          </clr-dg-row>
          <clr-dg-placeholder>No secrets yet.</clr-dg-placeholder>
        </clr-datagrid>

        <div class="btn-group">
          <button class="btn btn-sm btn-primary" (click)="edit(null)"><cds-icon shape="plus"></cds-icon> Add secret</button>
          <button class="btn btn-sm btn-outline" (click)="importLegacy()">Import existing credentials</button>
          <button class="btn btn-sm btn-outline" (click)="changeOpen = true">Change passphrase</button>
        </div>
      }
    }

    <clr-modal [(clrModalOpen)]="editOpen" clrModalSize="md">
      <h3 class="modal-title">{{ editing ? 'Replace ' + form.name : 'Add a secret' }}</h3>
      <div class="modal-body">
        <form class="clr-form clr-form-horizontal">
          <clr-input-container><label>Name</label>
            <input clrInput name="n" [(ngModel)]="form.name" [disabled]="editing" placeholder="mikrotik-ssh-key" />
            <clr-control-helper>lowercase, digits, . _ -</clr-control-helper>
          </clr-input-container>
          <clr-select-container><label>Kind</label>
            <select clrSelect name="k" [(ngModel)]="form.kind">
              <option value="password">password</option><option value="ssh-key">ssh-key</option>
              <option value="api-token">api-token</option><option value="other">other</option>
            </select>
          </clr-select-container>
          <clr-textarea-container><label>Value</label>
            <textarea clrTextarea name="v" [(ngModel)]="form.value" rows="4" autocomplete="off" spellcheck="false"></textarea>
          </clr-textarea-container>
          <clr-input-container><label>Description</label>
            <input clrInput name="d" [(ngModel)]="form.description" />
          </clr-input-container>
        </form>
      </div>
      <div class="modal-footer">
        <button class="btn btn-outline" (click)="editOpen = false">Cancel</button>
        <button class="btn btn-primary" [disabled]="!form.name || !form.value" (click)="save()">Save</button>
      </div>
    </clr-modal>

    <clr-modal [(clrModalOpen)]="changeOpen" clrModalSize="md">
      <h3 class="modal-title">Change vault passphrase</h3>
      <div class="modal-body">
        <form class="clr-form">
          <clr-password-container><label>Current passphrase</label><input clrPassword name="c" [(ngModel)]="cur" autocomplete="current-password" /></clr-password-container>
          <clr-password-container><label>New passphrase</label><input clrPassword name="nn" [(ngModel)]="p1" autocomplete="new-password" /></clr-password-container>
        </form>
      </div>
      <div class="modal-footer">
        <button class="btn btn-outline" (click)="changeOpen = false">Cancel</button>
        <button class="btn btn-primary" [disabled]="busy() || !cur || p1.length < 15" (click)="change()">{{ busy() ? 'Re-encrypting…' : 'Change' }}</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .narrow { max-width: 34rem; }
    .status { display: flex; gap: 0.8rem; align-items: center; margin: 0.5rem 0; }
    .btn-group { margin-top: 0.8rem; }
  `,
})
export class VaultPage implements OnInit {
  protected vs = inject(VaultService);
  private http = inject(HttpClient);
  protected secrets = signal<SecretRow[]>([]);
  protected message = signal<{ type: 'success' | 'danger'; text: string } | null>(null);
  protected busy = signal(false);
  protected p1 = '';
  protected p2 = '';
  protected cur = '';
  protected editOpen = false;
  protected changeOpen = false;
  protected editing = false;
  protected form = { name: '', kind: 'password', value: '', description: '' };

  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    this.vs.refresh().subscribe((s) => {
      if (s.unlocked) this.http.get<SecretRow[]>('/api/vault/secrets').subscribe((x) => this.secrets.set(x));
    });
  }

  private async act(fn: () => Promise<unknown>, ok: string): Promise<void> {
    this.busy.set(true);
    try {
      await fn();
      if (ok) this.message.set({ type: 'success', text: ok });
    } catch (e) {
      this.message.set({ type: 'danger', text: errorText(e) });
    }
    this.busy.set(false);
    this.p1 = this.p2 = this.cur = '';
    this.load();
  }

  protected init(): void {
    if (this.p1 !== this.p2) {
      this.message.set({ type: 'danger', text: 'The passphrases are not the same.' });
      return;
    }
    this.act(() => firstValueFrom(this.http.post('/api/vault/init', { passphrase: this.p1 })), 'Vault created and unlocked.');
  }

  protected unlock(): void {
    this.act(() => firstValueFrom(this.vs.unlock(this.p1)), 'Vault unlocked.');
  }

  protected lock(): void {
    this.act(() => firstValueFrom(this.http.post('/api/vault/lock', {})), 'Vault locked.');
  }

  protected edit(x: SecretRow | null): void {
    this.editing = !!x;
    this.form = { name: x?.name ?? '', kind: x?.kind ?? 'password', value: '', description: x?.description ?? '' };
    this.editOpen = true;
  }

  protected save(): void {
    const { name, ...body } = this.form;
    this.editOpen = false;
    this.act(() => firstValueFrom(this.http.put(`/api/vault/secrets/${encodeURIComponent(name)}`, body)), `Secret ${name} saved.`);
  }

  protected remove(name: string): void {
    this.act(() => firstValueFrom(this.http.delete(`/api/vault/secrets/${encodeURIComponent(name)}`)), `Secret ${name} deleted.`);
  }

  protected importLegacy(): void {
    this.act(async () => {
      const r = await firstValueFrom(this.http.post<{ imported: string[] }>('/api/vault/import-legacy', {}));
      this.message.set({ type: 'success', text: r.imported.length ? 'Imported: ' + r.imported.join(', ') : 'Nothing new to import.' });
    }, '');
  }

  protected change(): void {
    this.changeOpen = false;
    this.act(() => firstValueFrom(this.http.post('/api/vault/passphrase', { current: this.cur, new: this.p1 })), 'Passphrase changed; all secrets re-encrypted.');
  }
}
