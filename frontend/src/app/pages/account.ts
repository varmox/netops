import { DatePipe } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { firstValueFrom } from 'rxjs';
import { Auth, LoginResult, errorText } from '../auth';
import { PasskeyEnroll, RecoveryCodes, TotpEnroll } from '../mfa';
import { AgoPipe } from '../ui';

interface Factors {
  totp: boolean;
  passkeys: number;
  recovery_codes: number;
  passkey_list: { id: number; name: string; transports: string; created: number; last_used: number | null }[];
}

interface UserRow {
  id: number;
  username: string;
  role: string;
  created: number;
  last_login: number | null;
  locked_until: number;
  factors: { totp: boolean; passkeys: number };
}

@Component({
  selector: 'app-account',
  imports: [ClarityModule, FormsModule, DatePipe, AgoPipe, TotpEnroll, PasskeyEnroll, RecoveryCodes],
  template: `
    <div class="page-head"><h2>Account</h2><span class="muted">{{ auth.user()?.name }} · {{ auth.user()?.role }}</span></div>
    @if (message(); as m) {
      <clr-alert [clrAlertType]="m.type" [clrAlertClosable]="true" (clrAlertClosedChange)="message.set(null)">
        <clr-alert-item><span class="alert-text">{{ m.text }}</span></clr-alert-item>
      </clr-alert>
    }

    <clr-tabs>
      <clr-tab>
        <button clrTabLink>Sign-in methods</button>
        <clr-tab-content *clrIfActive="true">
          @if (codes(); as c) {
            <div class="card"><div class="card-block"><app-recovery-codes [codes]="c" (done)="codes.set(null)" /></div></div>
          }
          <div class="clr-row">
            <div class="clr-col-12 clr-col-lg-6">
              <div class="card"><div class="card-header">Passkeys</div><div class="card-block">
                <table class="table table-compact table-noborder">
                  <tbody>
                    @for (p of factors()?.passkey_list ?? []; track p.id) {
                      <tr>
                        <td class="left"><cds-icon shape="key"></cds-icon> {{ p.name }}</td>
                        <td class="left muted">added {{ p.created * 1000 | date: 'dd.MM.yyyy' }} · used {{ p.last_used | ago }}</td>
                        <td><button class="btn btn-sm btn-link" (click)="removePasskey(p.id)">Remove</button></td>
                      </tr>
                    } @empty { <tr><td class="left muted">No passkeys yet.</td></tr> }
                  </tbody>
                </table>
                <app-passkey-enroll [hostHint]="auth.state()?.hostname" (done)="added($event)" />
              </div></div>
            </div>
            <div class="clr-col-12 clr-col-lg-6">
              <div class="card"><div class="card-header">Authenticator app</div><div class="card-block">
                @if (factors()?.totp) {
                  <p><span class="label label-success">active</span></p>
                  <button class="btn btn-sm btn-outline" (click)="removeTotp()">Remove</button>
                } @else {
                  <app-totp-enroll (done)="added($event)" />
                }
              </div></div>
              <div class="card"><div class="card-header">Recovery codes</div><div class="card-block">
                <p>{{ factors()?.recovery_codes ?? 0 }} unused codes left.</p>
                <button class="btn btn-sm btn-outline" (click)="regenerate()">Create new codes</button>
              </div></div>
            </div>
          </div>
        </clr-tab-content>
      </clr-tab>

      <clr-tab>
        <button clrTabLink>Password</button>
        <clr-tab-content *clrIfActive>
          <form class="clr-form clr-form-horizontal pw" (ngSubmit)="changePassword()" #pf="ngForm">
            <clr-password-container>
              <label>Current password</label>
              <input clrPassword name="cur" [(ngModel)]="cur" required autocomplete="current-password" />
            </clr-password-container>
            <clr-password-container>
              <label>New password</label>
              <input clrPassword name="nw" [(ngModel)]="nw" required autocomplete="new-password" />
              <clr-control-helper>At least 15 characters; checked against known breaches. Other sessions are logged out.</clr-control-helper>
            </clr-password-container>
            <button type="submit" class="btn btn-primary" [disabled]="!pf.valid">Change password</button>
          </form>
        </clr-tab-content>
      </clr-tab>

      @if (auth.isAdmin()) {
        <clr-tab>
          <button clrTabLink>Users</button>
          <clr-tab-content *clrIfActive>
            <clr-datagrid>
              <clr-dg-column>User</clr-dg-column>
              <clr-dg-column>Role</clr-dg-column>
              <clr-dg-column>Second factor</clr-dg-column>
              <clr-dg-column>Last login</clr-dg-column>
              <clr-dg-column>Status</clr-dg-column>
              @for (u of users(); track u.id) {
                <clr-dg-row>
                  <clr-dg-action-overflow>
                    <button class="action-item" (click)="unlock(u.id)">Unlock</button>
                    <button class="action-item" (click)="deleteUser(u)">Delete</button>
                  </clr-dg-action-overflow>
                  <clr-dg-cell>{{ u.username }}</clr-dg-cell>
                  <clr-dg-cell><span class="label">{{ u.role }}</span></clr-dg-cell>
                  <clr-dg-cell>
                    @if (u.factors.passkeys) { <span class="label label-success">{{ u.factors.passkeys }} passkey(s)</span> }
                    @if (u.factors.totp) { <span class="label label-success">app</span> }
                    @if (!u.factors.passkeys && !u.factors.totp) { <span class="label label-warning">not set up yet</span> }
                  </clr-dg-cell>
                  <clr-dg-cell>{{ u.last_login | ago }}</clr-dg-cell>
                  <clr-dg-cell>@if (u.locked_until * 1000 > now) { <span class="label label-danger">locked</span> } @else { active }</clr-dg-cell>
                </clr-dg-row>
              }
            </clr-datagrid>
            <h4>Add a user</h4>
            <form class="adduser" (ngSubmit)="addUser()" #uf="ngForm">
              <clr-input-container><label>User name</label><input clrInput name="un" [(ngModel)]="newUser.username" required /></clr-input-container>
              <clr-password-container><label>Initial password</label><input clrPassword name="up" [(ngModel)]="newUser.password" required autocomplete="new-password" /></clr-password-container>
              <clr-radio-container clrInline>
                <label>Role</label>
                <clr-radio-wrapper><input type="radio" clrRadio name="role" value="viewer" [(ngModel)]="newUser.role" /><label>Viewer (read only)</label></clr-radio-wrapper>
                <clr-radio-wrapper><input type="radio" clrRadio name="role" value="admin" [(ngModel)]="newUser.role" /><label>Admin</label></clr-radio-wrapper>
              </clr-radio-container>
              <button type="submit" class="btn btn-primary" [disabled]="!uf.valid">Add user</button>
            </form>
            <p class="muted">New users set up their own second factor at their first login.</p>
          </clr-tab-content>
        </clr-tab>

        <clr-tab>
          <button clrTabLink>Audit log</button>
          <clr-tab-content *clrIfActive>
            <clr-datagrid>
              <clr-dg-column [clrDgField]="'time'">Time</clr-dg-column>
              <clr-dg-column [clrDgField]="'user'">User</clr-dg-column>
              <clr-dg-column [clrDgField]="'action'">Action</clr-dg-column>
              <clr-dg-column>Detail</clr-dg-column>
              <clr-dg-column [clrDgField]="'ip'">Address</clr-dg-column>
              <clr-dg-row *clrDgItems="let a of audit()" [clrDgItem]="a">
                <clr-dg-cell>{{ a.time * 1000 | date: 'dd.MM. HH:mm:ss' }}</clr-dg-cell>
                <clr-dg-cell>{{ a.user }}</clr-dg-cell>
                <clr-dg-cell><span class="label" [class.label-danger]="a.action.includes('failed')">{{ a.action }}</span></clr-dg-cell>
                <clr-dg-cell>{{ a.detail }}</clr-dg-cell>
                <clr-dg-cell class="mono">{{ a.ip }}</clr-dg-cell>
              </clr-dg-row>
              <clr-dg-footer>
                <clr-dg-pagination #ap [clrDgPageSize]="25">{{ ap.totalItems }} entries</clr-dg-pagination>
              </clr-dg-footer>
            </clr-datagrid>
          </clr-tab-content>
        </clr-tab>
      }
    </clr-tabs>
  `,
  styles: `
    .card { margin-top: 0.6rem; }
    .pw { max-width: 34rem; }
    .adduser { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 1rem; }
  `,
})
export class AccountPage implements OnInit {
  protected auth = inject(Auth);
  private http = inject(HttpClient);
  protected factors = signal<Factors | null>(null);
  protected codes = signal<string[] | null>(null);
  protected users = signal<UserRow[]>([]);
  protected audit = signal<any[]>([]);
  protected message = signal<{ type: 'success' | 'danger'; text: string } | null>(null);
  protected cur = '';
  protected nw = '';
  protected newUser = { username: '', password: '', role: 'viewer' };
  protected now = Date.now();

  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    this.http.get<Factors>('/api/auth/factors').subscribe((f) => this.factors.set(f));
    if (this.auth.isAdmin()) {
      this.http.get<UserRow[]>('/api/auth/users').subscribe((u) => this.users.set(u));
      this.http.get<any[]>('/api/auth/audit').subscribe((a) => this.audit.set(a));
    }
  }

  private async act(fn: () => Promise<unknown>, ok: string): Promise<void> {
    try {
      await fn();
      this.message.set({ type: 'success', text: ok });
    } catch (e) {
      this.message.set({ type: 'danger', text: errorText(e) });
    }
    this.load();
  }

  protected added(r: LoginResult): void {
    if (r.recovery_codes?.length) this.codes.set(r.recovery_codes);
    this.message.set({ type: 'success', text: 'Sign-in method added.' });
    this.load();
  }

  protected removePasskey(id: number): void {
    this.act(() => firstValueFrom(this.http.delete(`/api/auth/passkeys/${id}`)), 'Passkey removed.');
  }

  protected removeTotp(): void {
    this.act(() => firstValueFrom(this.http.delete('/api/auth/totp')), 'Authenticator app removed.');
  }

  protected regenerate(): void {
    this.act(async () => {
      const r = await firstValueFrom(this.http.post<{ recovery_codes: string[] }>('/api/auth/recovery/regenerate', {}));
      this.codes.set(r.recovery_codes);
    }, 'New recovery codes created; the old ones no longer work.');
  }

  protected changePassword(): void {
    this.act(() => firstValueFrom(this.http.post('/api/auth/password', { current: this.cur, new: this.nw })), 'Password changed.')
      .then(() => { this.cur = this.nw = ''; });
  }

  protected addUser(): void {
    this.act(() => firstValueFrom(this.http.post('/api/auth/users', this.newUser)), `User ${this.newUser.username} added.`)
      .then(() => { this.newUser = { username: '', password: '', role: 'viewer' }; });
  }

  protected deleteUser(u: UserRow): void {
    this.act(() => firstValueFrom(this.http.delete(`/api/auth/users/${u.id}`)), `User ${u.username} deleted.`);
  }

  protected unlock(id: number): void {
    this.act(() => firstValueFrom(this.http.post(`/api/auth/users/${id}/unlock`, {})), 'Account unlocked.');
  }
}
