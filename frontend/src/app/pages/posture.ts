import { HttpClient } from '@angular/common/http';
import { DatePipe, DecimalPipe } from '@angular/common';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { firstValueFrom } from 'rxjs';
import { errorText } from '../auth';
import { AgoPipe } from '../ui';

interface Cert {
  host: string; port: number; device_name: string; subject_cn: string; issuer_cn: string;
  self_signed: boolean; expires: number | null; not_before: number | null; tls_version: string;
  cipher: string | null; fingerprint: string; sans: string[]; key_bits: number | null;
  sig_algo: string | null; error: string | null;
}
interface Eol { device_name: string; product: string; cycle: string; status: string; days_left: number | null; latest: string | null; eol: string | null }
interface Exposure { kind: string; port: string; proto: string; to: string; label: string; level: string }
interface Hit { time: number; src: string; port: number; service: string; device_name: string | null; bytes: number; preview: string }
interface Cred { host: string; port: number; service: string; username: string; device_name: string }
interface HibpItem { source: string; breached: boolean | null; count: number; error?: string }
interface Breach { name: string; title: string; domain: string; date: string; count: number; data: string[]; verified: boolean }

@Component({
  selector: 'app-posture',
  imports: [ClarityModule, FormsModule, DatePipe, DecimalPipe, AgoPipe],
  template: `
    <div class="page-head">
      <h2>Security posture</h2>
      <button class="btn btn-sm btn-outline" (click)="load()"><cds-icon shape="refresh"></cds-icon> Refresh</button>
    </div>
    @if (msg(); as m) { <clr-alert [clrAlertType]="m.t" [clrAlertClosable]="true" (clrAlertClosedChange)="msg.set(null)"><clr-alert-item><span class="alert-text">{{ m.x }}</span></clr-alert-item></clr-alert> }

    <clr-tabs>
      <!-- ============ Overview ============ -->
      <clr-tab>
        <button clrTabLink>Overview</button>
        <clr-tab-content *clrIfActive="true">
          <div class="clr-row">
            <div class="clr-col-6 clr-col-md-3"><div class="card stat"><div class="card-block">
              <div class="n" [class.bad]="score() < 70">{{ score() }}<small>/100</small></div>
              <div class="l">Posture · {{ scoreLabel() }}</div></div></div></div>
            <div class="clr-col-6 clr-col-md-3"><div class="card stat sev" [class.warn]="certExpiring() || certWeak()"><div class="card-block">
              <div class="n">{{ certExpiring() + certWeak() }}</div><div class="l">cert issues</div>
              <div class="sub">{{ certs().length }} endpoint(s)</div></div></div></div>
            <div class="clr-col-6 clr-col-md-3"><div class="card stat sev" [class.bad]="eolCount()" [class.warn]="eolWarn()"><div class="card-block">
              <div class="n">{{ eolCount() }}</div><div class="l">end-of-life devices</div>
              <div class="sub">{{ eolWarn() }} nearing</div></div></div></div>
            <div class="clr-col-6 clr-col-md-3"><div class="card stat sev" [class.warn]="exposureWarn() || upnp()"><div class="card-block">
              <div class="n">{{ exposures().length }}</div><div class="l">internet exposures</div>
              <div class="sub">UPnP {{ upnp() ? 'on' : 'off' }}</div></div></div></div>
            <div class="clr-col-6 clr-col-md-3"><div class="card stat sev" [class.bad]="hits().length"><div class="card-block">
              <div class="n">{{ hits().length }}</div><div class="l">honeypot hits</div>
              <div class="sub">{{ listening().length }} trap(s) live</div></div></div></div>
            <div class="clr-col-6 clr-col-md-3"><div class="card stat sev" [class.bad]="credVuln()"><div class="card-block">
              <div class="n">{{ credVuln() }}</div><div class="l">default-password hits</div>
              <div class="sub">{{ credEnabled() ? (credRan() ? 'audited' : 'not run') : 'off' }}</div></div></div></div>
            <div class="clr-col-6 clr-col-md-3"><div class="card stat sev" [class.bad]="hibpBreached()"><div class="card-block">
              <div class="n">{{ hibpBreached() }}</div><div class="l">breached credentials</div>
              <div class="sub">{{ hibpEnabled() ? 'HIBP on' : 'HIBP off' }}</div></div></div></div>
          </div>
          <p class="muted">Each area has its own tab. The score drops for expiring/weak certs, end-of-life devices,
            internet-facing ports, UPnP, honeypot hits, factory logins and breached stored credentials.</p>
        </clr-tab-content>
      </clr-tab>

      <!-- ============ Certificates ============ -->
      <clr-tab>
        <button clrTabLink>Certificates ({{ certs().length }})</button>
        <clr-tab-content *clrIfActive>
          <div class="sec-head">
            <p class="muted">TLS endpoints on your devices — expiry, obsolete TLS and self-signed certs.
              {{ certExpiring() }} expiring soon, {{ certSelfSigned() }} self-signed.</p>
            <button class="btn btn-sm btn-outline" (click)="scan('certs')"><cds-icon shape="refresh"></cds-icon> Scan now</button>
          </div>
          <clr-datagrid>
            <clr-dg-column [clrDgField]="'device_name'">Device</clr-dg-column>
            <clr-dg-column [clrDgField]="'host'">Endpoint</clr-dg-column>
            <clr-dg-column [clrDgField]="'issuer_cn'">Issuer</clr-dg-column>
            <clr-dg-column [clrDgField]="'tls_version'">TLS</clr-dg-column>
            <clr-dg-column [clrDgField]="'expires'">Expires</clr-dg-column>
            <clr-dg-row *clrDgItems="let c of certs()" [clrDgItem]="c">
              <clr-dg-cell>{{ c.device_name }}</clr-dg-cell>
              <clr-dg-cell class="mono">{{ c.host }}:{{ c.port }}</clr-dg-cell>
              <clr-dg-cell>
                @if (c.error) { <span class="muted">—</span> }
                @else if (c.self_signed) { <span class="label">self-signed</span> }
                @else { {{ c.issuer_cn }} }
              </clr-dg-cell>
              <clr-dg-cell><span class="label" [class.label-warning]="weakTls(c.tls_version)" [class.label-danger]="!!c.error">{{ c.error ? 'error' : c.tls_version }}</span></clr-dg-cell>
              <clr-dg-cell>
                @if (c.expires) { <span [class.danger]="days(c.expires) < 21" [class.warn]="days(c.expires) >= 21 && days(c.expires) < 45">{{ daysLabel(c.expires) }}</span> }
                @else { <span class="muted">—</span> }
              </clr-dg-cell>
            </clr-dg-row>
            <clr-dg-placeholder>No TLS endpoints scanned yet.</clr-dg-placeholder>
            <ng-template [(clrIfDetail)]="certDetail" let-c>
              <clr-dg-detail>
                <clr-dg-detail-header>{{ c.subject_cn || c.host }}</clr-dg-detail-header>
                <clr-dg-detail-body>
                  @if (c.error) { <clr-alert clrAlertType="danger" [clrAlertClosable]="false" clrAlertSize="sm"><clr-alert-item><span class="alert-text">{{ c.error }}</span></clr-alert-item></clr-alert> }
                  <dl class="kv">
                    <dt>Endpoint</dt><dd class="mono">{{ c.host }}:{{ c.port }} · {{ c.device_name }}</dd>
                    <dt>Subject</dt><dd>{{ c.subject_cn || '—' }}</dd>
                    @if (c.sans?.length) { <dt>SANs</dt><dd class="mono sm">{{ c.sans.join(', ') }}</dd> }
                    <dt>Issuer</dt><dd>{{ c.self_signed ? 'self-signed' : (c.issuer_cn || '—') }}</dd>
                    <dt>Valid</dt><dd>@if (c.not_before) { {{ c.not_before * 1000 | date: 'dd.MM.yyyy' }} → } {{ c.expires ? (c.expires * 1000 | date: 'dd.MM.yyyy') : '—' }}
                      @if (c.expires) { <span [class.danger]="days(c.expires) < 21">({{ daysLabel(c.expires) }})</span> }</dd>
                    <dt>TLS</dt><dd><span [class.danger]="weakTls(c.tls_version)">{{ c.tls_version }}</span> · <span class="mono sm">{{ c.cipher || '—' }}</span></dd>
                    <dt>Key</dt><dd>{{ c.key_bits ? c.key_bits + '-bit' : '—' }} · {{ c.sig_algo || '—' }}</dd>
                    <dt>SHA-256</dt><dd class="mono sm">{{ c.fingerprint }}</dd>
                  </dl>
                </clr-dg-detail-body>
              </clr-dg-detail>
            </ng-template>
          </clr-datagrid>
        </clr-tab-content>
      </clr-tab>

      <!-- ============ Firmware / OS ============ -->
      <clr-tab>
        <button clrTabLink>Firmware / OS ({{ eol().length }})</button>
        <clr-tab-content *clrIfActive>
          <div class="sec-head">
            <p class="muted">End-of-life devices stop getting security updates — the usual botnet recruits. Add
              <code>eol_product</code> / <code>eol_cycle</code> to a device's facts to track it.</p>
            <button class="btn btn-sm btn-outline" (click)="scan('lifecycle')"><cds-icon shape="refresh"></cds-icon> Refresh</button>
          </div>
          <clr-datagrid>
            <clr-dg-column [clrDgField]="'device_name'">Device</clr-dg-column>
            <clr-dg-column [clrDgField]="'product'">Product</clr-dg-column>
            <clr-dg-column [clrDgField]="'status'">Status</clr-dg-column>
            <clr-dg-column [clrDgField]="'days_left'">EOL</clr-dg-column>
            <clr-dg-column [clrDgField]="'latest'">Latest</clr-dg-column>
            <clr-dg-row *clrDgItems="let e of eol()" [clrDgItem]="e">
              <clr-dg-cell>{{ e.device_name }}</clr-dg-cell>
              <clr-dg-cell>{{ e.product }} {{ e.cycle }}</clr-dg-cell>
              <clr-dg-cell><span class="label" [class.label-danger]="e.status === 'eol'" [class.label-warning]="e.status === 'warn'" [class.label-success]="e.status === 'ok'">
                {{ e.status === 'eol' ? 'end of life' : e.status === 'warn' ? 'nearing EOL' : 'supported' }}</span></clr-dg-cell>
              <clr-dg-cell>
                @if (e.eol && e.status !== 'ok') { <span [class.danger]="e.status === 'eol'">{{ e.eol }}{{ e.days_left != null ? ' · ' + (e.days_left < 0 ? -e.days_left + 'd ago' : 'in ' + e.days_left + 'd') : '' }}</span> }
                @else { <span class="muted">{{ e.eol || '—' }}</span> }
              </clr-dg-cell>
              <clr-dg-cell class="mono">{{ e.latest || '—' }}</clr-dg-cell>
            </clr-dg-row>
            <clr-dg-placeholder>No lifecycle data. Tag devices with <code>eol_product</code> in their facts.</clr-dg-placeholder>
          </clr-datagrid>
        </clr-tab-content>
      </clr-tab>

      <!-- ============ Internet exposure ============ -->
      <clr-tab>
        <button clrTabLink>Exposure ({{ exposures().length }})</button>
        <clr-tab-content *clrIfActive>
          <div class="sec-head">
            <p class="muted">Ports reachable from the internet, read from the router — the attack surface.</p>
            <button class="btn btn-sm btn-outline" (click)="scan('exposure')"><cds-icon shape="refresh"></cds-icon> Scan now</button>
          </div>
          @if (upnp() !== null) {
            <clr-alert [clrAlertType]="upnp() ? 'warning' : 'success'" [clrAlertClosable]="false" clrAlertSize="sm"><clr-alert-item>
              <span class="alert-text">UPnP is {{ upnp() ? 'ENABLED — any device can open its own hole to the internet' : 'disabled' }}.</span>
            </clr-alert-item></clr-alert>
          }
          <clr-datagrid>
            <clr-dg-column [clrDgField]="'kind'">Kind</clr-dg-column>
            <clr-dg-column [clrDgField]="'port'">Port</clr-dg-column>
            <clr-dg-column [clrDgField]="'to'">To</clr-dg-column>
            <clr-dg-column [clrDgField]="'label'">What</clr-dg-column>
            <clr-dg-row *clrDgItems="let e of exposures()" [clrDgItem]="e">
              <clr-dg-cell><span class="label" [class.label-warning]="e.level === 'warning'">{{ e.kind }}</span></clr-dg-cell>
              <clr-dg-cell class="mono">{{ e.port }}/{{ e.proto }}</clr-dg-cell>
              <clr-dg-cell class="mono">{{ e.to }}</clr-dg-cell>
              <clr-dg-cell>{{ e.label }}</clr-dg-cell>
            </clr-dg-row>
            <clr-dg-placeholder>Nothing reachable from the internet (or no MikroTik configured).</clr-dg-placeholder>
          </clr-datagrid>
        </clr-tab-content>
      </clr-tab>

      <!-- ============ Honeypot ============ -->
      <clr-tab>
        <button clrTabLink>Honeypot ({{ hits().length }})</button>
        <clr-tab-content *clrIfActive>
          <p class="muted">Fake Telnet/SMB/RDP/ADB services. Nothing here offers them, so any connection is suspicious.
            Live traps: @for (l of listening(); track l.port) { <span class="label">{{ l.port }}/{{ l.service }}</span> } @empty { <span class="muted">none (enable the Honeypot feature)</span> }</p>

          @if (topSources().length) {
            <h4>Top sources</h4>
            <div class="clr-row">
              @for (s of topSources(); track s.src) {
                <div class="clr-col-12 clr-col-md-6 clr-col-lg-4"><div class="card src"><div class="card-block">
                  <div class="src-head"><span class="mono">{{ s.name || s.src }}</span> <span class="label label-danger">{{ s.count }} hit(s)</span></div>
                  <div class="sub">ports {{ s.ports.join(', ') }} · last {{ s.last | ago }}</div>
                </div></div></div>
              }
            </div>
          }

          <h4>Recent hits</h4>
          <clr-datagrid>
            <clr-dg-column [clrDgField]="'time'">When</clr-dg-column>
            <clr-dg-column [clrDgField]="'src'">Source</clr-dg-column>
            <clr-dg-column [clrDgField]="'port'">Port</clr-dg-column>
            <clr-dg-column [clrDgField]="'service'">Service</clr-dg-column>
            <clr-dg-row *clrDgItems="let h of hits()" [clrDgItem]="h">
              <clr-dg-cell>{{ h.time | ago }}</clr-dg-cell>
              <clr-dg-cell>{{ h.device_name || h.src }} <span class="mono sub">{{ h.device_name ? h.src : '' }}</span></clr-dg-cell>
              <clr-dg-cell class="mono">{{ h.port }}</clr-dg-cell>
              <clr-dg-cell>{{ h.service }}</clr-dg-cell>
            </clr-dg-row>
            <clr-dg-placeholder>No honeypot hits — good.</clr-dg-placeholder>
            <ng-template [(clrIfDetail)]="hitDetail" let-h>
              <clr-dg-detail>
                <clr-dg-detail-header>{{ h.service }} from {{ h.src }}</clr-dg-detail-header>
                <clr-dg-detail-body>
                  <dl class="kv">
                    <dt>When</dt><dd>{{ h.time * 1000 | date: 'medium' }}</dd>
                    <dt>Source</dt><dd class="mono">{{ h.src }}{{ h.device_name ? ' (' + h.device_name + ')' : '' }}</dd>
                    <dt>Trap</dt><dd>port {{ h.port }} · {{ h.service }}</dd>
                    <dt>Bytes sent</dt><dd>{{ h.bytes }}</dd>
                    @if (h.preview) {
                      <dt>Payload</dt>
                      <dd><div class="mono sm">{{ decode(h.preview) }}</div><div class="mono sm muted">{{ h.preview }}</div></dd>
                    }
                  </dl>
                </clr-dg-detail-body>
              </clr-dg-detail>
            </ng-template>
          </clr-datagrid>
        </clr-tab-content>
      </clr-tab>

      <!-- ============ Default-password audit ============ -->
      <clr-tab>
        <button clrTabLink>Default passwords</button>
        <clr-tab-content *clrIfActive>
          <p class="muted">Checks whether your own devices still accept documented factory logins (the Mirai vector).
            It only reports which devices are vulnerable and changes nothing. LAN-only, rate-limited.</p>
          @if (!credEnabled()) {
            <clr-alert clrAlertType="info" [clrAlertClosable]="false" clrAlertSize="sm"><clr-alert-item>
              <span class="alert-text">Disabled. Set <code>CREDCHECK_ENABLED=true</code> to allow it.</span></clr-alert-item></clr-alert>
          } @else {
            <p><button class="btn btn-sm btn-warning-outline" [disabled]="credBusy()" (click)="runCred()">
              {{ credBusy() ? 'Checking…' : 'Run audit' }}</button></p>
            <clr-datagrid>
              <clr-dg-column [clrDgField]="'device_name'">Device</clr-dg-column>
              <clr-dg-column [clrDgField]="'host'">Endpoint</clr-dg-column>
              <clr-dg-column [clrDgField]="'service'">Service</clr-dg-column>
              <clr-dg-column>Accepted login</clr-dg-column>
              <clr-dg-row *clrDgItems="let r of credResults()" [clrDgItem]="r">
                <clr-dg-cell>{{ r.device_name }}</clr-dg-cell>
                <clr-dg-cell class="mono">{{ r.host }}:{{ r.port }}</clr-dg-cell>
                <clr-dg-cell>{{ r.service }}</clr-dg-cell>
                <clr-dg-cell><span class="label label-danger">{{ r.username }}</span></clr-dg-cell>
              </clr-dg-row>
              <clr-dg-placeholder>{{ credRan() ? 'No device accepted a factory login — good.' : 'Not run yet.' }}</clr-dg-placeholder>
            </clr-datagrid>
          }
        </clr-tab-content>
      </clr-tab>

      <!-- ============ Have I Been Pwned ============ -->
      <clr-tab>
        <button clrTabLink>Have I Been Pwned</button>
        <clr-tab-content *clrIfActive>
          @if (!hibpEnabled()) {
            <clr-alert clrAlertType="info" [clrAlertClosable]="false" clrAlertSize="sm"><clr-alert-item>
              <span class="alert-text">The Have I Been Pwned feature is off. Enable it under <strong>Features</strong>.</span></clr-alert-item></clr-alert>
          } @else {
            <h4>Password check</h4>
            <p class="muted">Test a password against known breaches. It's hashed in your browser — only the first 5
              characters of the SHA-1 hash are sent (k-anonymity), never the password itself.</p>
            <div class="pw-row">
              <input class="clr-input" type="password" [(ngModel)]="pwInput" placeholder="a password to test"
                     (keyup.enter)="checkPassword()" autocomplete="off" />
              <button class="btn btn-sm btn-primary" [disabled]="!pwInput || pwBusy()" (click)="checkPassword()">{{ pwBusy() ? 'Checking…' : 'Check' }}</button>
            </div>
            @if (pwResult(); as p) {
              @if (p.count > 0) {
                <clr-alert clrAlertType="danger" [clrAlertClosable]="false" clrAlertSize="sm"><clr-alert-item>
                  <span class="alert-text">Found in breaches <strong>{{ p.count | number }}</strong> time(s). Don't use this password.</span></clr-alert-item></clr-alert>
              } @else {
                <clr-alert clrAlertType="success" [clrAlertClosable]="false" clrAlertSize="sm"><clr-alert-item>
                  <span class="alert-text">Not found in any known breach. (That doesn't make it strong — length still matters.)</span></clr-alert-item></clr-alert>
              }
            }

            <h4>Stored credentials</h4>
            <p class="muted">Checks the passwords this box holds (service accounts + vault secrets) against Pwned Passwords.
              Values are never shown or sent — only the hash prefix.</p>
            <p><button class="btn btn-sm btn-outline" [disabled]="auditBusy()" (click)="runAudit()">{{ auditBusy() ? 'Checking…' : 'Audit stored credentials' }}</button></p>
            @if (audit(); as a) {
              <clr-datagrid>
                <clr-dg-column>Credential</clr-dg-column>
                <clr-dg-column>Status</clr-dg-column>
                <clr-dg-row *clrDgItems="let it of a.items" [clrDgItem]="it">
                  <clr-dg-cell class="mono">{{ it.source }}</clr-dg-cell>
                  <clr-dg-cell>
                    @if (it.breached === null) { <span class="label">check failed</span> }
                    @else if (it.breached) { <span class="label label-danger">breached · {{ it.count | number }}×</span> }
                    @else { <span class="label label-success">clean</span> }
                  </clr-dg-cell>
                </clr-dg-row>
                <clr-dg-placeholder>No stored passwords found to check.</clr-dg-placeholder>
              </clr-datagrid>
              @if (!a.vault_unlocked) { <p class="muted sm">Unlock the vault to also check vault-stored passwords.</p> }
            }

            <h4>Email breach lookup</h4>
            @if (!hibpAccount()) {
              <clr-alert clrAlertType="info" [clrAlertClosable]="false" clrAlertSize="sm"><clr-alert-item>
                <span class="alert-text">Set <code>HIBP_API_KEY</code> in <code>.env</code> to look up which breaches an email appears in (needs a paid HIBP subscription).</span></clr-alert-item></clr-alert>
            } @else {
              <p class="muted">See which breaches an email address appears in.</p>
              <div class="pw-row">
                <input class="clr-input" type="email" [(ngModel)]="emailInput" placeholder="you@example.com" (keyup.enter)="lookupEmail()" />
                <button class="btn btn-sm btn-primary" [disabled]="!emailInput || emailBusy()" (click)="lookupEmail()">{{ emailBusy() ? 'Looking…' : 'Look up' }}</button>
              </div>
              @if (breaches(); as b) {
                @if (b.error) { <clr-alert clrAlertType="danger" [clrAlertClosable]="false" clrAlertSize="sm"><clr-alert-item><span class="alert-text">{{ b.error }}</span></clr-alert-item></clr-alert> }
                @else if (!b.breaches.length) { <clr-alert clrAlertType="success" [clrAlertClosable]="false" clrAlertSize="sm"><clr-alert-item><span class="alert-text">{{ b.email }} is not in any breach in HIBP.</span></clr-alert-item></clr-alert> }
                @else {
                  <p class="danger">{{ b.email }} appears in {{ b.breaches.length }} breach(es):</p>
                  <clr-datagrid>
                    <clr-dg-column [clrDgField]="'title'">Breach</clr-dg-column>
                    <clr-dg-column [clrDgField]="'date'">Date</clr-dg-column>
                    <clr-dg-column>Accounts</clr-dg-column>
                    <clr-dg-column>Exposed data</clr-dg-column>
                    <clr-dg-row *clrDgItems="let br of b.breaches" [clrDgItem]="br">
                      <clr-dg-cell>{{ br.title }} <span class="mono sub">{{ br.domain }}</span></clr-dg-cell>
                      <clr-dg-cell>{{ br.date }}</clr-dg-cell>
                      <clr-dg-cell>{{ br.count | number }}</clr-dg-cell>
                      <clr-dg-cell class="sm">{{ br.data.slice(0, 6).join(', ') }}</clr-dg-cell>
                    </clr-dg-row>
                  </clr-datagrid>
                }
              }
            }
          }
        </clr-tab-content>
      </clr-tab>
    </clr-tabs>
  `,
  styles: `
    .sec-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.6rem 1rem; margin: 0.6rem 0; }
    .sec-head p { margin: 0; flex: 1; min-width: 14rem; }
    .danger { color: var(--clr-color-danger-700, #c21d00); font-weight: 600; }
    .warn { color: var(--clr-color-warning-700, #946f00); }
    .stat .n.bad { color: var(--clr-color-danger-700, #c21d00); }
    .stat.sev.bad { border-top: 3px solid #e12200; }
    .stat.sev.warn { border-top: 3px solid #e57200; }
    .stat .sub { font-size: 0.68rem; opacity: 0.7; }
    .sub { font-size: 0.72rem; opacity: 0.7; }
    .sm { font-size: 0.78rem; }
    .kv { display: grid; grid-template-columns: max-content 1fr; gap: 0.35rem 1rem; margin: 0; }
    .kv dt { font-weight: 600; opacity: 0.7; }
    .kv dd { margin: 0; word-break: break-word; }
    .src .src-head { display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; }
    .pw-row { display: flex; gap: 0.5rem; align-items: center; max-width: 30rem; margin-bottom: 0.6rem; }
    .pw-row .clr-input { flex: 1; }
    h4 { margin-top: 1.2rem; }
  `,
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
  protected credResults = signal<Cred[]>([]);
  protected credBusy = signal(false);
  protected credRan = signal(false);
  protected msg = signal<{ t: 'success' | 'danger'; x: string } | null>(null);
  protected certDetail: Cert | null = null;
  protected hitDetail: Hit | null = null;

  // HIBP
  protected hibpEnabled = signal(false);
  protected hibpAccount = signal(false);
  protected pwInput = '';
  protected pwBusy = signal(false);
  protected pwResult = signal<{ count: number; breached: boolean } | null>(null);
  protected auditBusy = signal(false);
  protected audit = signal<{ vault_unlocked: boolean; items: HibpItem[] } | null>(null);
  protected emailInput = '';
  protected emailBusy = signal(false);
  protected breaches = signal<{ email: string; breaches: Breach[]; error?: string } | null>(null);

  // Overview summaries
  protected certExpiring = computed(() => this.certs().filter((c) => c.expires && this.days(c.expires) < 45).length);
  protected certWeak = computed(() => this.certs().filter((c) => this.weakTls(c.tls_version) || !!c.error).length);
  protected certSelfSigned = computed(() => this.certs().filter((c) => c.self_signed).length);
  protected eolCount = computed(() => this.eol().filter((e) => e.status === 'eol').length);
  protected eolWarn = computed(() => this.eol().filter((e) => e.status === 'warn').length);
  protected exposureWarn = computed(() => this.exposures().filter((e) => e.level === 'warning').length);
  protected credVuln = computed(() => this.credResults().length);
  protected hibpBreached = computed(() => (this.audit()?.items ?? []).filter((i) => i.breached).length);
  protected topSources = computed(() => {
    const m = new Map<string, { src: string; name: string | null; count: number; last: number; ports: Set<number> }>();
    for (const h of this.hits()) {
      const e = m.get(h.src) ?? { src: h.src, name: h.device_name, count: 0, last: 0, ports: new Set<number>() };
      e.count++; e.last = Math.max(e.last, h.time); e.ports.add(h.port);
      m.set(h.src, e);
    }
    return [...m.values()].map((e) => ({ ...e, ports: [...e.ports].sort((a, b) => a - b) }))
      .sort((a, b) => b.count - a.count).slice(0, 9);
  });

  protected score = computed(() => {
    let s = 100;
    s -= this.certExpiring() * 6 + this.certWeak() * 5;
    s -= this.eolCount() * 10 + this.eolWarn() * 4;
    s -= this.exposureWarn() * 6 + (this.upnp() ? 8 : 0);
    s -= Math.min(20, this.hits().length * 3);
    s -= this.credVuln() * 15;
    s -= this.hibpBreached() * 12;
    return Math.max(0, Math.min(100, Math.round(s)));
  });

  protected scoreLabel = computed(() => { const n = this.score(); return n >= 85 ? 'good' : n >= 70 ? 'fair' : n >= 50 ? 'poor' : 'bad'; });

  ngOnInit(): void {
    this.load();
  }

  protected weakTls = (v: string) => ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'].includes(v);
  protected days = (exp: number) => Math.round((exp * 1000 - Date.now()) / 86400000);
  protected daysLabel = (exp: number) => { const d = this.days(exp); return d < 0 ? `expired ${-d}d ago` : `in ${d} days`; };

  protected decode(hex: string): string {
    let s = '';
    for (let i = 0; i + 1 < hex.length; i += 2) {
      const c = parseInt(hex.substr(i, 2), 16);
      s += c >= 32 && c < 127 ? String.fromCharCode(c) : '·';
    }
    return s || '(empty)';
  }

  protected load(): void {
    this.http.get<{ certs: Cert[] }>('/api/certs').subscribe((d) => this.certs.set(d.certs || []));
    this.http.get<{ devices: Eol[] }>('/api/lifecycle').subscribe((d) => this.eol.set(d.devices || []));
    this.http.get<{ upnp_enabled: boolean | null; exposures: Exposure[] }>('/api/exposure').subscribe((d) => {
      this.exposures.set(d.exposures || []); this.upnp.set(d.upnp_enabled);
    });
    this.http.get<{ summary: { listening: { port: number; service: string }[] }; hits: Hit[] }>('/api/honeypot').subscribe((d) => {
      this.hits.set(d.hits || []); this.listening.set(d.summary?.listening || []);
    });
    this.http.get<{ enabled: boolean; last: { results: Cred[] } }>('/api/credcheck').subscribe((d) => {
      this.credEnabled.set(d.enabled); this.credResults.set(d.last?.results || []);
    });
    this.http.get<{ enabled: boolean; account_lookup: boolean }>('/api/hibp').subscribe((d) => {
      this.hibpEnabled.set(d.enabled); this.hibpAccount.set(d.account_lookup);
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
      const r = await firstValueFrom(this.http.post<{ vulnerable: number; results: Cred[] }>('/api/credcheck/run', { confirm: true }));
      this.credResults.set(r.results); this.credRan.set(true);
      this.msg.set({ t: r.vulnerable ? 'danger' : 'success', x: r.vulnerable ? `${r.vulnerable} device(s) still accept a factory login.` : 'No device accepted a factory login.' });
    } catch (e) {
      this.msg.set({ t: 'danger', x: errorText(e) });
    }
    this.credBusy.set(false);
  }

  /** SHA-1 the password in the browser; send only the hash (prefix + suffix), never the password. */
  protected async checkPassword(): Promise<void> {
    if (!this.pwInput) return;
    this.pwBusy.set(true); this.pwResult.set(null);
    try {
      const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(this.pwInput));
      const hex = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
      const r = await firstValueFrom(this.http.post<{ count: number; breached: boolean }>('/api/hibp/password', { prefix: hex.slice(0, 5), suffix: hex.slice(5) }));
      this.pwResult.set(r);
    } catch (e) {
      this.msg.set({ t: 'danger', x: errorText(e) });
    }
    this.pwBusy.set(false);
  }

  protected async runAudit(): Promise<void> {
    this.auditBusy.set(true);
    try {
      this.audit.set(await firstValueFrom(this.http.post<{ vault_unlocked: boolean; items: HibpItem[] }>('/api/hibp/audit', {})));
    } catch (e) {
      this.msg.set({ t: 'danger', x: errorText(e) });
    }
    this.auditBusy.set(false);
  }

  protected async lookupEmail(): Promise<void> {
    if (!this.emailInput) return;
    this.emailBusy.set(true); this.breaches.set(null);
    try {
      this.breaches.set(await firstValueFrom(this.http.post<{ email: string; breaches: Breach[]; error?: string }>('/api/hibp/account', { email: this.emailInput.trim() })));
    } catch (e) {
      this.msg.set({ t: 'danger', x: errorText(e) });
    }
    this.emailBusy.set(false);
  }
}
