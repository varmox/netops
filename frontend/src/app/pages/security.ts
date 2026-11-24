import { DatePipe } from '@angular/common';
import { Component, DestroyRef, OnInit, computed, inject, input, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ClarityModule, ClrDatagridNumericFilterInterface, ClrDatagridStringFilterInterface } from '@clr/angular';
import { forkJoin, switchMap } from 'rxjs';
import { Api, Finding, Proposal, SecuritySummary } from '../api';
import { AgoPipe, refreshTicks } from '../ui';

const SEV_CLASS: Record<string, string> = {
  critical: 'label-danger', high: 'label-warning', medium: 'label-info', low: '',
};
const STATUS_CLASS: Record<string, string> = {
  open: 'label-danger', acknowledged: 'label-warning', remediating: 'label-info', quarantined: 'label-purple', resolved: 'label-success',
};

@Component({
  selector: 'app-security',
  imports: [ClarityModule, FormsModule, RouterLink, DatePipe, AgoPipe],
  template: `
    <div class="page-head">
      <h2>Security</h2>
      <div class="btn-group">
        <button class="btn btn-sm btn-outline" (click)="sync()" [disabled]="summary()?.running?.['feeds']">
          <cds-icon shape="refresh"></cds-icon> Sync CVE feeds
        </button>
        <button class="btn btn-sm btn-primary" (click)="scan()" [disabled]="summary()?.running?.['scan']">
          <cds-icon shape="radar"></cds-icon> Scan LAN
        </button>
      </div>
    </div>

    @if (summary()?.dry_run) {
      <clr-alert clrAlertType="info" [clrAlertClosable]="false">
        <clr-alert-item><span class="alert-text">
          Dry-run mode: remediation actions are logged but nothing changes on the router (SECURITY_DRY_RUN=true).
        </span></clr-alert-item>
      </clr-alert>
    }
    @if (summary()?.running?.['feeds'] || summary()?.running?.['scan']) {
      <div class="running">
        <span>{{ summary()?.running?.['scan'] ? 'Scanning the LAN (nmap + vulners)…' : 'Syncing CISA KEV and NVD…' }}</span>
        <clr-progress-bar [clrLoop]="true"></clr-progress-bar>
      </div>
    }
    @if (message(); as m) {
      <clr-alert [clrAlertType]="m.type" [clrAlertClosable]="true" (clrAlertClosedChange)="message.set(null)">
        <clr-alert-item><span class="alert-text">{{ m.text }}</span></clr-alert-item>
      </clr-alert>
    }

    <!-- Scoreboard -->
    @if (summary(); as s) {
      <div class="clr-row">
        @for (sev of severities; track sev) {
          <div class="clr-col-6 clr-col-md-4 clr-col-xl-2">
            <div class="card score" [class]="'card score sev-' + sev"><div class="card-block">
              <div class="cap">{{ sev }}</div><div class="big">{{ s.open[sev] }}</div><div class="sub">open</div>
            </div></div>
          </div>
        }
        <div class="clr-col-6 clr-col-md-4 clr-col-xl-2">
          <div class="card score"><div class="card-block">
            <div class="cap">Actively exploited</div><div class="big">{{ s.kev }}</div><div class="sub">CISA KEV</div>
          </div></div>
        </div>
        <div class="clr-col-6 clr-col-md-4 clr-col-xl-2">
          <div class="card score"><div class="card-block">
            <div class="cap">Quarantined</div><div class="big">{{ s.quarantined }}</div>
            <div class="sub">feeds {{ s.last_feeds | ago }} · scan {{ s.last_scan | ago }}</div>
          </div></div>
        </div>
      </div>
    }

    <clr-tabs>
      <clr-tab>
        <button clrTabLink>Findings ({{ visible().length }})</button>
        <clr-tab-content *clrIfActive="true">
          <clr-toggle-wrapper class="toggle">
            <input type="checkbox" clrToggle name="showResolved" [ngModel]="showResolved()" (ngModelChange)="showResolved.set($event)" />
            <label>Show resolved</label>
          </clr-toggle-wrapper>
          <clr-datagrid [clrDgLoading]="loading()">
            <clr-dg-column [clrDgField]="'severity'">Severity</clr-dg-column>
            <clr-dg-column [clrDgField]="'cve'">CVE</clr-dg-column>
            <clr-dg-column [clrDgField]="'device_name'">Device</clr-dg-column>
            <clr-dg-column [clrDgField]="'product'">
              <ng-container *clrDgHideableColumn="{ hidden: false }">Product</ng-container>
            </clr-dg-column>
            <clr-dg-column [clrDgField]="'score'">CVSS</clr-dg-column>
            <clr-dg-column>Sources</clr-dg-column>
            <clr-dg-column [clrDgField]="'confidence'">
              <ng-container *clrDgHideableColumn="{ hidden: false }">Confidence</ng-container>
            </clr-dg-column>
            <clr-dg-column [clrDgField]="'status'">Status</clr-dg-column>

            <clr-dg-row *clrDgItems="let f of visible()" [clrDgItem]="f">
              <clr-dg-cell><span class="label" [class]="'label ' + sevClass[f.severity]">{{ f.severity }}</span></clr-dg-cell>
              <clr-dg-cell class="mono">{{ f.cve }}</clr-dg-cell>
              <clr-dg-cell>
                @if (f.device) { <a [routerLink]="['/devices', f.device]">{{ f.device_name }}</a> } @else { <span class="mono">{{ f.host }}</span> }
              </clr-dg-cell>
              <clr-dg-cell>{{ f.product }}</clr-dg-cell>
              <clr-dg-cell>{{ f.score ?? '–' }}</clr-dg-cell>
              <clr-dg-cell>
                @if (f.kev) { <span class="badge badge-danger">KEV</span> }
                @for (s of f.sources; track s) { @if (s !== 'kev') { <span class="badge">{{ s }}</span> } }
              </clr-dg-cell>
              <clr-dg-cell>{{ f.confidence }}</clr-dg-cell>
              <clr-dg-cell><span class="label" [class]="'label ' + statusClass[f.status]">{{ f.status }}</span></clr-dg-cell>
            </clr-dg-row>

            <ng-template [(clrIfDetail)]="detail" let-f>
              <clr-dg-detail>
                <clr-dg-detail-header>
                  {{ f.cve }} <span class="label" [class]="'label ' + sevClass[f.severity]">{{ f.severity }}</span>
                  @if (f.kev) { <span class="label label-danger">actively exploited</span> }
                </clr-dg-detail-header>
                <clr-dg-detail-body>
                  <p><strong>{{ f.device_name }}</strong> · <span class="mono">{{ f.host }}</span> · {{ f.product }}</p>
                  <p>{{ f.summary }}</p>
                  @if (f.required_action) {
                    <clr-alert clrAlertType="warning" [clrAlertClosable]="false" [clrAlertSizeSmall]="true">
                      <clr-alert-item><span class="alert-text">CISA: {{ f.required_action }}</span></clr-alert-item>
                    </clr-alert>
                  }
                  @if (f.confidence === 'check version') {
                    <p class="muted">The device's version is unknown, so this is listed because it is actively exploited.
                      Check the version on the device, then acknowledge or resolve.</p>
                  }

                  @if (f.items?.length) {
                    <h5>{{ f.sources.includes('trivy') ? 'Vulnerabilities with a fix' : 'Pending packages' }} ({{ f.items.length }})</h5>
                    <div class="items">
                      <table class="table table-compact">
                        <thead><tr><th class="left">{{ f.sources.includes('trivy') ? 'CVE' : 'Package' }}</th><th class="left">Package</th>
                          <th class="left">Installed</th><th class="left">Fixed in</th><th>Severity</th></tr></thead>
                        <tbody>
                          @for (i of f.items.slice(0, 100); track i.id + i.pkg) {
                            <tr>
                              <td class="left mono">{{ i.id }} @if (i.kev) { <span class="badge badge-danger">KEV</span> }</td>
                              <td class="left">{{ i.pkg }}</td>
                              <td class="left mono">{{ i.installed }}</td>
                              <td class="left mono">{{ i.fixed }}</td>
                              <td><span class="label" [class.label-danger]="i.severity === 'critical'"
                                        [class.label-warning]="i.severity === 'high' || i.severity === 'security'">{{ i.severity }}</span></td>
                            </tr>
                          }
                        </tbody>
                      </table>
                    </div>
                  }

                  <h5>Remediation</h5>
                  <div class="actions">
                    @for (p of f.proposals; track p.action) {
                      <button class="btn btn-sm" [class.btn-danger]="isContainment(p.action)"
                              [class.btn-primary]="!isContainment(p.action)" (click)="confirm(f, p)">{{ p.label }}</button>
                    }
                    @if (f.status !== 'acknowledged' && f.status !== 'resolved') {
                      <button class="btn btn-sm btn-outline" (click)="run(f, 'acknowledge')">Acknowledge</button>
                    }
                    @if (f.status !== 'resolved') {
                      <button class="btn btn-sm btn-outline" (click)="run(f, 'resolve')">Mark resolved</button>
                    }
                  </div>
                  @if (!f.proposals.length) {
                    <p class="muted">Protected device: no quarantine. Update it with the vendor's tools.</p>
                  }

                  <h5>References</h5>
                  <ul class="refs">
                    @if (f.cve.startsWith('CVE-')) {
                      <li><a [href]="'https://nvd.nist.gov/vuln/detail/' + f.cve" target="_blank" rel="noopener">NVD {{ f.cve }}</a></li>
                    }
                    @for (r of f.references; track r) { <li><a [href]="r" target="_blank" rel="noopener">{{ r }}</a></li> }
                  </ul>

                  @if (f.history.length) {
                    <h5>History</h5>
                    <ul class="refs">
                      @for (h of f.history; track h.time) {
                        <li>{{ h.time * 1000 | date: 'dd.MM. HH:mm' }} · {{ h.action }} by {{ h.by }}: {{ h.result }}</li>
                      }
                    </ul>
                  }
                  <p class="muted">First seen {{ f.first_seen | ago }} · last seen {{ f.last_seen | ago }}</p>
                </clr-dg-detail-body>
              </clr-dg-detail>
            </ng-template>

            <clr-dg-placeholder>No findings. Sync the CVE feeds or scan the LAN.</clr-dg-placeholder>
            <clr-dg-footer>
              <clr-dg-pagination #pg [clrDgPageSize]="15">
                <clr-dg-page-size [clrPageSizeOptions]="[15, 30, 100]">Per page</clr-dg-page-size>
                {{ pg.firstItem + 1 }}–{{ pg.lastItem + 1 }} of {{ pg.totalItems }}
              </clr-dg-pagination>
            </clr-dg-footer>
          </clr-datagrid>
        </clr-tab-content>
      </clr-tab>

      <clr-tab>
        <button clrTabLink>Quarantine</button>
        <clr-tab-content *clrIfActive>
          <p class="muted">Firewall quarantine drops the host's routed and internet traffic. Wi-Fi quarantine disconnects the
            client and blocks it from rejoining. Same-subnet traffic is switched, not routed, so it is not filtered.</p>
          <clr-datagrid>
            <clr-dg-column [clrDgField]="'kind'">Type</clr-dg-column>
            <clr-dg-column [clrDgField]="'address'">Address</clr-dg-column>
            <clr-dg-column [clrDgField]="'comment'">Reason</clr-dg-column>
            <clr-dg-column>Action</clr-dg-column>
            <clr-dg-row *clrDgItems="let q of quarantined()" [clrDgItem]="q">
              <clr-dg-cell>{{ q.kind === 'wifi' ? 'Wi-Fi' : q.kind === 'fw' ? 'Firewall' : q.kind }}</clr-dg-cell>
              <clr-dg-cell class="mono">{{ q.address }}</clr-dg-cell>
              <clr-dg-cell>{{ q.comment }}</clr-dg-cell>
              <clr-dg-cell>@if (q.kind !== 'dry-run') { <button class="btn btn-sm btn-link" (click)="release(q.kind, q.address)">Release</button> }</clr-dg-cell>
            </clr-dg-row>
            <clr-dg-placeholder>Nothing is quarantined.</clr-dg-placeholder>
          </clr-datagrid>
        </clr-tab-content>
      </clr-tab>

      <clr-tab>
        <button clrTabLink>Discovered services</button>
        <clr-tab-content *clrIfActive>
          <p class="muted">Last scan {{ services().time | ago }} · {{ services().targets.length }} hosts (inventory + DHCP leases).</p>
          <clr-datagrid>
            <clr-dg-column [clrDgField]="'host'">Host
              <clr-dg-string-filter [clrDgStringFilter]="svcHostFilter"></clr-dg-string-filter>
            </clr-dg-column>
            <clr-dg-column [clrDgField]="'port'">Port
              <clr-dg-numeric-filter [clrDgNumericFilter]="portFilter"></clr-dg-numeric-filter>
            </clr-dg-column>
            <clr-dg-column [clrDgField]="'service'">Service
              <clr-dg-string-filter [clrDgStringFilter]="svcFilter"></clr-dg-string-filter>
            </clr-dg-column>
            <clr-dg-column [clrDgField]="'product'">Product / version</clr-dg-column>
            <clr-dg-row *clrDgItems="let s of services().services" [clrDgItem]="s">
              <clr-dg-cell class="mono">{{ s.host }}</clr-dg-cell>
              <clr-dg-cell>{{ s.port }}/{{ s.proto }}</clr-dg-cell>
              <clr-dg-cell>{{ s.service }}</clr-dg-cell>
              <clr-dg-cell>{{ s.product }}</clr-dg-cell>
            </clr-dg-row>
            <clr-dg-placeholder>No scan yet. Use "Scan LAN" (nightly at the time set in .env).</clr-dg-placeholder>
            <clr-dg-footer>
              <span class="footer-note">{{ services().services.length }} open ports</span>
              <clr-dg-pagination #spg [clrDgPageSize]="25">
                <clr-dg-page-size [clrPageSizeOptions]="[25, 50, 100]">per page</clr-dg-page-size>
                {{ spg.firstItem + 1 }}–{{ spg.lastItem + 1 }} of {{ spg.totalItems }}
              </clr-dg-pagination>
            </clr-dg-footer>
          </clr-datagrid>
        </clr-tab-content>
      </clr-tab>

      <clr-tab>
        <button clrTabLink>News &amp; audit</button>
        <clr-tab-content *clrIfActive>
          <div class="clr-row">
            <div class="clr-col-12 clr-col-lg-6">
              <h4>Cloudflare CVE news</h4>
              <ul class="refs">
                @for (n of news(); track n.link) {
                  <li><a [href]="n.link" target="_blank" rel="noopener">{{ n.title }}</a> <span class="muted">· {{ n.date | date: 'dd.MM.yyyy' }}</span></li>
                } @empty { <li class="muted">No news loaded.</li> }
              </ul>
              <p class="muted">Zero Wire itself has no machine-readable feed; this is Cloudflare's CVE blog. Matching uses CISA KEV and NVD.</p>
            </div>
            <div class="clr-col-12 clr-col-lg-6">
              <h4>Audit log</h4>
              <ul class="clr-timeline clr-timeline-vertical">
                @for (a of audit(); track a.time) {
                  <li class="clr-timeline-step">
                    <div class="clr-timeline-step-header">{{ a.time * 1000 | date: 'dd.MM. HH:mm' }}</div>
                    <cds-icon role="img" shape="success-standard" status="success" aria-label="done"></cds-icon>
                    <div class="clr-timeline-step-body">
                      <span class="clr-timeline-step-title">{{ a.action }}@if (a.dry_run) { (dry run) }</span>
                      <span class="clr-timeline-step-description">{{ a.host }} · {{ a.by }} · {{ a.result }}</span>
                    </div>
                  </li>
                } @empty { <li class="muted">No actions yet.</li> }
              </ul>
            </div>
          </div>
        </clr-tab-content>
      </clr-tab>
    </clr-tabs>

    <clr-modal [(clrModalOpen)]="modalOpen" clrModalSize="md">
      <h3 class="modal-title">{{ pending()?.proposal?.label }}</h3>
      <div class="modal-body">
        @if (pending(); as p) {
          <p><strong>{{ p.finding.device_name }}</strong> (<span class="mono">{{ p.finding.host }}</span>) because of {{ p.finding.cve }}.</p>
          <p>{{ p.proposal.description }}</p>
          @if (summary()?.dry_run) { <p class="muted">Dry-run mode: this is only logged.</p> }
        }
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" (click)="modalOpen = false">Cancel</button>
        <button type="button" class="btn btn-danger" [disabled]="busy()" (click)="approve()">{{ busy() ? 'Working…' : 'Approve' }}</button>
      </div>
    </clr-modal>
  `,
  styles: `
    .running { display: flex; align-items: center; gap: 0.8rem; font-size: 0.8rem; margin: 0.4rem 0; }
    .running clr-progress-bar { flex: 1; }
    .score .card-block { padding: 0.6rem 0.9rem; }
    .cap { font-size: 0.62rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; opacity: 0.75; }
    .big { font-size: 1.8rem; font-weight: 500; line-height: 1.2; }
    .sub { font-size: 0.68rem; opacity: 0.75; }
    .sev-critical { border-top: 3px solid #e12200; } .sev-high { border-top: 3px solid #e57200; }
    .sev-medium { border-top: 3px solid #0079ad; } .sev-low { border-top: 3px solid #8c8c8c; }
    .toggle { margin: 0.6rem 0 0; }
    .actions { display: flex; flex-wrap: wrap; gap: 0.3rem; }
    .refs { font-size: 0.75rem; padding-left: 1rem; word-break: break-all; }
    .items { max-height: 18rem; overflow: auto; font-size: 0.72rem; }
    h5 { margin-top: 1rem; }
    .footer-note { margin-right: auto; opacity: 0.8; }
  `,
})
export class SecurityPage implements OnInit {
  /** ?finding=<id> (from an alert's "Open" button) opens that finding. */
  readonly finding = input<string>();
  private api = inject(Api);
  private destroyRef = inject(DestroyRef);
  private ticks = refreshTicks();

  protected severities = ['critical', 'high', 'medium', 'low'] as const;
  protected sevClass = SEV_CLASS;
  protected statusClass = STATUS_CLASS;
  protected summary = signal<SecuritySummary | null>(null);
  protected findings = signal<Finding[]>([]);
  protected showResolved = signal(false);
  protected visible = computed(() => this.findings().filter((f) => this.showResolved() || f.status !== 'resolved'));
  protected detail: Finding | null = null;
  protected loading = signal(true);

  // Discovered-services datagrid filters.
  protected svcHostFilter: ClrDatagridStringFilterInterface<any> = {
    accepts: (s, v) => String(s.host).toLowerCase().includes(v.toLowerCase()),
  };
  protected portFilter: ClrDatagridNumericFilterInterface<any> = {
    accepts: (s, low, high) => (low == null || s.port >= low) && (high == null || s.port <= high),
  };
  protected svcFilter: ClrDatagridStringFilterInterface<any> = {
    accepts: (s, v) => `${s.service} ${s.product}`.toLowerCase().includes(v.toLowerCase()),
  };
  protected quarantined = signal<{ kind: string; address: string; comment: string }[]>([]);
  protected services = signal<{ time: number | null; targets: string[]; services: any[] }>({ time: null, targets: [], services: [] });
  protected news = signal<{ title: string; link: string; date: string }[]>([]);
  protected audit = signal<any[]>([]);
  protected message = signal<{ type: 'success' | 'danger' | 'info'; text: string } | null>(null);
  protected modalOpen = false;
  protected pending = signal<{ finding: Finding; proposal: Proposal } | null>(null);
  protected busy = signal(false);

  ngOnInit(): void {
    this.ticks.pipe(
      switchMap(() => forkJoin([this.api.securitySummary(), this.api.findings()])),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe(([s, f]) => {
      this.summary.set(s);
      this.findings.set(f);
      this.loading.set(false);
      const want = this.finding();
      if (want && !this.detail) this.detail = f.find((x) => x.id === want) ?? null;
    });
    this.loadSide();
  }

  private loadSide(): void {
    this.api.quarantine().subscribe({ next: (q) => this.quarantined.set(q), error: () => this.quarantined.set([]) });
    this.api.securityServices().subscribe((s) => this.services.set(s));
    this.api.securityNews().subscribe((n) => this.news.set(n));
    this.api.securityAudit().subscribe((a) => this.audit.set(a));
  }

  private refresh(): void {
    forkJoin([this.api.securitySummary(), this.api.findings()]).subscribe(([s, f]) => {
      this.summary.set(s);
      this.findings.set(f);
      if (this.detail) this.detail = f.find((x) => x.id === this.detail!.id) ?? null;
    });
    this.loadSide();
  }

  protected sync(): void {
    this.api.securitySync().subscribe(() => { this.message.set({ type: 'info', text: 'CVE feed sync started.' }); this.refresh(); });
  }

  protected scan(): void {
    this.api.securityScan().subscribe(() => { this.message.set({ type: 'info', text: 'LAN scan started; it takes a few minutes.' }); this.refresh(); });
  }

  protected confirm(f: Finding, p: Proposal): void {
    this.pending.set({ finding: f, proposal: p });
    this.modalOpen = true;
  }

  protected approve(): void {
    const p = this.pending();
    if (!p) return;
    this.busy.set(true);
    this.api.findingAction(p.finding.id, p.proposal.action).subscribe({
      next: (r) => { this.busy.set(false); this.modalOpen = false; this.message.set({ type: 'success', text: r.result }); this.refresh(); },
      error: (e) => { this.busy.set(false); this.modalOpen = false; this.message.set({ type: 'danger', text: e.error?.detail ?? e.message }); },
    });
  }

  protected run(f: Finding, action: string): void {
    this.api.findingAction(f.id, action).subscribe({
      next: (r) => { this.message.set({ type: 'success', text: r.result }); this.refresh(); },
      error: (e) => this.message.set({ type: 'danger', text: e.error?.detail ?? e.message }),
    });
  }

  /** Quarantine-type actions are red; fixes (updates) are primary blue. */
  protected isContainment(action: string): boolean {
    return action === 'quarantine' || action === 'wifi-disconnect';
  }

  protected release(kind: string, address: string): void {
    this.api.releaseQuarantine(kind, address).subscribe({
      next: (r) => { this.message.set({ type: 'success', text: r.result }); this.refresh(); },
      error: (e) => this.message.set({ type: 'danger', text: e.error?.detail ?? e.message }),
    });
  }
}
