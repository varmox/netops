import { HttpClient } from '@angular/common/http';
import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ClarityModule } from '@clr/angular';

export interface TimelineEvent {
  time: number;
  kind: string;
  level: string;
  title: string;
  detail: string;
  ref: string | null;
  device?: string;
  device_name?: string;
}

const KIND_ICON: Record<string, string> = {
  config: 'file', security: 'shield', certificate: 'certificate', exposure: 'world',
  honeypot: 'bug', lifecycle: 'hourglass',
};

@Component({
  selector: 'app-timeline',
  imports: [ClarityModule, RouterLink, DatePipe],
  template: `
    <div class="page-head"><h2>Timeline</h2></div>
    <p class="muted">Everything that changed across the network — config backups, findings, certificates,
      exposure, end-of-life and honeypot hits — newest first.</p>
    <ul class="tl">
      @for (e of events(); track $index) {
        <li class="tl-item" [class]="'lvl-' + e.level">
          <cds-icon [shape]="icon(e.kind)" size="16"></cds-icon>
          <div class="tl-body">
            <div class="tl-top"><span class="tl-title">{{ e.title }}</span>
              @if (e.device) { <a class="tl-dev" [routerLink]="['/devices', e.device]">{{ e.device_name }}</a> }
              <span class="tl-time">{{ e.time * 1000 | date: 'MMM d, HH:mm' }}</span></div>
            @if (e.detail) { <div class="tl-detail">{{ e.detail }}</div> }
          </div>
        </li>
      } @empty { <li class="muted">Nothing recorded yet.</li> }
    </ul>
  `,
  styles: `
    .tl { list-style: none; padding: 0; margin: 0; }
    .tl-item { display: flex; gap: 0.7rem; padding: 0.55rem 0; border-bottom: 1px solid var(--clr-color-neutral-300, #ccc); align-items: flex-start; }
    .tl-item cds-icon { margin-top: 0.15rem; flex: none; }
    .tl-body { flex: 1; min-width: 0; }
    .tl-top { display: flex; gap: 0.6rem; align-items: baseline; flex-wrap: wrap; }
    .tl-title { font-weight: 600; }
    .tl-time { color: var(--clr-color-neutral-600, #666); font-size: 0.75rem; margin-left: auto; }
    .tl-detail { color: var(--clr-color-neutral-700, #555); font-size: 0.85rem; }
    .lvl-warning cds-icon { color: var(--clr-color-warning-800, #a65); }
    .lvl-critical cds-icon { color: var(--clr-color-danger-700, #c21d00); }
  `,
})
export class TimelinePage implements OnInit {
  private http = inject(HttpClient);
  protected events = signal<TimelineEvent[]>([]);
  protected icon = (k: string) => KIND_ICON[k] ?? 'dot-circle';

  ngOnInit(): void {
    this.http.get<TimelineEvent[]>('/api/timeline').subscribe((e) => this.events.set(e));
  }
}
