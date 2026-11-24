import { DatePipe } from '@angular/common';
import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { Alerts, LEVEL_LABEL, alertStatus } from '../alerts';
import { Alert, Api } from '../api';
import { Level, Prefs } from '../prefs';

const ICON: Record<Level, string> = {
  danger: 'error-standard', warning: 'warning-standard', success: 'success-standard', info: 'info-standard',
};

@Component({
  selector: 'app-alerts',
  imports: [ClarityModule, FormsModule, DatePipe],
  template: `
    <div class="page-head">
      <h2>Alerts</h2>
      <button class="btn btn-sm btn-outline" (click)="test()" [disabled]="sent()">
        {{ sent() ? 'Test sent' : 'Send test alert' }}
      </button>
    </div>

    <clr-alert [clrAlertType]="alerts.connected() ? 'info' : 'warning'" [clrAlertClosable]="false" [clrAlertLightweight]="true">
      <clr-alert-item>
        <span class="alert-text">
          @if (alerts.connected()) { Live from ntfy topic <span class="mono">{{ topic() }}</span>. }
          @else { Live connection to ntfy lost, reconnecting… }
          Phones: ntfy app → <span class="mono">http://&lt;docker-host&gt;:8090/{{ topic() }}</span>
        </span>
      </clr-alert-item>
    </clr-alert>

    <clr-checkbox-container clrInline>
      <label>Show</label>
      @for (l of levels; track l) {
        <clr-checkbox-wrapper>
          <input type="checkbox" clrCheckbox [name]="'show-' + l"
                 [ngModel]="prefs.levels().includes(l)" (ngModelChange)="prefs.toggleLevel(l, $event)" />
          <label>{{ label[l] }} ({{ count(l) }})</label>
        </clr-checkbox-wrapper>
      }
    </clr-checkbox-container>

    <ul class="clr-timeline clr-timeline-vertical">
      @for (a of alerts.visible(); track a.id) {
        <li class="clr-timeline-step">
          <div class="clr-timeline-step-header">{{ a.time * 1000 | date: 'dd.MM. HH:mm' }}</div>
          <cds-icon role="img" [shape]="icon(a)" [status]="status(a)" [attr.aria-label]="label[status(a)]"></cds-icon>
          <div class="clr-timeline-step-body">
            <span class="clr-timeline-step-title">{{ a.title || 'Alert' }}</span>
            <span class="clr-timeline-step-description">{{ a.message }}</span>
          </div>
        </li>
      } @empty {
        <li class="muted">No alerts in these levels in the last 24 hours.</li>
      }
    </ul>
  `,
})
export class AlertsPage implements OnInit {
  private api = inject(Api);
  protected alerts = inject(Alerts);
  protected prefs = inject(Prefs);
  protected topic = signal('netops');
  protected sent = signal(false);
  protected status = alertStatus;
  protected levels: Level[] = ['danger', 'warning', 'info', 'success'];
  protected label = LEVEL_LABEL;

  ngOnInit(): void {
    this.alerts.markSeen();
    this.api.summary().subscribe((s) => this.topic.set(s.settings.ntfy_topic));
  }

  protected icon(a: Alert): string {
    return ICON[alertStatus(a)];
  }

  protected count(l: Level): number {
    return this.alerts.items().filter((a) => alertStatus(a) === l).length;
  }

  protected test(): void {
    this.sent.set(true);
    this.api.testAlert().subscribe({ complete: () => setTimeout(() => this.sent.set(false), 3000) });
  }
}
