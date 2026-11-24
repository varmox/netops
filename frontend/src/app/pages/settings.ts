import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ClarityModule } from '@clr/angular';
import { LEVEL_LABEL } from '../alerts';
import { Api, Summary } from '../api';
import { Level, Prefs, ThemePref } from '../prefs';

@Component({
  selector: 'app-settings',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="page-head"><h2>Settings</h2></div>
    <p class="muted">Display settings are stored in this browser. Server settings come from <span class="mono">.env</span>.</p>

    <div class="clr-row">
      <div class="clr-col-12 clr-col-lg-6">
        <div class="card"><div class="card-header">Appearance</div><div class="card-block">
          <clr-radio-container clrInline>
            <label>Theme</label>
            @for (t of themes; track t.value) {
              <clr-radio-wrapper>
                <input type="radio" clrRadio name="theme" [value]="t.value"
                       [ngModel]="prefs.theme()" (ngModelChange)="prefs.theme.set($event)" />
                <label>{{ t.label }}</label>
              </clr-radio-wrapper>
            }
          </clr-radio-container>
        </div></div>

        <div class="card"><div class="card-header">Refresh</div><div class="card-block">
          <clr-toggle-container>
            <label>Auto refresh</label>
            <clr-toggle-wrapper>
              <input type="checkbox" clrToggle name="autoRefresh"
                     [ngModel]="prefs.autoRefresh()" (ngModelChange)="prefs.autoRefresh.set($event)" />
              <label>Reload dashboard and device lists automatically</label>
            </clr-toggle-wrapper>
          </clr-toggle-container>
          <clr-radio-container clrInline>
            <label>Every</label>
            @for (s of intervals; track s) {
              <clr-radio-wrapper>
                <input type="radio" clrRadio name="interval" [value]="s" [disabled]="!prefs.autoRefresh()"
                       [ngModel]="prefs.refreshSeconds()" (ngModelChange)="prefs.refreshSeconds.set($event)" />
                <label>{{ s }} s</label>
              </clr-radio-wrapper>
            }
          </clr-radio-container>
        </div></div>
      </div>

      <div class="clr-col-12 clr-col-lg-6">
        <div class="card"><div class="card-header">Alerts</div><div class="card-block">
          <clr-checkbox-container>
            <label>Show these levels (Alerts page, bell badge, notifications)</label>
            @for (l of levels; track l) {
              <clr-checkbox-wrapper>
                <input type="checkbox" clrCheckbox [name]="'level-' + l"
                       [ngModel]="prefs.levels().includes(l)" (ngModelChange)="prefs.toggleLevel(l, $event)" />
                <label>{{ label[l] }}</label>
              </clr-checkbox-wrapper>
            }
          </clr-checkbox-container>
          <clr-toggle-container>
            <label>Banner</label>
            <clr-toggle-wrapper>
              <input type="checkbox" clrToggle name="downBanner"
                     [ngModel]="prefs.downBanner()" (ngModelChange)="prefs.downBanner.set($event)" />
              <label>Red banner at the top while a device is down</label>
            </clr-toggle-wrapper>
          </clr-toggle-container>
          <clr-toggle-container>
            <label>Desktop notifications</label>
            <clr-toggle-wrapper>
              <input type="checkbox" clrToggle name="desktop" [disabled]="permission() === 'denied' || permission() === 'unsupported'"
                     [ngModel]="prefs.desktopNotifications()" (ngModelChange)="setDesktop($event)" />
              <label>Pop up new alerts while this tab is open</label>
            </clr-toggle-wrapper>
            @if (permission() === 'denied') {
              <clr-control-helper>Blocked in the browser settings for this site.</clr-control-helper>
            }
            @if (permission() === 'unsupported') {
              <clr-control-helper>This browser can't show notifications here (they need HTTPS).</clr-control-helper>
            }
          </clr-toggle-container>
        </div></div>

        @if (summary(); as s) {
          <div class="card"><div class="card-header">Server</div><div class="card-block">
            <clr-stack-view>
              <clr-stack-block><clr-stack-label>Health checks</clr-stack-label><clr-stack-content>every {{ s.settings.check_interval }} s</clr-stack-content></clr-stack-block>
              <clr-stack-block><clr-stack-label>Config backups</clr-stack-label><clr-stack-content>daily at {{ s.settings.backup_time }}</clr-stack-content></clr-stack-block>
              <clr-stack-block><clr-stack-label>ntfy topic</clr-stack-label><clr-stack-content class="mono">{{ s.settings.ntfy_topic }}</clr-stack-content></clr-stack-block>
              <clr-stack-block><clr-stack-label>Phone subscription</clr-stack-label><clr-stack-content class="mono">http://&lt;docker-host&gt;:8090/{{ s.settings.ntfy_topic }}</clr-stack-content></clr-stack-block>
            </clr-stack-view>
          </div></div>
        }
      </div>
    </div>
  `,
  styles: `.card { margin-top: 0; margin-bottom: 1rem; }`,
})
export class SettingsPage implements OnInit {
  private api = inject(Api);
  protected prefs = inject(Prefs);
  protected summary = signal<Summary | null>(null);
  protected permission = signal<NotificationPermission | 'unsupported'>(
    'Notification' in window ? Notification.permission : 'unsupported');
  protected themes: { value: ThemePref; label: string }[] = [
    { value: 'system', label: 'Like the system' }, { value: 'light', label: 'Light' }, { value: 'dark', label: 'Dark' },
  ];
  protected intervals = [15, 30, 60];
  protected levels: Level[] = ['danger', 'warning', 'info', 'success'];
  protected label = LEVEL_LABEL;

  ngOnInit(): void {
    this.api.summary().subscribe((s) => this.summary.set(s));
  }

  protected async setDesktop(on: boolean): Promise<void> {
    if (on && 'Notification' in window && Notification.permission === 'default') {
      this.permission.set(await Notification.requestPermission());
    }
    this.prefs.desktopNotifications.set(on && this.permission() === 'granted');
  }
}
