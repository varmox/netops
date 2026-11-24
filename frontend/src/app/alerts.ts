import { Injectable, OnDestroy, computed, inject, signal } from '@angular/core';
import { Alert, Api } from './api';
import { Level, Prefs } from './prefs';

/**
 * Alerts from ntfy: the last 24 h from the backend, then live over Server-Sent Events
 * (nginx proxies /ntfy/<topic>/sse to the ntfy container, behind the login).
 */
@Injectable({ providedIn: 'root' })
export class Alerts implements OnDestroy {
  private api = inject(Api);
  private prefs = inject(Prefs);
  private source?: EventSource;

  readonly items = signal<Alert[]>([]);
  readonly connected = signal(false);
  readonly unseen = signal(0);
  /** Alerts in the levels chosen in Settings. */
  readonly visible = computed(() => this.items().filter((a) => this.prefs.levels().includes(alertStatus(a))));

  start(topic: string): void {
    if (this.source) return;
    this.api.alerts().subscribe((list) => this.items.set(list));
    this.source = new EventSource(`/ntfy/${encodeURIComponent(topic)}/sse`, { withCredentials: true });
    this.source.onopen = () => this.connected.set(true);
    this.source.onerror = () => this.connected.set(false);   // EventSource reconnects by itself
    this.source.onmessage = (e) => {
      const msg = JSON.parse(e.data);
      if (msg.event !== 'message') return;
      const alert = msg as Alert;
      this.items.update((list) => [alert, ...list.filter((a) => a.id !== alert.id)].slice(0, 200));
      if (this.prefs.levels().includes(alertStatus(alert))) {
        this.unseen.update((n) => n + 1);
        this.desktop(alert);
      }
    };
  }

  stop(): void {
    this.source?.close();
    this.source = undefined;
    this.connected.set(false);
  }

  markSeen(): void {
    this.unseen.set(0);
  }

  private desktop(a: Alert): void {
    if (this.prefs.desktopNotifications() && 'Notification' in window && Notification.permission === 'granted') {
      new Notification(a.title || 'NetOps alert', { body: a.message, tag: a.id });
    }
  }

  ngOnDestroy(): void {
    this.stop();
  }
}

/** ntfy priority (1-5) and tags -> Clarity status */
export function alertStatus(a: Alert): Level {
  if (a.tags?.includes('white_check_mark')) return 'success';
  if ((a.priority ?? 3) >= 5) return 'danger';
  if ((a.priority ?? 3) >= 4) return 'warning';
  return 'info';
}

export const LEVEL_LABEL: Record<Level, string> = {
  danger: 'Critical', warning: 'Warning', info: 'Info', success: 'Recovered',
};
