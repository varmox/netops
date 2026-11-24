import { Component, Pipe, PipeTransform, inject, input } from '@angular/core';
import { toObservable } from '@angular/core/rxjs-interop';
import { ClarityModule } from '@clr/angular';
import { Observable, combineLatest, of, switchMap, timer } from 'rxjs';
import { Status } from './api';
import { Prefs } from './prefs';

const STATUS: Record<Status, { label: string; cls: string; icon: string }> = {
  up: { label: 'Up', cls: 'label-success', icon: 'success-standard' },
  degraded: { label: 'Degraded', cls: 'label-warning', icon: 'warning-standard' },
  down: { label: 'Down', cls: 'label-danger', icon: 'error-standard' },
  unknown: { label: 'Unknown', cls: '', icon: 'unknown-status' },
};

@Component({
  selector: 'app-status',
  imports: [ClarityModule],
  template: `<span class="label" [class]="'label ' + s().cls"><cds-icon [shape]="s().icon" size="12"></cds-icon>&nbsp;{{ s().label }}</span>`,
})
export class StatusLabel {
  readonly status = input<Status>('unknown');
  protected s = () => STATUS[this.status()] ?? STATUS.unknown;
}

/** Unix seconds (or a Date) -> "3 min ago" */
@Pipe({ name: 'ago' })
export class AgoPipe implements PipeTransform {
  transform(value: number | Date | null | undefined): string {
    if (value == null) return '–';
    const ms = value instanceof Date ? value.getTime() : value * 1000;
    const s = Math.round((Date.now() - ms) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
    return `${Math.floor(s / 86400)} d ago`;
  }
}

@Pipe({ name: 'bytes' })
export class BytesPipe implements PipeTransform {
  transform(n: number | null | undefined): string {
    if (n == null) return '–';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
  }
}

/**
 * Emits now, then every `refreshSeconds` while auto refresh is on (Settings). Call in an injection context.
 * Pages pipe it into their API call.
 */
export function refreshTicks(): Observable<number> {
  const prefs = inject(Prefs);
  return combineLatest([toObservable(prefs.autoRefresh), toObservable(prefs.refreshSeconds)]).pipe(
    switchMap(([on, s]) => (on ? timer(0, s * 1000) : of(0))),
  );
}

/** Keep object identity across refreshes, so datagrid selection and open detail panes survive. */
export function mergeById<T extends { id: string }>(current: T[], fresh: T[]): T[] {
  const byId = new Map(current.map((x) => [x.id, x]));
  return fresh.map((f) => {
    const existing = byId.get(f.id);
    return existing ? Object.assign(existing, f) : f;
  });
}
