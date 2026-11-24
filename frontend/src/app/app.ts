import { Component, DestroyRef, computed, effect, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import {
  ClarityIcons, ClarityModule, angleIcon, backupIcon, bellIcon, blockIcon, bugIcon, certificateIcon, checkCircleIcon,
  clockIcon, cogIcon, dashboardIcon, devicesIcon, displayIcon, dotCircleIcon, downloadIcon,
  errorStandardIcon, exclamationCircleIcon, fileIcon, filterGridIcon, historyIcon, homeIcon, hostIcon, hourglassIcon,
  inboxIcon, infoStandardIcon, keyIcon, lineChartIcon,
  lockIcon, logoutIcon, mobileIcon, plusIcon, unlockIcon, moonIcon, networkGlobeIcon, popOutIcon, radarIcon, refreshIcon,
  routerIcon, shieldIcon, successStandardIcon, sunIcon, switchIcon,
  unknownStatusIcon, userIcon, videoCameraIcon, volumeUpIcon, warningStandardIcon, wifiIcon, worldIcon,
} from '@clr/angular';
import { EMPTY, switchMap, timer } from 'rxjs';
import { Alerts } from './alerts';
import { Api, Device } from './api';
import { Auth } from './auth';
import { FeaturesService } from './features';
import { Prefs } from './prefs';
import { VaultService } from './vault';

ClarityIcons.addIcons(
  angleIcon, backupIcon, bellIcon, blockIcon, bugIcon, certificateIcon, checkCircleIcon, clockIcon, cogIcon, dashboardIcon,
  devicesIcon, displayIcon, dotCircleIcon, downloadIcon, errorStandardIcon, exclamationCircleIcon, fileIcon, filterGridIcon,
  historyIcon, homeIcon, hostIcon, hourglassIcon, inboxIcon, infoStandardIcon, keyIcon, lineChartIcon, lockIcon, logoutIcon,
  mobileIcon, moonIcon, networkGlobeIcon, plusIcon, unlockIcon,
  popOutIcon, radarIcon, refreshIcon, routerIcon, shieldIcon, successStandardIcon, sunIcon, switchIcon, unknownStatusIcon, userIcon,
  videoCameraIcon, volumeUpIcon, warningStandardIcon, wifiIcon, worldIcon,
);

@Component({
  selector: 'app-root',
  imports: [ClarityModule, RouterOutlet, RouterLink, RouterLinkActive],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App {
  private api = inject(Api);
  protected auth = inject(Auth);
  protected alerts = inject(Alerts);
  protected prefs = inject(Prefs);
  protected vault = inject(VaultService);
  protected navCollapsed = signal(false);
  protected devices = signal<Device[]>([]);
  protected bannerClosed = signal(false);
  protected down = computed(() => this.devices().filter((d) => d.state.status === 'down'));
  protected criticalFindings = signal(0);
  // Shared feature state: a toggle on the Features page updates this instantly, so the sidebar follows.
  protected features = inject(FeaturesService);
  protected postureKeys = ['certs', 'lifecycle', 'exposure', 'honeypot', 'credcheck'];

  constructor() {
    const destroyRef = inject(DestroyRef);
    // Once logged in: live alerts, and a device poll for the "device down" banner.
    effect(() => {
      if (this.auth.user()) {
        this.api.summary().subscribe((s) => this.alerts.start(s.settings.ntfy_topic));
        this.vault.refresh().subscribe();
      } else {
        this.alerts.stop();
      }
    });
    timer(0, 30000).pipe(
      switchMap(() => (this.auth.user() ? this.api.devices() : EMPTY)),
      takeUntilDestroyed(destroyRef),
    ).subscribe((d) => {
      if (this.down().length === 0) this.bannerClosed.set(false);   // a new outage shows the banner again
      this.devices.set(d);
      this.api.securitySummary().subscribe({ next: (s) => this.criticalFindings.set(s.open.critical), error: () => {} });
      this.vault.refresh().subscribe({ error: () => {} });
      this.features.refresh().subscribe({ error: () => {} });
    });
  }

  /** A nav item for a feature shows when the feature is on (and while feature state is still loading). */
  protected feat(key: string): boolean {
    return this.features.enabled(key);
  }

  protected postureOn(): boolean {
    return this.features.anyEnabled(this.postureKeys);
  }

  protected toggleTheme(): void {
    this.prefs.theme.set(this.prefs.effectiveTheme() === 'dark' ? 'light' : 'dark');
  }

  protected downNames(): string {
    return this.down().map((d) => d.name).join(', ');
  }
}
