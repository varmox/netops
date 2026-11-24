import { Routes } from '@angular/router';
import { authGuard } from './auth';

export const routes: Routes = [
  { path: 'login', title: 'Log in · NetOps', loadComponent: () => import('./pages/login').then((m) => m.LoginPage) },
  { path: 'setup', title: 'Set up · NetOps', loadComponent: () => import('./pages/setup').then((m) => m.SetupPage) },
  { path: 'enroll', title: 'Second factor · NetOps', loadComponent: () => import('./pages/setup').then((m) => m.EnrollPage) },
  { path: 'k/:token', title: 'Status', loadComponent: () => import('./pages/kiosk').then((m) => m.KioskPage) },
  {
    path: '',
    canActivateChild: [authGuard],
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'dashboard' },
      { path: 'dashboard', title: 'Dashboard · NetOps', loadComponent: () => import('./pages/dashboard').then((m) => m.DashboardPage) },
      { path: 'devices', title: 'Devices · NetOps', loadComponent: () => import('./pages/devices').then((m) => m.DevicesPage) },
      { path: 'devices/:id', title: 'Device · NetOps', loadComponent: () => import('./pages/device').then((m) => m.DevicePage) },
      { path: 'backups', title: 'Backups · NetOps', loadComponent: () => import('./pages/backups').then((m) => m.BackupsPage) },
      { path: 'alerts', title: 'Alerts · NetOps', loadComponent: () => import('./pages/alerts').then((m) => m.AlertsPage) },
      { path: 'security', title: 'Security · NetOps', loadComponent: () => import('./pages/security').then((m) => m.SecurityPage) },
      { path: 'posture', title: 'Posture · NetOps', loadComponent: () => import('./pages/posture').then((m) => m.PosturePage) },
      { path: 'dns', title: 'DNS · NetOps', loadComponent: () => import('./pages/dns').then((m) => m.DnsPage) },
      { path: 'timeline', title: 'Timeline · NetOps', loadComponent: () => import('./pages/timeline').then((m) => m.TimelinePage) },
      { path: 'map', title: 'Network map · NetOps', loadComponent: () => import('./pages/map').then((m) => m.MapPage) },
      { path: 'wifi', title: 'Wi-Fi · NetOps', loadComponent: () => import('./pages/wifi').then((m) => m.WifiPage) },
      { path: 'family', title: 'Status · NetOps', loadComponent: () => import('./pages/family').then((m) => m.FamilyPage) },
      { path: 'metrics', title: 'Metrics · NetOps', loadComponent: () => import('./pages/metrics').then((m) => m.MetricsPage) },
      { path: 'features', title: 'Features · NetOps', loadComponent: () => import('./pages/features').then((m) => m.FeaturesPage) },
      { path: 'settings', title: 'Settings · NetOps', loadComponent: () => import('./pages/settings').then((m) => m.SettingsPage) },
      { path: 'account', title: 'Account · NetOps', loadComponent: () => import('./pages/account').then((m) => m.AccountPage) },
      { path: 'vault', title: 'Vault · NetOps', loadComponent: () => import('./pages/vault').then((m) => m.VaultPage) },
    ],
  },
  { path: '**', redirectTo: 'dashboard' },
];
