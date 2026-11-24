import { AfterViewInit, Component, ElementRef, OnDestroy, effect, inject, input, output, viewChild } from '@angular/core';
import { BarChart, GraphChart, LineChart, TreemapChart } from 'echarts/charts';
import { GridComponent, LegendComponent, TitleComponent, TooltipComponent } from 'echarts/components';
import * as echarts from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import { Prefs } from './prefs';

echarts.use([LineChart, BarChart, TreemapChart, GraphChart, GridComponent, TitleComponent, TooltipComponent, LegendComponent, CanvasRenderer]);

/** Clarity's data-visualisation colours, in the order series get them. */
export const PALETTE = ['#0079ad', '#49afd9', '#8939ad', '#00bfa9', '#e57200', '#e12200', '#62a420', '#ffb92e'];
export const HEALTH = { good: '#62a420', warn: '#efc006', bad: '#e12200', unknown: '#8c8c8c' };

export type Series = { name: string; values: [number, number][] };

function themeColors(dark: boolean) {
  return {
    text: dark ? '#adbbc4' : '#565656',
    grid: dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.07)',
    tooltipBg: dark ? '#21333b' : '#ffffff',
  };
}

/** One ECharts instance that follows its container size and the app theme. */
@Component({
  selector: 'app-chart',
  template: `<div #el class="chart" [style.height]="height()"></div>`,
  styles: `.chart { width: 100%; }`,
})
export class Chart implements AfterViewInit, OnDestroy {
  readonly options = input.required<echarts.EChartsCoreOption>();
  readonly height = input('220px');
  readonly itemClick = output<{ name: string; data: unknown }>();
  private el = viewChild.required<ElementRef<HTMLDivElement>>('el');
  private prefs = inject(Prefs);
  private chart?: echarts.ECharts;
  private resize = new ResizeObserver(() => this.chart?.resize());

  constructor() {
    effect(() => {
      const opts = this.options();
      const c = themeColors(this.prefs.effectiveTheme() === 'dark');
      this.chart?.setOption({
        color: PALETTE,
        textStyle: { color: c.text, fontFamily: 'Metropolis, "Avenir Next", "Helvetica Neue", Arial, sans-serif' },
        tooltip: { backgroundColor: c.tooltipBg, borderWidth: 0, textStyle: { color: c.text } },
        ...opts,
      }, { notMerge: true });
    });
  }

  ngAfterViewInit(): void {
    this.chart = echarts.init(this.el().nativeElement, undefined, { renderer: 'canvas' });
    this.chart.on('click', (p) => this.itemClick.emit({ name: p.name, data: p.data }));
    this.resize.observe(this.el().nativeElement);
    // the effect ran before init: apply once now
    const c = themeColors(this.prefs.effectiveTheme() === 'dark');
    this.chart.setOption({ color: PALETTE, textStyle: { color: c.text }, ...this.options() });
  }

  ngOnDestroy(): void {
    this.resize.disconnect();
    this.chart?.dispose();
  }
}

/** Axis/grid styling shared by the time-series charts. */
export function timeSeriesOptions(series: Series[], opts: { unit?: string; area?: boolean; dark: boolean; max?: number }) {
  const c = themeColors(opts.dark);
  return {
    grid: { left: 8, right: 12, top: 28, bottom: 4, containLabel: true },
    legend: { top: 0, right: 0, icon: 'roundRect', itemWidth: 10, itemHeight: 4, textStyle: { color: c.text, fontSize: 11 } },
    tooltip: { trigger: 'axis', valueFormatter: (v: number) => formatValue(v, opts.unit) },
    xAxis: { type: 'time', axisLine: { lineStyle: { color: c.grid } }, axisLabel: { color: c.text, fontSize: 10 }, splitLine: { show: false } },
    yAxis: {
      type: 'value', max: opts.max, splitLine: { lineStyle: { color: c.grid } },
      axisLabel: { color: c.text, fontSize: 10, formatter: (v: number) => formatValue(v, opts.unit) },
    },
    series: series.map((s) => ({
      name: s.name, type: 'line', showSymbol: false, smooth: 0.2, lineStyle: { width: 1.6 },
      areaStyle: opts.area ? { opacity: 0.12 } : undefined,
      data: s.values.map(([t, v]) => [t * 1000, v]),
    })),
  };
}

export function formatValue(v: number, unit?: string): string {
  if (v == null || Number.isNaN(v)) return '–';
  switch (unit) {
    case 'bps': {
      const u = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s'];
      let i = 0;
      while (Math.abs(v) >= 1000 && i < u.length - 1) { v /= 1000; i++; }
      return `${v.toFixed(v < 10 && i ? 1 : 0)} ${u[i]}`;
    }
    case 'ms': return `${v.toFixed(v < 10 ? 1 : 0)} ms`;
    case '%': return `${v.toFixed(0)} %`;
    case 'C': return `${v.toFixed(0)} °C`;
    case 'dBm': return `${v.toFixed(0)} dBm`;
    default: return v.toFixed(Math.abs(v) < 10 ? 1 : 0);
  }
}

/** A tiny line without axes, for scoreboards and lists. */
@Component({
  selector: 'app-spark',
  imports: [Chart],
  template: `<app-chart [options]="opts()" [height]="height()" />`,
})
export class Spark {
  readonly values = input<[number, number][]>([]);
  readonly color = input(PALETTE[0]);
  readonly height = input('36px');
  protected opts = () => ({
    animation: false,
    grid: { left: 0, right: 0, top: 2, bottom: 2 },
    xAxis: { type: 'time', show: false },
    yAxis: { type: 'value', show: false, scale: true },
    tooltip: { show: false },
    series: [{
      type: 'line', showSymbol: false, smooth: 0.3, lineStyle: { width: 1.5, color: this.color() },
      areaStyle: { color: this.color(), opacity: 0.12 },
      data: this.values().map(([t, v]) => [t * 1000, v]),
    }],
  });
}
