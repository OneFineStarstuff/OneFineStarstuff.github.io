export interface ReportingWindow {
  start: string;
  end: string;
}

/** Returns the most recent completed 24-hour window ending at 09:00 UTC. */
export function getReportingWindow(now?: Date): ReportingWindow;

/** Formats a reporting window as an explicit UTC interval. */
export function formatReportingWindow(window: ReportingWindow): string;
