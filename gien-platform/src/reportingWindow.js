/**
 * The GIEN prototype's reporting cutoff is 09:00 UTC.
 * This utility only defines the requested reporting window; it does not
 * imply that evidence has been received or validated for that window.
 */
export function getReportingWindow (now = new Date()) {
  const end = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate(),
    9, 0, 0, 0
  ))

  if (now.getTime() < end.getTime()) {
    end.setUTCDate(end.getUTCDate() - 1)
  }

  const start = new Date(end.getTime() - 24 * 60 * 60 * 1000)
  return { start: start.toISOString(), end: end.toISOString() }
}

export function formatReportingWindow (window) {
  return `${window.start} — ${window.end}`
}
