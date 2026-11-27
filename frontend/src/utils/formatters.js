export function formatDateTime(isoString) {
  if (!isoString) return '—';
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date);
}

export function formatShortTime(isoString) {
  if (!isoString) return '—';
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date);
}

export function formatRelativeTime(isoString) {
  if (!isoString) return '—';
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return '—';
  const diffMs = date.getTime() - Date.now();
  const absSec = Math.round(Math.abs(diffMs) / 1000);
  const past = diffMs < 0;

  if (absSec < 60) return past ? `${absSec}s ago` : `in ${absSec}s`;
  const mins = Math.round(absSec / 60);
  if (mins < 60) return past ? `${mins}m ago` : `in ${mins}m`;
  const hrs = Math.round(mins / 60);
  if (hrs < 48) return past ? `${hrs}h ago` : `in ${hrs}h`;
  const days = Math.round(hrs / 24);
  return past ? `${days}d ago` : `in ${days}d`;
}

export function isExpiredTimestamp(isoString) {
  if (!isoString) return false;
  const ts = new Date(isoString).getTime();
  if (Number.isNaN(ts)) return false;
  return Date.now() >= ts;
}

export function shortenId(value, head = 8, tail = 4) {
  if (!value || typeof value !== 'string') return '—';
  if (value.length <= head + tail + 3) return value;
  return `${value.slice(0, head)}...${value.slice(-tail)}`;
}

export function formatNumber(val) {
  if (val === null || val === undefined || Number.isNaN(Number(val))) return '—';
  return new Intl.NumberFormat('en-US').format(Number(val));
}
