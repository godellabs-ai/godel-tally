// Console timestamps read "14th Oct 2026" (plus "15:05:33" where the time matters) in the viewer's browser timezone.
type DateInput = string | number | Date;
const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const pad = (value: number) => String(value).padStart(2, "0");
const ordinal = (day: number) => `${day}${day % 100 >= 11 && day % 100 <= 13 ? "th" : ["th", "st", "nd", "rd"][day % 10] ?? "th"}`;

// Local Date getters resolve in the browser's timezone; unparseable values are shown as received.
function parse(value: DateInput) {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}
export function formatDate(value: DateInput) {
  const date = parse(value);
  return date ? `${ordinal(date.getDate())} ${months[date.getMonth()]} ${date.getFullYear()}` : String(value);
}
export function formatTime(value: DateInput) {
  const date = parse(value);
  return date ? `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}` : String(value);
}
export function formatDateTime(value: DateInput) {
  const date = parse(value);
  return date ? `${formatDate(date)}, ${formatTime(date)}` : String(value);
}
export const browserTimeZone = () => Intl.DateTimeFormat().resolvedOptions().timeZone;
