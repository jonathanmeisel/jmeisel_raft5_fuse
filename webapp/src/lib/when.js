// Times as people say them: "14:00" today, "yesterday 14:00", else
// "Nov 4 14:00".

export function when(ms) {
  const at = new Date(ms);
  const time = at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const day = new Date(at).setHours(0, 0, 0, 0);
  const today = new Date().setHours(0, 0, 0, 0);
  if (day === today) return time;
  if (today - day === 24 * 3600 * 1000) return `yesterday ${time}`;
  return `${at.toLocaleDateString([], { month: "short", day: "numeric" })} ${time}`;
}
