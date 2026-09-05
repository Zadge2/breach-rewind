import type { Bundle, Summary } from "./model";
import { summary } from "./model";
const element = document.getElementById("rewind-evidence");
export const offline = Boolean(element);
export const embedded: Bundle[] = element
  ? JSON.parse(element.textContent ?? "[]")
  : [];
export async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch(path, {
    ...options,
    headers: {
      "X-Rewind-Client": "1",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });
  if (!response.ok) {
    const data = await response
      .json()
      .catch(() => ({ error: `Request failed (${response.status})` }));
    throw new Error(data.error ?? `Request failed (${response.status})`);
  }
  return response.json();
}
export const list = () =>
  offline
    ? Promise.resolve(embedded.map(summary))
    : request<Summary[]>("/api/recordings");
export const get = (id: string, signal?: AbortSignal) =>
  offline
    ? Promise.resolve(embedded.find((b) => b.id === id)!)
    : request<Bundle>(`/api/recordings/${encodeURIComponent(id)}`, { signal });
export function download(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}
export async function report(id: string, baseline: string) {
  const response = await fetch(
    `/api/recordings/${encodeURIComponent(id)}/report${baseline ? `?baseline=${encodeURIComponent(baseline)}` : ""}`,
    { headers: { "X-Rewind-Client": "1" } },
  );
  if (!response.ok)
    throw new Error(
      "Report export failed. Rebuild the viewer assets and retry.",
    );
  download(await response.blob(), "breach-rewind-report.html");
}
