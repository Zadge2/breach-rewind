import { test, expect } from "@playwright/test";
import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {createHash} from 'node:crypto';

test("full investigation: execution, filtering, inspector, playback, graph, comparison and export", async ({
  page,
}, info) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Every action leaves a trace." }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Record demo", exact: true }).click();
  await page.getByLabel("CHOOSE A SCENARIO").selectOption("diagnostic-export");
  await page
    .getByRole("button", { name: "Run & record both versions" })
    .click();
  await expect(page.getByRole("dialog")).toHaveCount(0, { timeout: 30000 });
  await expect(page.locator(".capture-name")).toContainText("vulnerable");
  await expect(page.locator(".event-row")).toHaveCount(9);
  await page.getByLabel("Search events").fill("credential");
  await expect(page.locator(".event-row")).toHaveCount(2);
  await page.locator(".event-row").first().click();
  await expect(page.locator(".attributes")).toContainText("[REDACTED]");
  await page.getByLabel("Search events").fill("does-not-exist");
  await expect(page.getByText("No events match this view.")).toBeVisible();
  await page.getByLabel("Search events").fill("");
  await page.getByRole("button", { name: "High risk", exact: true }).click();
  await expect(page.locator(".event-row")).toHaveCount(3);
  await page.getByRole("button", { name: "High risk", exact: true }).click();
  await page.getByRole("button", { name: "Reset playback" }).click();
  await expect(page.locator(".event-row")).toHaveCount(0);
  await page.getByRole("button", { name: "Play recording" }).click();
  await expect(page.locator(".event-row")).toHaveCount(9, { timeout: 12000 });
  await page.getByRole("tab", { name: "Evidence graph" }).click();
  await expect(
    page.getByRole("img", { name: "Event evidence graph" }),
  ).toBeVisible();
  await expect(page.locator(".graph-node")).toHaveCount(9);
  await page.getByRole("tab", { name: "Before / after" }).click();
  await expect(page.locator(".diff-metrics")).toContainText("Events removed");
  await expect(page.locator(".diff-table")).toContainText(
    "Synthetic credential",
  );
  const reportDownload = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "Export report", exact: true })
    .click();
  const download = await reportDownload;
  const reportPath = info.outputPath("report.html");
  await download.saveAs(reportPath);
  const html = await fs.readFile(reportPath, "utf8");
  expect(html).not.toContain("BR_DECOY_NEVER");
  expect(html).toContain("connect-src 'none'");
  const jsonDownload = page.waitForEvent("download");
  await page.getByLabel("Download evidence JSON").click();
  const json = await jsonDownload;
  const jsonPath = info.outputPath("recording.json");
  await json.saveAs(jsonPath);
  const bundle = JSON.parse(await fs.readFile(jsonPath, "utf8"));
  expect(bundle.digest).toMatch(/^[a-f0-9]{64}$/);
  await page.screenshot({
    path: info.outputPath("comparison.png"),
    fullPage: true,
  });
  // Standalone file must work without the server or an internet connection.
  await page.context().setOffline(true);
  await page.goto(pathToFileURL(reportPath).href);
  await expect(
    page.getByRole("heading", { name: "Every action leaves a trace." }),
  ).toBeVisible();
  await expect(page.locator(".event-row")).toHaveCount(9);
  await page.getByRole("tab", { name: "Before / after" }).click();
  await expect(page.locator(".diff-table")).toContainText(
    "Synthetic credential",
  );
  await page.context().setOffline(false);
  expect(errors).toEqual([]);
});

test("all demo scenarios, keyboard dismissal, mobile layout, and import errors", async ({
  page,
}, info) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Record demo", exact: true }).click();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  for (const scenario of ["path-traversal", "stale-authorization"]) {
    await page
      .getByRole("button", { name: "Record demo", exact: true })
      .click();
    await page.getByLabel("CHOOSE A SCENARIO").selectOption(scenario);
    await page
      .getByRole("button", { name: "Run & record both versions" })
      .click();
    await expect(page.getByRole("dialog")).toHaveCount(0, { timeout: 30000 });
    await expect(page.locator(".event-row")).toHaveCount(10);
  }
  await page
    .locator("input[type=file]")
    .setInputFiles({
      name: "bad.json",
      mimeType: "application/json",
      buffer: Buffer.from('{"schema":"100"}'),
    });
  await expect(page.getByRole("alert")).toBeVisible();
  await page.getByLabel("Dismiss error").click();
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(
    page.getByRole("button", { name: "Record demo", exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: info.outputPath("mobile.png"),
    fullPage: true,
  });
  await page.setViewportSize({ width: 1440, height: 1100 });
  await page.screenshot({
    path: path.resolve("../artifacts/workspace.png"),
    fullPage: true,
  });
});

test("cross-origin pages cannot read or mutate the local API", async ({
  request,
}) => {
  const denied = await request.get("/api/recordings");
  expect(denied.status()).toBe(403);
  const cross = await request.get("/api/recordings", {
    headers: { "X-Rewind-Client": "1", Origin: "https://attacker.invalid" },
  });
  expect(cross.status()).toBe(403);
  const ok = await request.get("/api/recordings", {
    headers: { "X-Rewind-Client": "1" },
  });
  expect(ok.status()).toBe(200);
  expect(ok.headers()["content-security-policy"]).toContain(
    "frame-ancestors 'none'",
  );
});

test('untrusted HTML stays text in the live viewer and offline export',async({page,request},info)=>{
 const headers={'X-Rewind-Client':'1'};
 const list=await (await request.get('/api/recordings',{headers})).json();
 const b=await (await request.get(`/api/recordings/${list[0].id}`,{headers})).json();
 b.id='xss-'+Date.now();b.scenario='';b.title='Hostile evidence test';
 b.events[0].summary='</script><img src=x onerror="window.__rewindXSS=true">';
 b.digest='';
 const canonical=JSON.stringify(b).replace(/</g,'\\u003c').replace(/>/g,'\\u003e').replace(/&/g,'\\u0026').replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029');
 b.digest=createHash('sha256').update(canonical).digest('hex');
 const imported=await request.post('/api/import',{headers:{...headers,'Content-Type':'application/json'},data:JSON.stringify(b)});expect(imported.status()).toBe(201);
 await page.goto('/');await expect(page.locator('.capture-name')).toContainText('Hostile evidence test');await expect(page.locator('.event-row').first()).toContainText('onerror');expect(await page.evaluate(()=>('__rewindXSS' in window))).toBe(false);
 const waiting=page.waitForEvent('download');await page.getByRole('button',{name:'Export report',exact:true}).click();const download=await waiting;const reportPath=info.outputPath('hostile-evidence.html');await download.saveAs(reportPath);await page.goto(pathToFileURL(reportPath).href);await expect(page.locator('.event-row').first()).toContainText('onerror');expect(await page.evaluate(()=>('__rewindXSS' in window))).toBe(false);
});
