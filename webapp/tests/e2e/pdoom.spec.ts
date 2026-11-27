import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

/** A3 (WP-114): p(doom) renders inside the configured GREEN threshold. */
test('rendered p(doom) sits inside its bands.json GREEN threshold', async ({ page }) => {
  const here = dirname(fileURLToPath(import.meta.url));
  const bands = JSON.parse(
    readFileSync(resolve(here, '../../src/data/bands.json'), 'utf-8'),
  );
  const greenBelow: number = bands.lowerIsBetter.p_doom_pct.greenBelow;
  expect(greenBelow, 'bands.json must define p_doom_pct.greenBelow').toBeGreaterThan(0);

  await page.goto('/briefing');
  const row = page.getByRole('row').filter({ hasText: 'Ensemble p(doom)' });
  await expect(row).toHaveCount(1);
  await expect(row).toBeVisible();

  const displayedValue = await row.locator('td').nth(1).innerText();
  const numericValue = Number.parseFloat(displayedValue.replace('%', '').trim());
  expect(Number.isFinite(numericValue), 'p(doom) has a numeric percentage').toBe(true);
  expect(numericValue, 'p(doom) within GREEN band').toBeLessThanOrEqual(greenBelow);
});
