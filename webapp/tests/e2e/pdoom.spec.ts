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
  const greenBelow: number = bands.lowerIsBetter['p(doom)'].greenBelow;
  expect(greenBelow, 'bands.json must define a greenBelow threshold for p(doom)').toBeTruthy();

  await page.goto('/');
  const panel = page.getByText(/p\\(doom\\)/i).first();
  await expect(panel).toBeVisible();

  const body = await page.locator('body').innerText();
  const match = body.match(/p\\(doom\\)[^0-9]*([0-9]+(?:\\.[0-9]+)?)\\s*%/i);
  expect(match, 'p(doom) renders as a percentage').toBeTruthy();
  expect(Number(match![1]), 'p(doom) within GREEN band').toBeLessThanOrEqual(greenBelow);
});
