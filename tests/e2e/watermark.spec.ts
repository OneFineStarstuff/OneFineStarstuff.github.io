import { expect, test } from '@playwright/test';

/** A2 (WP-114): classification banner + fictional-simulation footer on EVERY view. */
const routes = ['/', '/briefing', '/compliance', '/drills', '/about'];

test.describe('watermark invariants', () => {
  for (const route of routes) {
    test('route ' + route + ' carries the classification banner and disclaimer', async ({ page }) => {
      await page.goto(route);
      await expect(page.getByText('TOP SECRET // SUPERVISORY EYES ONLY')).toBeVisible();
      await expect(page.getByText(/fictional/i)).toBeVisible();
    });
  }
});
