import { test, expect } from '@playwright/test';

test.describe('Navigation', () => {
  test('should have a working navbar', async ({ page }) => {
    await page.goto('/');

    // Check Dashboard link
    await page.getByRole('link', { name: 'Dashboard' }).click();
    await expect(page).toHaveURL(/\/dashboard/);

    // Check Logo link returns home
    await page.locator('header .logo').click();
    await expect(page).toHaveURL(/\/$/);
  });
});
