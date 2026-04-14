import { test, expect } from '@playwright/test';

test.describe('Navigation', () => {
  test('should have a working navbar', async ({ page }) => {
    await page.goto('/');

    // Check Dashboard link
    await page.getByRole('link', { name: 'Dashboard' }).click();
    await expect(page).toHaveURL(/\/dashboard/);

    // Check Build link
    await page.getByRole('link', { name: 'Build' }).click();
    await expect(page).toHaveURL(/\/create/);

    // Check Logo link returns home
    await page.locator('header .logo').click();
    await expect(page).toHaveURL(/\/$/);
  });

  test('should show status link pointing to backend', async ({ page }) => {
    await page.goto('/');
    const statusLink = page.getByRole('link', { name: 'Status' });
    await expect(statusLink).toHaveAttribute('href', 'http://localhost:39210/health');
  });
});
