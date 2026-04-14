import { test, expect } from '@playwright/test';

test.describe('Home Page', () => {
  test('should display the main title and hero section', async ({ page }) => {
    await page.goto('/');
    
    // Check for the main heading
    await expect(page.locator('h1')).toContainText(/TRULY ANONYMOUS.*SURVEYS/s);
    
    // Check for "Create New Form" button
    const createBtn = page.getByRole('link', { name: 'Create New Form' });
    await expect(createBtn).toBeVisible();
  });

  test('should navigate to form creation when clicking Create', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('link', { name: 'Create New Form' }).click();
    await expect(page).toHaveURL(/\/create/);
  });
});
