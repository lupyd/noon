import { test, expect } from '@playwright/test';

test.describe('Form Builder', () => {
  test('should show authentication required message when not logged in', async ({ page }) => {
    await page.goto('/create');
    await expect(page.getByRole('heading', { name: 'Create New Form' })).toBeVisible();
    await expect(page.getByPlaceholder('Email Address')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Send Verification Code' })).toBeVisible();
  });

  test('should allow email verification flow', async ({ page }) => {
    await page.goto('/create');
    
    // Mock the request_otp endpoint
    await page.route('**/email/request_otp', async route => {
      await route.fulfill({ status: 200 });
    });

    // Mock the verify_otp endpoint
    await page.route('**/email/verify_otp', async route => {
      await route.fulfill({ 
        status: 200, 
        contentType: 'text/plain',
        body: 'mock-session-token' 
      });
    });

    // Fill email
    await page.getByPlaceholder('Email Address').fill('test@example.com');
    await page.getByRole('button', { name: 'Send Verification Code' }).click();

    // Verify code input appears
    await expect(page.getByPlaceholder('000000')).toBeVisible();

    // Fill code and verify
    await page.getByPlaceholder('000000').fill('123456');
    await page.getByRole('button', { name: 'Verify & Enter' }).click();

    // Now it should show the form builder
    await expect(page.getByRole('heading', { name: 'Create New Form' })).toBeVisible();
    
    // Test adding a field
    await page.getByRole('button', { name: 'Add New Field' }).click();
    await expect(page.getByText('1 Fields')).toBeVisible();
    
    // Test filling form details
    await page.getByPlaceholder('e.g. Q2 Performance Review').fill('Test Form');
    await page.getByPlaceholder('Detailed instruction for respondents...').fill('Test Description');
    await page.getByPlaceholder('team@company.com, user@example.com').fill('participant@example.com');
    
    // Test deadline
    await page.locator('input[type="datetime-local"]').fill('2026-12-31T23:59');

    // Click deploy (should fail if we don't mock the create endpoint)
    await page.route('**/forms/create', async route => {
      await route.fulfill({ 
        status: 200, 
        contentType: 'application/json',
        body: JSON.stringify({ id: 123 }) 
      });
    });
    
    await page.getByRole('button', { name: 'Create Form' }).click();
    
    // Check success state
    await expect(page.getByRole('heading', { name: 'Form Ready' })).toBeVisible();
    await expect(page.locator('code')).toContainText('/forms/123');
  });
});
