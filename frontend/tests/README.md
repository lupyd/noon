# Integrated Playwright Testing for Noon Frontend

This setup provides a comprehensive suite of integrated tests for the Noon frontend, ensuring that core user flows remain functional as the application evolves.

## Getting Started

Playwright is configured to automatically start the Vite dev server on port `8080` before running tests.

### Running Tests

You can run the tests using the following commands from the `frontend` directory:

```bash
# Run all tests in headless mode
npm test

# Run tests with the Playwright UI (interactive)
npm run test:ui

# Show the last test report
npx playwright show-report
```

## Test Structure

The tests are located in the `frontend/tests` directory:

- `home.spec.ts`: Verifies the landing page content and primary call to action.
- `navigation.spec.ts`: Ensures the navbar links correctly route between pages.
- `form-builder.spec.ts`: Tests the form creation flow, including:
    - Authentication gate verification.
    - **Mocked email OTP flow**: Simulates the backend verification process.
    - Form field interaction and deployment simulation.

## Key Features

- **Backend Mocking**: The `form-builder` tests use Playwright's `page.route` to mock backend endpoints. This allows testing complex flows (like OTP verification) without needing a live backend or real email services.
- **Cross-Browser Ready**: Chromium is configured by default, but you can easily enable Firefox and WebKit in `playwright.config.ts`.
- **Automatic Server Management**: The `webServer` configuration in `playwright.config.ts` ensures the frontend is always up during testing.

## Writing New Tests

To add a new test, create a `.spec.ts` file in the `tests` directory. 

Example of mocking a Protobuf response:
```typescript
await page.route('**/api/endpoint', async route => {
  await route.fulfill({
    status: 200,
    contentType: 'application/octet-stream',
    body: Buffer.from([...binaryData]),
  });
});
```
