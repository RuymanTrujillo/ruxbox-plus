// One bounded router attempt includes launch, login, navigation and CGI work.
// Stage limits consume this shared deadline; they are never added sequentially.
export const REQUEST_BUDGETS = Object.freeze({
  routerMs: 70_000,
  cleanupMs: 5_000,
  requestMs: 85_000,
  localMs: 12_000,
  operationMs: 155_000,
  slowMs: 10_000,
  launchMs: 20_000,
  navigationMs: 20_000,
  actionMs: 12_000,
  cgiMs: 12_000,
  submitMs: 15_000,
});

const localResources = new Set([
  '/api/session', '/api/health', '/api/operations', '/api/settings',
  '/api/settings/detect', '/api/disconnect', '/api/commit',
  '/api/router/public-network',
]);
export function requestBudget(resource) {
  return localResources.has(resource) ? REQUEST_BUDGETS.localMs : REQUEST_BUDGETS.requestMs;
}
