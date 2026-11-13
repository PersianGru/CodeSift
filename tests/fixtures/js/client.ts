// Deliberately vulnerable sample for CodeSift tests. Never deploy.
export function render(el: HTMLElement, params: URLSearchParams): void {
  // REAL: DOM XSS from the URL
  el.innerHTML = "<p>" + params.get("msg") + "</p>";
}

export function redirect(params: URLSearchParams): void {
  // REAL: open redirect
  window.location.href = params.get("next") as string;
}

export function title(el: HTMLElement): void {
  // FALSE POSITIVE: constant markup
  el.innerHTML = "<b>Dashboard</b>";
}
