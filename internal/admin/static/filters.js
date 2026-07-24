// Email-list filter polish. Loaded once from layout.html and driven by a
// delegated document listener, so htmx swaps of #shell need no re-init.
//
// Everything here is optional: without JS the period chips are plain radios
// you confirm with "Apply filters", and the date inputs count only when the
// "Custom" chip is picked (the form says so). This script removes the extra
// tap in both directions — pick a chip and the list reloads, type a date and
// Custom selects itself.
document.addEventListener('change', (e) => {
  const el = e.target;
  if (!(el instanceof HTMLInputElement)) return;
  const form = el.closest('form.filter-form');
  if (!form) return;

  if (el.name === 'range') {
    const dates = [...form.querySelectorAll('input[type="date"]')];
    if (el.value === 'custom') {
      // Only submit once there's something to submit; otherwise leave the
      // chip selected so the dates can be filled in.
      if (dates.some((d) => d.value)) form.requestSubmit();
      return;
    }
    // A preset supersedes the dates server-side; clear them so the form
    // shows the window that's actually in effect.
    dates.forEach((d) => { d.value = ''; });
    form.requestSubmit();
    return;
  }

  if (el.type === 'date') {
    const custom = form.querySelector('input[name="range"][value="custom"]');
    if (custom) custom.checked = true;
  }
});
