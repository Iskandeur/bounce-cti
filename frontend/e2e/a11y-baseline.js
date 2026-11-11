// axe-core rules the app violates today, each with what is wrong and why it is
// tolerated for now. This is the to-do list of the accessibility work: fix a
// rule in the app, then delete its line here, and a11y.spec.js keeps it fixed.
// A rule missing from this list fails the suite as soon as one element breaks it.
// The check goes one way: a listed rule that no longer fires is not reported.
//
// Counts are elements on the fixture investigation, dark / light theme, taken
// when the baseline was written (2026-11-11, axe-core 4.14).
export const BASELINE = {
  // WCAG 2 A / AA
  'color-contrast':
    '35 / 27 on the main screen, 2 on the login screen. Dim text on the dark surfaces ' +
    '(#768390, 4.46:1 at best, 3.28:1 on chips), the hypothesis card, and in the light theme ' +
    'the status green (1.7:1), amber chips and links. Needs the theme tokens of styles.css ' +
    'retuned, a design change with its own review.',
  'select-name':
    '1. The Model <select> of the new-investigation form has no label, title or aria-label ' +
    '(its name is the "Model" div above it, tied to nothing).',
  'scrollable-region-focusable':
    '1. The agent log (.event-log) scrolls and cannot be reached with the keyboard.',

  // axe best practices
  'label-title-only':
    '2. The Vertical and Thinking effort <select>s are named by their title attribute only.',
  'landmark-one-main':
    '1. The page has no <main>: the shell is a grid of <div>s.',
  'page-has-heading-one':
    '1. No <h1>; section titles are styled <div>s (.section-label).',
  'region':
    '34 on the main screen, 5 on the login screen. Follows from the two above: ' +
    'nothing is inside a landmark.',
}
