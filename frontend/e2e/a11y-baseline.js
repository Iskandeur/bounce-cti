// axe-core rules the app is allowed to violate, each with what is wrong and why
// it is tolerated for now. Empty since 2026-11-13: the seven rules listed when
// the suite was written (colour contrast, the unnamed <select>s, the agent log
// out of keyboard reach, no <main>, no <h1>, content outside landmarks) are
// fixed, and a11y.spec.js keeps them fixed on the screens it opens.
//
// A rule missing from this list fails the suite as soon as one element breaks
// it. Add a line only for a violation that cannot be fixed in the same change,
// with the reason, and delete it with the fix.
export const BASELINE = {}
