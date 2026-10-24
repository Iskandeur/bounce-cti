// Pure helper for the activeInv <-> ?inv=<id> URL sync (App.jsx).
//
// Returns the new query string ('' or '?a=b') the URL should carry, or null
// when it must be left alone. Nothing is rewritten until `hydrated` is true:
// at mount activeInv is still null, and syncing then would delete a deep link
// (?inv=<id>) before the initial investigation list has loaded and read it.
export function nextInvSearch(search, activeInv, hydrated) {
  if (!hydrated) return null
  const sp = new URLSearchParams(search)
  const cur = sp.get('inv') || null
  if (activeInv === cur) return null
  if (activeInv) sp.set('inv', activeInv)
  else sp.delete('inv')
  const qs = sp.toString()
  return qs ? '?' + qs : ''
}
