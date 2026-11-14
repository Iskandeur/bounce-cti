// Props that make an element that is not a <button> (a chip in a sentence, a
// row that opens) work as one: reachable with Tab, activated with Enter or
// Space, announced as a button. `undefined` handler: plain element, no props.
export function pressable(onPress) {
  if (!onPress) return {}
  return {
    role: 'button',
    tabIndex: 0,
    onClick: onPress,
    onKeyDown: (e) => {
      if (e.target !== e.currentTarget) return
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        onPress(e)
      }
    },
  }
}

// What a button gets while its action runs: announced as busy, deaf to a
// second press, and not dimmed (a disabled button would hide the line that
// runs under its label). At rest, the press handler. Its label is a
// <BusyLabel> (components/BusyLabel.jsx).
export const busyProps = (busy, onPress) =>
  busy ? { 'aria-busy': true, 'aria-disabled': true } : { onClick: onPress }
