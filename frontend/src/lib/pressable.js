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
