// The app's one icon set. Every icon is drawn on a 16x16 grid as open paths,
// rendered by components/Icon.jsx with one stroke (1.5), no fill, in the
// colour of the text around it. Hand-drawn for this app: no icon font, no
// dependency, no emoji (a glyph or an emoji is drawn by whatever font the
// reader's system has, so two neighbours never match).
//
// Which controls take an icon:
//   - a button with no room for a word (history row, sidebar header, phone
//     top bar, the search field's shortcuts): the icon alone, and the button
//     carries an aria-label;
//   - next to a label, only where the action leaves the page or cannot be
//     undone, or to tell apart two neighbours that both say a format name:
//     copy to the clipboard (copy), save a file (download), pick a file
//     (upload), open another site or program (external), add (plus),
//     delete (trash), dismiss (close);
//   - a toggle shows its state as a box, empty or ticked (box / boxChecked),
//     so "on" is never said by colour alone and its label never changes.
// Every other button is its label and nothing else: no arrow after a verb.
export const ICONS = {
  copy: [
    'M6.5 5.5h6a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1h-6a1 1 0 0 1-1-1v-6a1 1 0 0 1 1-1z',
    'M10.5 5.5v-2a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2',
  ],
  download: ['M8 2.5v8.5', 'M4.5 7.5 8 11l3.5-3.5', 'M2.5 13.5h11'],
  upload: ['M8 11V2.5', 'M4.5 6 8 2.5 11.5 6', 'M2.5 13.5h11'],
  external: [
    'M9.5 2.5h4v4',
    'M13.5 2.5 7.5 8.5',
    'M11.5 9.5v3a1 1 0 0 1-1 1h-7a1 1 0 0 1-1-1v-7a1 1 0 0 1 1-1h3',
  ],
  plus: ['M8 3v10', 'M3 8h10'],
  trash: [
    'M2.5 4.5h11',
    'M6 4.5v-1a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v1',
    'M4 4.5l.6 8.1a1 1 0 0 0 1 .9h4.8a1 1 0 0 0 1-.9l.6-8.1',
    'M6.75 7.5V11',
    'M9.25 7.5V11',
  ],
  close: ['M4 4l8 8', 'M12 4l-8 8'],
  check: ['M3 8.5 6.5 12 13 4.5'],
  box: ['M4 2.5h8A1.5 1.5 0 0 1 13.5 4v8a1.5 1.5 0 0 1-1.5 1.5H4A1.5 1.5 0 0 1 2.5 12V4A1.5 1.5 0 0 1 4 2.5z'],
  boxChecked: [
    'M4 2.5h8A1.5 1.5 0 0 1 13.5 4v8a1.5 1.5 0 0 1-1.5 1.5H4A1.5 1.5 0 0 1 2.5 12V4A1.5 1.5 0 0 1 4 2.5z',
    'M5.25 8.25 7.25 10.25 10.75 5.75',
  ],
  stop: ['M4.5 4.5h7v7h-7z'],
  play: ['M5.5 3.5v9l7-4.5z'],
  edit: ['M10.5 3 13 5.5 5.5 13H3v-2.5z', 'M9 4.5 11.5 7'],
  rerun: ['M13 8a5 5 0 1 1-5-5 5 5 0 0 1 3.5 1.45L13 6', 'M13 3v3h-3'],
  merge: ['M2.5 4h3l4 4h4', 'M2.5 12h3l4-4', 'M11.5 6l2 2-2 2'],
  sun: [
    'M8 5.25a2.75 2.75 0 1 0 0 5.5 2.75 2.75 0 0 0 0-5.5z',
    'M8 1.5V3', 'M8 13v1.5', 'M1.5 8H3', 'M13 8h1.5',
    'M3.4 3.4l1.1 1.1', 'M11.5 11.5l1.1 1.1', 'M3.4 12.6l1.1-1.1', 'M11.5 4.5l1.1-1.1',
  ],
  moon: ['M13.5 9.5A5.75 5.75 0 0 1 6.5 2.5a5.75 5.75 0 1 0 7 7z'],
  settings: [
    'M2.5 5h5.5', 'M11 5h2.5', 'M2.5 11h2.5', 'M8 11h5.5',
    'M9.5 3.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3z',
    'M6.5 9.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3z',
  ],
  logout: [
    'M6.5 2.5h-3a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h3',
    'M10.5 5l3 3-3 3',
    'M13.5 8h-7',
  ],
  menu: ['M2.5 4h11', 'M2.5 8h11', 'M2.5 12h11'],
  panel: [
    'M3.5 2.5h9a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1v-9a1 1 0 0 1 1-1z',
    'M9.5 2.5v11',
  ],
  next: ['M4 6l4 4 4-4'],
}

export const ICON_NAMES = Object.keys(ICONS)
