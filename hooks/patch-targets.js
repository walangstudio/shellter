'use strict';
// A patch blob as the files it writes: [{ file_path, content }], content = the added (`+`) lines.
// One parser for the codex/agy shim and the opencode adapter.
// Headers: `*** Add|Update|Delete File:` (indented or not) and the rename target `*** Move to:`.
// In a blob with no `*** ` header, a unified diff's `+++ b/path` right after a `--- ` line (a tab
// starts its timestamp); in a `***` blob a `+++` line is added content.
function patchTargets(text) {
  const lines = String(text).split('\n');
  const starBlob = lines.some((l) => /^\s*\*\*\* /.test(l));
  const out = [];
  let cur = null, prev = '';
  for (const line of lines) {
    const h = /^\s*\*\*\* (?:(?:Add|Update|Delete) File|Move to):\s*(.+?)\s*$/.exec(line) ||
      (!starBlob && prev.startsWith('--- ') && /^\+\+\+ (?:b\/)?([^\t]+?)\s*(?:\t.*)?$/.exec(line));
    prev = line;
    if (h) {
      const moved = /Move to:/.test(line) && cur;
      cur = { file_path: h[1], content: moved ? cur.content : '' };
      out.push(cur);
      continue;
    }
    if (cur && line.startsWith('+')) cur.content += line.slice(1) + '\n';
  }
  return out;
}

module.exports = { patchTargets };
