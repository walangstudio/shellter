'use strict';
// A patch blob as the files it writes: [{ file_path, content }], content = the added (`+`) lines.
// One parser for the codex/agy shim and the opencode adapter.
// Headers: `*** Add|Update|Delete File:` (indented or not), the rename target `*** Move to:`, and a
// unified diff's `+++ b/path` right after a `--- a/path` line (a tab starts its timestamp; a git-quoted
// name is decoded as git does, octal bytes included; `+++ /dev/null` deletes the `---` file). Inside a
// `***` file a `--- x` / `+++ y` pair may be a removed and an added line, so there it is read both
// ways: `y` is checked as a file, and the lines after it still count for the `***` file.
const ESC = { a: '\x07', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v' };
function headerName(rest) {
  const q = /^"((?:[^"\\]|\\.)*)"/.exec(rest);
  if (!q) return /^([^\t]*?)\s*(?:\t.*)?$/.exec(rest)[1];
  const bytes = [];
  q[1].replace(/\\([0-7]{1,3})|\\(.)|([^\\]+)/g, (m, oct, c, plain) => {
    if (oct) bytes.push(parseInt(oct, 8) & 0xff);
    else if (c) bytes.push(...Buffer.from(ESC[c] || c));
    else bytes.push(...Buffer.from(plain));
    return '';
  });
  return Buffer.from(bytes).toString('utf8');
}

function patchTargets(text) {
  const out = [];
  let cur = [], prev = '';
  for (const line of String(text).split('\n')) {
    const star = /^\s*\*\*\* (?:(?:Add|Update|Delete) File|Move to):\s*(.+?)\s*$/.exec(line);
    const uni = !star && prev.startsWith('--- ') && line.startsWith('+++ ');
    const from = prev;
    prev = line;
    if (star) {
      const t = { file_path: star[1], content: /Move to:/.test(line) && cur.length ? cur[cur.length - 1].content : '', star: true };
      out.push(t); cur = [t];
      continue;
    }
    if (line.startsWith('+')) for (const t of uni ? cur.filter((x) => x.star) : cur) t.content += line.slice(1) + '\n';
    if (uni) {
      let name = headerName(line.slice(4));
      if (name === '/dev/null') name = headerName(from.slice(4)).replace(/^a\//, '');
      const t = { file_path: name.replace(/^b\//, ''), content: '' };
      out.push(t);
      cur = cur.some((x) => x.star) ? [...cur.filter((x) => x.star), t] : [t];
    }
  }
  return out.map(({ file_path, content }) => ({ file_path, content }));
}

module.exports = { patchTargets };
