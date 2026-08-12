export interface PCRDisplayRow {
  key: string;
  label: string;
  value: string;
  collapsed: boolean;
}

/**
 * Sort PCR indexes as numbers and collapse consecutive zero-valued PCRs.
 * Lexicographic sorting puts PCR10 before PCR2, while rendering every unused
 * register separately makes the release-defining PCR0 unnecessarily hard to
 * find in a real Nitro document.
 */
export function buildPCRDisplayRows(pcrs: Record<string, string>): PCRDisplayRow[] {
  const entries = Object.entries(pcrs).sort(([left], [right]) => Number(left) - Number(right));
  const rows: PCRDisplayRow[] = [];

  for (let cursor = 0; cursor < entries.length; ) {
    const [index, value] = entries[cursor];
    if (!isZeroPCR(value)) {
      rows.push({ key: index, label: `PCR${index}`, value, collapsed: false });
      cursor++;
      continue;
    }

    let end = cursor;
    while (
      end + 1 < entries.length &&
      isZeroPCR(entries[end + 1][1]) &&
      Number(entries[end + 1][0]) === Number(entries[end][0]) + 1
    ) {
      end++;
    }

    const startIndex = entries[cursor][0];
    const endIndex = entries[end][0];
    rows.push({
      key: `${startIndex}-${endIndex}`,
      label: cursor === end ? `PCR${startIndex}` : `PCR${startIndex}–${endIndex}`,
      value: "all zero (expected)",
      collapsed: true,
    });
    cursor = end + 1;
  }

  return rows;
}

function isZeroPCR(value: string): boolean {
  return value.length > 0 && /^0+$/.test(value);
}
