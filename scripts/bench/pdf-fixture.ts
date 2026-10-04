// Synthetic PDF builder from the upstream probe fixtures (MIT).
function buildPdf(
  objects: (string | { head: string; stream: Uint8Array })[],
): Uint8Array {
  const encoder = new TextEncoder();
  const parts: Uint8Array[] = [];
  let offset = 0;
  const push = (chunk: string | Uint8Array) => {
    const bytes = typeof chunk === "string" ? encoder.encode(chunk) : chunk;
    parts.push(bytes);
    offset += bytes.length;
  };

  push("%PDF-1.4\n");
  const offsets: number[] = [];
  objects.forEach((object, index) => {
    offsets.push(offset);
    push(`${index + 1} 0 obj\n`);
    if (typeof object === "string") {
      push(`${object}\n`);
    } else {
      push(`<< ${object.head} /Length ${object.stream.length} >>\nstream\n`);
      push(object.stream);
      push("\nendstream\n");
    }
    push("endobj\n");
  });

  const xrefAt = offset;
  let table = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const at of offsets) table += `${String(at).padStart(10, "0")} 00000 n \n`;
  push(table);
  push(
    `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\n` +
      `startxref\n${xrefAt}\n%%EOF\n`,
  );

  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** A PDF whose every page carries a real text layer. */
export function textPdf(pages: string[][]): Uint8Array {
  const encoder = new TextEncoder();
  const objects: (string | { head: string; stream: Uint8Array })[] = [
    "", // 1: catalog, filled in below once the page tree is known
    "", // 2: page tree, likewise
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", // 3
  ];
  const kids: string[] = [];

  for (const lines of pages) {
    let content = "BT /F1 12 Tf 72 720 Td 14 TL\n";
    for (const line of lines) {
      content += `(${line.replace(/([()\\])/g, "\\$1")}) Tj T*\n`;
    }
    content += "ET\n";
    objects.push({ head: "", stream: encoder.encode(content) });
    const contentNumber = objects.length;
    objects.push(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] ` +
        `/Contents ${contentNumber} 0 R ` +
        `/Resources << /Font << /F1 3 0 R >> >> >>`,
    );
    kids.push(`${objects.length} 0 R`);
  }

  objects[0] = "<< /Type /Catalog /Pages 2 0 R >>";
  objects[1] = `<< /Type /Pages /Kids [${kids.join(" ")}] /Count ${pages.length} >>`;
  return buildPdf(objects);
}
