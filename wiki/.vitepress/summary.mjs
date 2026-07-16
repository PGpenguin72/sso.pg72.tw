const SUMMARY_LINK = /^\s*[*-]\s+\[([^\]]+)]\(([^)]+)\)\s*$/;

export function parseSummary(markdown) {
  const sections = [];
  let current = { text: null, items: [] };

  for (const [index, rawLine] of markdown.split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!line || /^#\s+/.test(line)) continue;

    const heading = line.match(/^##\s+(.+)$/);
    if (heading) {
      if (current.items.length > 0) sections.push(current);
      current = { text: heading[1].trim(), items: [] };
      continue;
    }

    const link = rawLine.match(SUMMARY_LINK);
    if (!link) {
      throw new Error(`Unsupported SUMMARY.md line ${index + 1}: ${rawLine}`);
    }

    const [, text, sourcePath] = link;
    if (
      !sourcePath.endsWith(".md") ||
      sourcePath.startsWith("/") ||
      sourcePath.includes("\\") ||
      sourcePath.split("/").includes("..")
    ) {
      throw new Error(`Unsafe SUMMARY.md target on line ${index + 1}: ${sourcePath}`);
    }

    current.items.push({ text: text.trim(), sourcePath });
  }

  if (current.items.length > 0) sections.push(current);
  if (sections.length === 0) throw new Error("SUMMARY.md contains no pages");

  const allItems = sections.flatMap((section) => section.items);
  const seen = new Set();
  for (const item of allItems) {
    if (seen.has(item.sourcePath)) {
      throw new Error(`Duplicate SUMMARY.md target: ${item.sourcePath}`);
    }
    seen.add(item.sourcePath);
  }

  return sections;
}

export function sourcePathToRoute(sourcePath) {
  if (sourcePath === "README.md" || sourcePath === "index.md") return "/";
  return `/${sourcePath.replace(/\.md$/, "")}`;
}

function navItem(item) {
  return { text: item.text, link: sourcePathToRoute(item.sourcePath) };
}

export function createNavigation(sections) {
  const sidebar = [];
  const nav = [];

  for (const section of sections) {
    const items = section.items.map(navItem);
    if (section.text === null) {
      sidebar.push(...items);
      nav.push(...items);
      continue;
    }

    sidebar.push({ text: section.text, items });
    nav.push({ text: section.text, items });
  }

  return { nav, sidebar };
}

export function createLlmsText({ title, description, siteUrl }, sections) {
  const lines = [`# ${title}`, "", `> ${description}`, ""];

  for (const section of sections) {
    if (section.text) lines.push(`## ${section.text}`, "");
    for (const item of section.items) {
      const url = new URL(sourcePathToRoute(item.sourcePath), siteUrl);
      lines.push(`- [${item.text}](${url.href})`);
    }
    lines.push("");
  }

  return `${lines.join("\n").trim()}\n`;
}
