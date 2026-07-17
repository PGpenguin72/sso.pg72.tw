export default async function* exactTestReporter(source) {
  for await (const event of source) {
    if (["test:pass", "test:fail", "test:summary"].includes(event.type)) {
      yield `${JSON.stringify(event)}\n`;
    }
  }
}
