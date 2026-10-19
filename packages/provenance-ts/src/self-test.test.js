const { runSelfTests } = require('../dist/index.js');

describe('Moonglade Provenance Self-Test Suite', () => {
  test('executes all 6 condition suites cleanly and returns passed report', async () => {
    const report = await runSelfTests();
    expect(report.passed).toBe(true);
    expect(report.version).toBe('2.5.0');
    expect(report.conditions.length).toBe(6);
    expect(report.verifiedPackageArtifacts).toBe(0);

    for (const c of report.conditions) {
      expect(c.passed).toBe(true);
      expect(typeof c.durationMs).toBe('number');
    }
  });
});
