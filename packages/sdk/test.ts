import { CounselClient } from './src/index.js';

async function main() {
  const client = new CounselClient('http://localhost:3000', 'test-api-key');

  const record = await client.attest(
    'agent-abc',
    'acme-corp',
    'data-query',
    { query: 'SELECT * FROM users', rowsReturned: 42 },
  );

  console.log('Attestation record:');
  console.log(JSON.stringify(record, null, 2));
}

main().catch((err) => { console.error(err); process.exit(1); });
