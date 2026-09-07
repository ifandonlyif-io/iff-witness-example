import { readFile } from 'node:fs/promises';
import { verifyBundle } from '../client/verify.mjs';
import { verifyBundleAgent } from '../client/agent-bundle.mjs';
import { parseJSONStrict } from '../web/service-receipt.mjs';
const [, , bundlePath, policyPath] = process.argv;
if (!bundlePath) { console.error('Usage: npm run verify -- bundle.json [trusted-policy.json]'); process.exitCode=2; }
else {
  try {
    const raw=await readFile(bundlePath,'utf8');
    parseJSONStrict(raw); // Syntax errors are invalid input, distinct from failed proof checks.
    const policy=policyPath ? parseJSONStrict(await readFile(policyPath,'utf8')).value : {expectedIssuer:'https://ifandonlyif.io'};
    const result=await verifyBundle(raw,policy);
    result.checks=result.checks.filter(check=>check.id!=='agent_identity');
    result.checks.push(...verifyBundleAgent(raw,policy.agentic ?? {}).checks);
    console.log(JSON.stringify({checks:result.checks},null,2));
    // Zero means no failed checks, NOT that all identities/claims were verified.
    process.exitCode=result.checks.some(check=>check.status==='fail')?1:0;
  }catch(error){console.error(error.message);process.exitCode=2;}
}
