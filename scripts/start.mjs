import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const child = spawn('go', ['run', './cmd/witness'], {
  cwd: fileURLToPath(new URL('../', import.meta.url)), stdio: 'inherit', env: process.env,
});
for (const signal of ['SIGINT','SIGTERM']) process.on(signal, () => child.kill(signal));
child.on('error', () => { console.error('Unable to start Witness. Install the Go version specified by the root go.mod.'); process.exitCode=1; });
child.on('exit', (code) => { process.exitCode=code ?? 1; });
