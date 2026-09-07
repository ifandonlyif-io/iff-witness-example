import { parseJSONStrict } from '../web/service-receipt.mjs';
import { validAPIKey, parseIFFKeyIDs } from './settings-values.mjs';

const byID = (id) => document.getElementById(id);
let settings = null;
let busy = false;
const updates = typeof BroadcastChannel === 'function' ? new BroadcastChannel('iff-witness-settings') : null;
function setText(id, value) { byID(id).textContent = value; }
function enableForm() {
  const available = settings?.settings_available === true && !busy;
  byID('api-key').disabled = !available;
  byID('save-key').disabled = !available;
  byID('clear-key').disabled = !available || !settings.compute_configured;
  byID('iff-key-ids').disabled = !available;
  byID('save-iff-keys').disabled = !available;
  byID('clear-iff-keys').disabled = !available || !settings.iff_key_ids?.length;
}
function showError(message) { setText('settings-error', message); byID('settings-error').hidden = false; }
function render(hydratePins = false) {
  setText('key-state', settings.compute_configured ? '已設定 · 尚未驗證額度' : '尚未設定');
  const pins = settings.iff_key_ids ?? [];
  setText('iff-key-state', pins.length ? `已指定 ${pins.length} 筆 · 仍需核對收據` : '未指定 · 不影響 0G 啟用');
  if (hydratePins) byID('iff-key-ids').value = pins.join('\n');
  setText('example-state', settings.example_configured ? 'IFF 範例已備妥' : '尚未設定範例');
  setText('settings-model', settings.model ?? '—');
  setText('settings-budget', `${settings.remaining_live_checks} / ${settings.max_live_checks} 次`);
  enableForm();
}
async function request(options = {}) {
  const response = await fetch('/api/settings', {credentials:'same-origin',redirect:'error',cache:'no-store',signal:AbortSignal.timeout(10000),...options});
  const raw = await response.text();
  if (raw.length > 16384) throw new Error('設定回應異常，請重新整理。');
  let data;
  try { data = parseJSONStrict(raw).value; } catch { throw new Error('無法讀取設定，請確認服務已更新並重新啟動。'); }
  if (!response.ok) {
    const code = data.code ?? data.error;
    // Never render server-controlled error text in a credential form.
    if (response.status === 403 || code === 'settings_unavailable') throw new Error('設定只開放本機直接連線。請從這台電腦的 127.0.0.1 或 localhost 開啟，公開部署請使用服務的環境設定。');
    if (response.status === 400 || response.status === 413) throw new Error('設定格式不正確。請依欄位說明檢查格式與長度後再試。');
    throw new Error('設定未能完成，請重新整理後再試。');
  }
  return data;
}
async function save(clear = false) {
  byID('settings-error').hidden = true; setText('settings-message','');
  const input = byID('api-key');
  // Read only for this request, then clear the field even if the request fails.
  let key = clear ? '' : input.value.trim();
  input.value = '';
  if (!clear && !validAPIKey(key)) {
    key = ''; showError('請貼上單行金鑰，不含空白或換行。'); input.focus(); return;
  }
  busy = true; enableForm(); setText('settings-message', clear ? '正在清除…' : '正在儲存…');
  try {
    const pending = request({method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({api_key:key})});
    key = '';
    settings = await pending;
    updates?.postMessage('changed'); // Only a notification; never the key or settings data.
    render();
    setText('settings-message',clear ? '本次金鑰已清除。新的查核不會使用已清除的金鑰。' : settings.example_configured ? '已儲存。切回 Demo 即可選擇真實模式；尚未發送推理或檢查額度。' : '金鑰已儲存；仍需設定 IFF 範例，才能啟用真實模式。');
  } catch(error) {
    setText('settings-message',''); showError(error.name === 'TimeoutError' ? '尚未確認是否儲存成功。請重新整理查看金鑰狀態。' : error instanceof TypeError ? '無法連上本機服務，請確認 Demo 仍在執行。' : error.message);
  } finally { key=''; busy=false; input.value=''; enableForm(); }
}
async function saveIFFKeys(clear = false) {
  byID('settings-error').hidden = true; setText('iff-settings-message', '');
  let ids;
  try { ids = clear ? [] : parseIFFKeyIDs(byID('iff-key-ids').value); }
  catch (error) { showError(error.message); byID('iff-key-ids').focus(); return; }
  busy = true; enableForm(); setText('iff-settings-message', clear ? '正在清除…' : '正在儲存…');
  try {
    // Omit api_key entirely: editing public policy must never clear/replace a secret.
    settings = await request({method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({iff_key_ids:ids})});
    updates?.postMessage('changed');
    render(true);
    setText('iff-settings-message', settings.iff_key_ids.length ? '驗證指紋已儲存。切回 Demo 會重新核對現有證據，不會再次呼叫 0G。' : '驗證指紋已清除。瀏覽器不再獨立信任真實 IFF 簽署者；0G 金鑰沒有改動。');
  } catch (error) {
    setText('iff-settings-message', '');
    showError(error.name === 'TimeoutError' ? '尚未確認是否儲存成功。請重新整理查看驗證指紋。' : error instanceof TypeError ? '無法連上本機服務，請確認 Demo 仍在執行。' : error.message);
  } finally { busy = false; enableForm(); }
}
byID('settings-form').addEventListener('submit',event=>{event.preventDefault(); if(!busy)void save();});
byID('clear-key').addEventListener('click',()=>{if(!busy)void save(true);});
byID('iff-settings-form').addEventListener('submit',event=>{event.preventDefault(); if(!busy)void saveIFFKeys();});
byID('clear-iff-keys').addEventListener('click',()=>{if(!busy)void saveIFFKeys(true);});
window.addEventListener('pagehide',()=>{byID('api-key').value='';});

try { settings=await request(); render(true); }
catch(error) { setText('key-state','無法讀取'); showError(error instanceof TypeError ? '無法連上本機服務，請確認 Demo 仍在執行。' : error.message); enableForm(); }
