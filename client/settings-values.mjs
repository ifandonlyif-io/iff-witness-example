// Match the local settings API. Only public fingerprints can be re-displayed.
export function validAPIKey(key) {
  return typeof key === 'string' && key.length > 0 && key.length <= 512 && /^[A-Za-z0-9._~+/-]+=*$/.test(key);
}

export function parseIFFKeyIDs(text) {
  const ids = text.split(/[,\r\n]/).map(value => value.trim()).filter(Boolean);
  if (ids.length > 16) throw new Error('最多可設定 16 筆 IFF 驗證指紋。');
  if (ids.some(id => !/^sha256:[0-9a-f]{64}$/.test(id))) {
    throw new Error('請填入完整公鑰指紋：sha256: 加上 64 個小寫十六進位字元。不要填公鑰原文或私鑰。');
  }
  return [...new Set(ids)];
}
