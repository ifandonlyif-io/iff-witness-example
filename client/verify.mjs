import { verifyMessage } from "ethers";
import { parseJSONStrict, verifyServiceReceipt, REQUEST_HASH_DOMAIN } from "../web/service-receipt.mjs";

const DIGEST = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const encoder = new TextEncoder();

export async function sha256Text(text) {
    const hash = await globalThis.crypto.subtle.digest("SHA-256", encoder.encode(text));
    return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function json(value) {
    return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4,"0")}`);
}

// C1's published IFF fingerprint algorithm. The Labs UI restricts this local
// implementation to ASCII fields; unknown normalization cases fail closed.
// Transport fields (timeout, resource metadata, extra) are NOT in C1's scope.
export async function requestProjection(request) {
    const url = request?.url;
    const payment = request?.payment_required;
    if (typeof url !== "string" || !/^https:\/\/[\x21-\x7e]+$/.test(url)) throw new Error("需要標準的 HTTPS endpoint 網址。");
    const parsed = new URL(url);
    if (parsed.username || parsed.password || parsed.search || parsed.hash || (parsed.port && parsed.port!=="443")) throw new Error("Endpoint 網址包含不支援的組成部分。");
    if (payment?.x402Version!==2 || !Array.isArray(payment.accepts) || payment.accepts.length===0 || payment.accepts.length>128) throw new Error("需要範圍受限的 x402 v2 accepts 陣列。");
    const optionHashes=[];
    for (const option of payment.accepts) {
        for (const field of ["scheme","network","asset","payTo","amount"]) {
            if (typeof option?.[field]!=="string" || !/^[\x20-\x7e]+$/.test(option[field])) throw new Error("此驗證器僅支援 ASCII 字元的 x402 付款欄位。");
        }
        if (!/^[0-9]+$/.test(option.amount.trim()) || BigInt(option.amount.trim())<=0n) throw new Error("付款金額不是正整數十進位數字。");
        const normalizeAddress=(value)=>ADDRESS.test(value.trim()) ? value.trim().toLowerCase() : value.trim();
        const canonical=JSON.stringify({scheme:option.scheme.trim().toLowerCase(),network:option.network.trim().toLowerCase(),asset:normalizeAddress(option.asset),pay_to:normalizeAddress(option.payTo),amount:option.amount.trim().replace(/^0+/,"")||"0"});
        optionHashes.push(await sha256Text("iff-x402-option/v1\n"+canonical));
    }
    const optionFingerprints=[...new Set(optionHashes)].sort();
    const setFingerprint=await sha256Text("iff-x402-set/v1\n"+optionFingerprints.join("\n"));
    return json({url,received:{set_fingerprint:setFingerprint,option_fingerprints:optionFingerprints}});
}

function shape(value) { return value && typeof value==="object" && !Array.isArray(value); }
function sameAddress(a,b) { return typeof a==="string" && typeof b==="string" && ADDRESS.test(a) && ADDRESS.test(b) && a.toLowerCase()===b.toLowerCase(); }

// Trust options come from the caller's policy or a separately authenticated
// lookup. A key directory, nonce, signer address, or status inside an uploaded
// file cannot promote itself to a trusted policy.
export async function verifyBundle(input, options={}) {
    const checks=[];
    const check=(id,status,label,detail)=>checks.push({id,status,label,detail});
    let bundle;
    try {
        const text=typeof input==="string" ? input : JSON.stringify(input);
        if (encoder.encode(text).length>2*1024*1024) throw new Error("Bundle exceeds 2 MiB.");
        bundle=parseJSONStrict(text).value;
        if (!shape(bundle) || bundle.schema!=="iff-witness/bundle/v1" || !shape(bundle.iff) || !shape(bundle.request) || !shape(bundle.compute) || !shape(bundle.explanation)) throw new Error("Unsupported Witness bundle shape.");
    } catch (error) {
        check("bundle","fail","證據包格式",error.message);
        return {checks,tampered:true,iffResult:null};
    }

    let iffResult=null;
    try {
        if (typeof bundle.iff.response!=="string") throw new Error("IFF response must retain its raw JSON text.");
        iffResult=await verifyServiceReceipt(bundle.iff.response,{expectedIssuer:options.expectedIssuer,trustedKeyIDs:options.trustedKeyIDs,now:options.now});
        check("iff_signature","pass","IFF 收據簽章",`${iffResult.algorithm} 簽章（Service Receipt v${iffResult.version}）與已簽署的內容／主體雜湊相符。這是來源證明，不是安全認證。`);
        const localIssuer=/^http:\/\/(localhost|127\.|\[::1\])/.test(iffResult.payload.issuer) || new URL(iffResult.payload.issuer).hostname.endsWith(".example");
        check("iff_issuer",iffResult.issuerTrusted ? (localIssuer?"warning":"pass") : "unverified",localIssuer?"本機演練金鑰":"IFF 發行者",iffResult.issuerTrusted ? `已比對呼叫端提供的發行者／金鑰政策：${iffResult.payload.issuer}${localIssuer?"。本機演練簽章，非正式 IFF 正式收據。":"。"}` : "沒有比對到任何獨立信任的發行者／金鑰政策。內嵌金鑰與證據包內附的目錄都不能作為信任錨點。");
        check("iff_time",!iffResult.expired && !iffResult.notYetValid?"pass":"warning","收據有效時間",iffResult.expired?"簽章仍屬歷史有效，但收據已過期；不足以支持新的動作。":iffResult.notYetValid?"收據的簽發時間在未來；不足以支持這次動作。":"收據仍在簽署的有效時間窗內。");
        check("iff_outer",iffResult.subjectMatchesOuter===true?"pass":"fail","顯示結果與簽署內容",iffResult.subjectMatchesOuter===true?"顯示的完整 IFF 結果與簽署內容一致。":"顯示的 IFF 結果與簽署內容不一致。");
        const submittedNonce=bundle.request.receipt?.nonce;
        const nonceBound=typeof submittedNonce==="string" && submittedNonce.length>0 && submittedNonce===iffResult.payload.nonce;
        const externalNonce=typeof options.expectedNonce==="string" && options.expectedNonce.length>0;
        const nonceMatches=nonceBound && (!externalNonce || options.expectedNonce===submittedNonce);
        check("iff_nonce",nonceMatches ? (externalNonce?"pass":"warning") : "fail","請求 nonce",!nonceMatches?"簽署的 nonce 與送出或另行預期的 nonce 不符。":externalNonce?"簽署的 nonce 與呼叫端這次請求相符。":"nonce 僅與內附的請求相符。未提供獨立預期的 nonce，無法排除重送攻擊。");
        try {
            const projection=await requestProjection(bundle.request);
            const hash=await sha256Text(REQUEST_HASH_DOMAIN+projection);
            const matches=iffResult.payload.service==="x402-requirement-verification" && projection===bundle.iff.request_projection && hash===iffResult.payload.request_sha256;
            check("iff_request",matches?"pass":"fail","付款要求指紋綁定",matches?"重新計算的 URL ＋ C1 付款指紋與簽署的請求摘要相符。C1 綁定 scheme、network、asset、payTo 與 amount；不含 timeout／resource／extra 欄位。":"重新計算的付款指紋、URL 或服務類型與簽署的請求承諾不符。");
        } catch (error) { check("iff_request","fail","付款要求指紋綁定",error.message); }
    } catch (error) {
        check("iff_signature","fail","IFF 收據簽章",error.message);
    }

    const compute=bundle.compute;
    const proof=compute.proof;
    if (typeof compute.request_json==="string" && compute.request_json!=="") {
        try {
            const request=parseJSONStrict(compute.request_json).value;
            const userMessages=Array.isArray(request.messages)?request.messages.filter((message)=>message.role==="user"):[];
            const matches=iffResult!==null && userMessages.length===1 && userMessages[0].content===iffResult.subjectText;
            check("compute_evidence",matches?"pass":"fail","模型輸入與 IFF 證據",matches?"保留的模型請求中，唯一的 user 訊息就是已驗證的 IFF 簽署內容原文。供應商是否簽署這些位元組另行核對。":"保留的模型輸入內容，與簽署的 IFF 內容原文不符。");
            check("compute_model",request.model===compute.model?"pass":"fail","模型名稱核對",request.model===compute.model?"顯示的模型名稱與保留的請求相符。這只是請求內容一致，不代表證明模型確實執行。":"顯示的模型名稱與保留的請求不符。");
        } catch { check("compute_evidence","fail","模型輸入與 IFF 證據","保留的模型請求不是嚴格格式的 JSON。"); }
    }
    if (bundle.explanation.source!=="0g") {
        check("compute_router","unverified","0G 請求","此證據包為明確標示的本機演練解說；未宣稱任何 0G 請求或證明。");
    } else {
        let trace;
        try { trace=parseJSONStrict(compute.response_json).value?.x_0g_trace; } catch { /* Missing trace remains unverified. */ }
        check("compute_router",trace?.tee_verified===false?"fail":trace?.tee_verified===true?"warning":"unverified","Router 回報",trace?.tee_verified===true?"Router 回報 tee_verified=true。這是未簽署的中繼資料，不是獨立證明。":trace?.tee_verified===false?"Router 回報供應商驗證失敗。":"Router 的驗證中繼資料缺漏或無法取得。");
    }

    let outputMatches=false;
    if (typeof compute.response_json==="string" && compute.response_json!=="") {
        try {
            const response=parseJSONStrict(compute.response_json).value;
            outputMatches=response.choices?.length===1 && typeof bundle.explanation.text==="string" && response.choices[0]?.message?.content===bundle.explanation.text;
            check("compute_display",outputMatches?"pass":"fail","解說與回應原文",outputMatches?"顯示的解說與保留的回應原文相符。此一致性檢查本身不是密碼學證明。":"顯示的解說與保留的回應原文不符。");
        } catch { check("compute_display","fail","解說與回應原文","保留的 0G 回應不是嚴格格式的 JSON。"); }
    }

    if (!shape(proof) || typeof proof.text!=="string" || !proof.text || typeof proof.signature!=="string" || !proof.signature) {
        for (const [id,label] of [["compute_signature","0G 原始簽章"],["compute_identity","0G 簽署者身份"],["compute_content","0G 輸入／輸出綁定"]]) check(id,"unverified",label,"沒有可供獨立驗證的原始供應商簽章。未宣稱任何密碼學層級的解說綁定。");
    } else {
        let recovered="";
        try {
            recovered=verifyMessage(proof.text,proof.signature);
            const signatureMatches=sameAddress(recovered,proof.signer_address);
            check("compute_signature",signatureMatches?"pass":"fail","0G 原始簽章",signatureMatches?"EIP-191 簽章復原出的簽署者與聲明相符。身份另行核對。":"簽章復原出的簽署者與隨附證明所聲明的不同。");
        } catch { check("compute_signature","fail","0G 原始簽章","EIP-191 簽章格式錯誤或無效。"); }
        const provider=typeof proof.provider==="string"?proof.provider.toLowerCase():"";
        const trust=options.trustedComputeSigners;
        const expected=shape(trust) && Object.prototype.hasOwnProperty.call(trust,provider)?trust[provider]:null;
        const trusted=typeof expected==="string" ? expected : expected?.signer;
        check("compute_identity",trusted ? (sameAddress(recovered,trusted)?"pass":"fail") : "unverified","0G 簽署者身份",trusted ? "復原出的簽署者已比對另行提供的供應商對簽署者政策。未核對硬體認證。" : "未提供獨立的供應商對簽署者釘選值。內附的登記快照與伺服器狀態欄位僅供參考。");
        const parts=proof.text.split(":");
        const supported=parts.length===2 || (parts.length===5 && parts[2]==="centralized" && parts[3]!=="" && DIGEST.test(parts[4]));
        if (!supported || !DIGEST.test(parts[0]) || !DIGEST.test(parts[1])) {
            check("compute_content","unverified","0G 輸入／輸出綁定","不支援的簽署格式。即使簽章有效，也不代表這段解說內容確實被簽署過。");
        } else if (typeof compute.request_json!=="string" || typeof compute.response_json!=="string") {
            check("compute_content","unverified","0G 輸入／輸出綁定","缺少供應商請求／回應的原始位元組。");
        } else {
            const requestBound=await sha256Text(compute.request_json)===parts[0];
            const responseBound=await sha256Text(compute.response_json)===parts[1];
            const matches=requestBound && responseBound && outputMatches;
            check("compute_content",matches?"pass":"unverified","0G 輸入／輸出綁定",matches?"重新計算的請求／回應 SHA-256 雜湊與簽署聲明相符，顯示的輸出也與該回應一致。這不代表模型的回答內容正確。":"簽署的雜湊與保留的原始位元組不符。可能因 Router 轉換或內容變更而無法獨立綁定；請勿將此解說視為已驗證。");
        }
    }
    check("agent_identity","unverified","Agentic ID","尚未附上 Agentic ID／X-Agent-Proof 服務證明。");
    return {checks,tampered:checks.some(({status})=>status==="fail"),iffResult};
}

// A genuine negative demonstration even when no 0G credentials are configured:
// alter only the visible IFF verdict, retaining the original signed subject.
export function tamperBundle(bundle) {
    const copy=structuredClone(bundle);
    const outer=parseJSONStrict(copy.iff.response).value;
    if (!["consistent","diverged","stale","unobserved"].includes(outer.verdict)) throw new Error("Bundle does not contain a supported IFF verdict.");
    const changed=outer.verdict==="consistent"?"diverged":"consistent";
    // Production's fixed response shape has exactly one verdict field. Keep
    // every other byte, including large integer tokens, untouched.
    copy.iff.response=copy.iff.response.replace(/("verdict"\s*:\s*")(consistent|diverged|unobserved|stale)(")/,(_,before,_value,after)=>before+changed+after);
    return copy;
}
