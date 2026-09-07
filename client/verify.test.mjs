import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash, sign } from "node:crypto";
import { Wallet } from "ethers";
import { requestProjection, sha256Text, tamperBundle, verifyBundle } from "./verify.mjs";

const schema="https://ifandonlyif.io/schemas/service-receipt-v1.json";
const now=new Date("2026-09-05T02:00:00.000Z");
const digest=(value)=>createHash("sha256").update(value).digest("hex");
const b64=(value)=>Buffer.from(value).toString("base64url");
const check=(result,id)=>result.checks.find((item)=>item.id===id);

// Test-only locally generated identity. It never represents production IFF.
async function fixture() {
    const {privateKey,publicKey}=generateKeyPairSync("ed25519");
    const publicBytes=publicKey.export({type:"spki",format:"der"}).subarray(-32);
    const keyID="sha256:"+digest(publicBytes);
    const request={url:"https://weather.witness.example/forecast",payment_required:{x402Version:2,accepts:[{scheme:"exact",network:"eip155:8453",asset:"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",amount:"1000",payTo:"0x1111111111111111111111111111111111111111",maxTimeoutSeconds:60}]},receipt:{version:"1",nonce:"fixture-request-1"}};
    const projection=await requestProjection(request);
    const subject={url:request.url,verdict:"consistent",received:JSON.parse(projection).received,disclaimer:"Test fixture; not payment safety."};
    const subjectText=JSON.stringify(subject);
    const payload={schema,receipt_id:"sr1_"+b64(Buffer.alloc(18,1)),issuer:"https://witness.example",service:"x402-requirement-verification",issued_at:"2026-09-05T02:00:00.000000Z",expires_at:"2026-09-05T02:05:00.000000Z",nonce:request.receipt.nonce,request_sha256:digest("iff-service-receipt/request/v1\n"+projection),subject_media_type:"application/json",subject_sha256:digest("iff-service-receipt/subject/v1\n"+subjectText),subject:b64(subjectText),evidence:null,compute_proof:null};
    const payloadJSON=JSON.stringify(payload);
    const envelope={schema,payload:b64(payloadJSON),payload_sha256:digest(payloadJSON),signature:{algorithm:"Ed25519",key_id:keyID,public_key:b64(publicBytes),value:b64(sign(null,Buffer.from(digest("iff-service-receipt/v1\n"+payloadJSON),"hex"),privateKey))}};
    const bundle={schema:"iff-witness/bundle/v1",id:"test",created_at:now.toISOString(),mode:"rehearsal",scenario:"consistent",request,iff:{response:JSON.stringify({...subject,service_receipt:envelope}),request_projection:projection,key_directory:{issuer:"https://witness.example",keys:[{key_id:keyID}]}},explanation:{source:"rehearsal",text:"Local rehearsal explanation."},compute:{status:"not_requested"},agent:null};
    return {bundle,options:{expectedIssuer:"https://witness.example",trustedKeyIDs:[keyID],expectedNonce:request.receipt.nonce,now}};
}

test("rehearsal receipt checks cryptographic integrity but remains labelled local",async()=>{
    const {bundle,options}=await fixture();
    const result=await verifyBundle(bundle,options);
    assert.equal(result.tampered,false,JSON.stringify(result.checks));
    for (const id of ["iff_signature","iff_outer","iff_nonce","iff_request"]) assert.equal(check(result,id).status,"pass",id);
    assert.equal(check(result,"iff_issuer").status,"warning");
    assert.equal(check(result,"compute_signature").status,"unverified");
});

test("outer verdict alteration is rejected while original signed subject remains authoritative",async()=>{
    const {bundle,options}=await fixture();
    const result=await verifyBundle(tamperBundle(bundle),options);
    assert.equal(result.tampered,true);
    assert.equal(check(result,"iff_signature").status,"pass");
    assert.equal(check(result,"iff_outer").status,"fail");
    assert.equal(result.iffResult.subject.verdict,"consistent");
});

test("bundled key directory and claimed verified statuses never establish trust",async()=>{
    const {bundle}=await fixture();
    bundle.mode="live";
    bundle.compute.status="independently_verified";
    bundle.iff.verification={signature_valid:true,issuer_trusted:true};
    const result=await verifyBundle(bundle,{now});
    assert.equal(check(result,"iff_issuer").status,"unverified");
    assert.equal(check(result,"compute_signature").status,"unverified");
    assert.equal(check(result,"iff_nonce").status,"warning");
});

test("wrong external nonce, altered payment and substituted request projection fail",async()=>{
    const {bundle,options}=await fixture();
    const replay=await verifyBundle(bundle,{...options,expectedNonce:"different-request"});
    assert.equal(check(replay,"iff_nonce").status,"fail");
    bundle.request.payment_required.accepts[0].amount="9999";
    bundle.iff.request_projection=await requestProjection(bundle.request);
    const result=await verifyBundle(bundle,options);
    assert.equal(check(result,"iff_request").status,"fail");
});

test("expired or future receipt retains historical signature but never reports freshness",async()=>{
    const {bundle,options}=await fixture();
    for (const date of ["2026-09-05T02:05:00Z","2026-09-05T01:59:59Z"]) {
        const result=await verifyBundle(bundle,{...options,now:new Date(date)});
        assert.equal(check(result,"iff_signature").status,"pass");
        assert.equal(check(result,"iff_time").status,"warning");
    }
});

test("modified embedded public key fails signature verification",async()=>{
    const {bundle,options}=await fixture();
    const raw=JSON.parse(bundle.iff.response);
    raw.service_receipt.signature.public_key=b64(Buffer.alloc(32,1));
    bundle.iff.response=JSON.stringify(raw);
    assert.equal(check(await verifyBundle(bundle,options),"iff_signature").status,"fail");
});

test("duplicate JSON and forged outer field are rejected",async()=>{
    const {bundle,options}=await fixture();
    const duplicate=JSON.stringify(bundle).replace('"scenario":"consistent"','"scenario":"diverged","scenario":"consistent"');
    assert.equal(check(await verifyBundle(duplicate,options),"bundle").status,"fail");
    const raw=JSON.parse(bundle.iff.response);raw.status="trusted";
    bundle.iff.response=JSON.stringify(raw);
    assert.equal(check(await verifyBundle(bundle,options),"iff_outer").status,"fail");
});

test("no proof means no claimed cryptographic binding for a local explanation",async()=>{
    const {bundle,options}=await fixture();
    bundle.explanation.text="A different unsigned explanation.";
    const result=await verifyBundle(bundle,options);
    assert.equal(result.tampered,false);
    assert.equal(check(result,"compute_content").status,"unverified");
});

async function computeFixture() {
    const {bundle,options}=await fixture();
    const wallet=Wallet.createRandom();
    const provider="0x1111111111111111111111111111111111111111";
    const subject=Buffer.from(JSON.parse(Buffer.from(JSON.parse(bundle.iff.response).service_receipt.payload,"base64url").toString()).subject,"base64url").toString();
    const requestJSON=JSON.stringify({model:"fixture-model",messages:[{role:"user",content:subject}]});
    const responseJSON=JSON.stringify({choices:[{message:{content:"Signed fixture answer."}}]});
    const text=await sha256Text(requestJSON)+":"+await sha256Text(responseJSON);
    bundle.explanation={source:"0g",text:"Signed fixture answer."};
    bundle.compute={status:"independently_verified",model:"fixture-model",provider,request_json:requestJSON,response_json:responseJSON,proof:{provider,text,signature:await wallet.signMessage(text),signer_address:wallet.address}};
    options.trustedComputeSigners={[provider]:wallet.address};
    return {bundle,options,wallet};
}

test("compute fixture requires signature, separately pinned identity, exact bytes and output",async()=>{
    const {bundle,options}=await computeFixture();
    const result=await verifyBundle(bundle,options);
    for (const id of ["compute_signature","compute_identity","compute_content","compute_display","compute_evidence","compute_model"]) assert.equal(check(result,id).status,"pass",id);
    const noPin=await verifyBundle(bundle,{...options,trustedComputeSigners:{}});
    assert.equal(check(noPin,"compute_identity").status,"unverified");
    const wrongPin=await verifyBundle(bundle,{...options,trustedComputeSigners:{[bundle.compute.provider]:Wallet.createRandom().address}});
    assert.equal(check(wrongPin,"compute_identity").status,"fail");
});

test("changed output and signed-byte changes cannot remain verified",async()=>{
    const {bundle,options}=await computeFixture();
    bundle.explanation.text="Altered answer.";
    assert.equal(check(await verifyBundle(bundle,options),"compute_display").status,"fail");
    const response=JSON.parse(bundle.compute.response_json);
    response.choices[0].message.content=bundle.explanation.text;
    bundle.compute.response_json=JSON.stringify(response);
    assert.equal(check(await verifyBundle(bundle,options),"compute_content").status,"unverified");
    bundle.compute.proof.text=await sha256Text(bundle.compute.request_json)+":"+await sha256Text(bundle.compute.response_json);
    assert.equal(check(await verifyBundle(bundle,options),"compute_signature").status,"fail");
});

test("a signed assistant string is unsupported, not a full request/response proof",async()=>{
    const {bundle,options,wallet}=await computeFixture();
    bundle.compute.proof.text=bundle.explanation.text;
    bundle.compute.proof.signature=await wallet.signMessage(bundle.explanation.text);
    const result=await verifyBundle(bundle,options);
    assert.equal(check(result,"compute_signature").status,"pass");
    assert.equal(check(result,"compute_content").status,"unverified");
});

test("fingerprinting normalizes EVM case and amount and removes duplicate options",async()=>{
    const {bundle}=await fixture();
    const before=await requestProjection(bundle.request);
    const option=bundle.request.payment_required.accepts[0];
    option.amount="0001000";option.asset=option.asset.toLowerCase();
    bundle.request.payment_required.accepts.push({...option});
    assert.equal(await requestProjection(bundle.request),before);
});

test("request fingerprint matches the independently published C1 baseline vector",async()=>{
    // ifandonlyif-io/iff-x402-transparency/spec/testdata/fingerprint_vectors.json:
    // single_option_basic. Expected hashes are not generated by this verifier.
    const request={url:"https://api.example/",payment_required:{x402Version:2,accepts:[{scheme:"exact",network:"eip155:8453",asset:"0xab12cd34ab12cd34ab12cd34ab12cd34ab12cd34",amount:"1000000",payTo:"0xef56ab78ef56ab78ef56ab78ef56ab78ef56ab78",maxTimeoutSeconds:60}]}};
    assert.deepEqual(JSON.parse(await requestProjection(request)).received,{set_fingerprint:"91639af6f1dc968c3506c117712fc7830368e7cad3e2dd7cebe209cbb4f229ea",option_fingerprints:["368387837e4883346a4479ec48d19718b432b70f7185c77b4a2150a07d61c768"]});
});

test("splicing a valid compute proof from another IFF receipt cannot bind the evidence",async()=>{
    const {bundle,options}=await computeFixture();
    const other=await fixture();
    const payload=JSON.parse(Buffer.from(JSON.parse(other.bundle.iff.response).service_receipt.payload,"base64url").toString());
    const otherSubject=Buffer.from(payload.subject,"base64url").toString().replace("Test fixture; not payment safety.","Different IFF evidence.");
    const request=JSON.parse(bundle.compute.request_json);
    request.messages[0].content=otherSubject;
    bundle.compute.request_json=JSON.stringify(request);
    assert.equal(check(await verifyBundle(bundle,options),"compute_evidence").status,"fail");
    bundle.compute.model="forged-model";
    assert.equal(check(await verifyBundle(bundle,options),"compute_model").status,"fail");
});
