const p=require('pkijs'), a=require('asn1js'), c=require('node:crypto');
const {verifyTimeStampToken}=require('../dist/timestamp');
p.setEngine('node',c.webcrypto,new p.CryptoEngine({name:'node',crypto:c.webcrypto,subtle:c.webcrypto.subtle}));
const ab=b=>b.buffer.slice(b.byteOffset,b.byteOffset+b.byteLength);
async function fixture(opts={}) {
 const keys=await c.webcrypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
 const rootKeys=await c.webcrypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
 const root=new p.Certificate();root.version=2;root.serialNumber=new a.Integer({value:100});
 const rootName=new p.AttributeTypeAndValue({type:'2.5.4.3',value:new a.Utf8String({value:'Synthetic audit root'})});root.subject.typesAndValues.push(rootName);root.issuer.typesAndValues.push(rootName);root.notBefore.value=new Date('2025-01-01');root.notAfter.value=new Date('2028-01-01');await root.subjectPublicKeyInfo.importKey(rootKeys.publicKey);
 root.extensions=[new p.Extension({extnID:'2.5.29.19',critical:true,extnValue:new p.BasicConstraints({cA:true,pathLenConstraint:0}).toSchema().toBER(false)}),new p.Extension({extnID:'2.5.29.15',critical:true,extnValue:new a.BitString({unusedBits:1,valueHex:new Uint8Array([6]).buffer}).toBER(false)})];await root.sign(rootKeys.privateKey,'SHA-256');
 const cert=new p.Certificate();cert.version=2;cert.serialNumber=new a.Integer({value:1});
 const name=new p.AttributeTypeAndValue({type:'2.5.4.3',value:new a.Utf8String({value:'Synthetic audit TSA'})});cert.issuer.typesAndValues.push(opts.selfSigned?name:rootName);cert.subject.typesAndValues.push(name);
 cert.notBefore.value=new Date('2026-01-01');cert.notAfter.value=new Date(opts.expired?'2026-02-01':'2027-01-01');await cert.subjectPublicKeyInfo.importKey(keys.publicKey);
 const eku=new p.ExtKeyUsage({keyPurposes:opts.badEku?['1.3.6.1.5.5.7.3.1']:['1.3.6.1.5.5.7.3.8']});
 cert.extensions=[new p.Extension({extnID:'2.5.29.37',critical:!opts.noncriticalEku,extnValue:eku.toSchema().toBER(false)})];if(opts.badKu)cert.extensions.push(new p.Extension({extnID:'2.5.29.15',critical:true,extnValue:new a.BitString({unusedBits:2,valueHex:new Uint8Array([4]).buffer}).toBER(false)}));await cert.sign(opts.selfSigned?keys.privateKey:rootKeys.privateKey,'SHA-256');
 const doc=Buffer.from('synthetic audit content');const hash=c.createHash('sha256').update(doc).digest();
 const tst=new p.TSTInfo({version:1,policy:'1.2.3.4',messageImprint:new p.MessageImprint({hashAlgorithm:new p.AlgorithmIdentifier({algorithmId:'2.16.840.1.101.3.4.2.1'}),hashedMessage:new a.OctetString({valueHex:ab(hash)})}),serialNumber:new a.Integer({value:1}),genTime:new Date('2026-10-18T12:00:00Z')});
 const bytes=Buffer.from(tst.toSchema().toBER(false));const certBytes=Buffer.from(cert.toSchema(true).toBER(false));
 const certHash=c.createHash('sha256').update(certBytes).digest();if(opts.badEss)certHash[0]^=1;
 const ess=new a.Sequence({value:[new a.Sequence({value:[new a.Sequence({value:[new a.OctetString({valueHex:ab(certHash)})]})]})]});
 const attrs=[new p.Attribute({type:'1.2.840.113549.1.9.3',values:[new a.ObjectIdentifier({value:'1.2.840.113549.1.9.16.1.4'})]}),new p.Attribute({type:'1.2.840.113549.1.9.4',values:[new a.OctetString({valueHex:ab(c.createHash('sha256').update(bytes).digest())})]}),new p.Attribute({type:'1.2.840.113549.1.9.16.2.47',values:[ess]})];
 const sd=new p.SignedData({version:3,encapContentInfo:new p.EncapsulatedContentInfo({eContentType:'1.2.840.113549.1.9.16.1.4',eContent:new a.OctetString({valueHex:ab(bytes)})}),certificates:opts.selfSigned?[cert]:[cert,root],signerInfos:[new p.SignerInfo({version:1,sid:new p.IssuerAndSerialNumber({issuer:cert.issuer,serialNumber:cert.serialNumber}),signedAttrs:new p.SignedAndUnsignedAttributes({type:0,attributes:attrs})})]});await sd.sign(keys.privateKey,0,'SHA-256');
 const ci=new p.ContentInfo({contentType:'1.2.840.113549.1.7.2',content:sd.toSchema(true)});const token=Buffer.from(ci.toSchema().toBER(false));
 const pem='-----BEGIN CERTIFICATE-----\n'+Buffer.from(root.toSchema(true).toBER(false)).toString('base64')+'\n-----END CERTIFICATE-----\n';return {doc,token,pem};
}
module.exports={fixture};
