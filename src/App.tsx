import React, { useState } from 'react';
import { Lock, Unlock, Copy, Check, AlertCircle, ShieldCheck } from 'lucide-react';

const DEFAULT_AES_KEY = "1uNgm/8Z8BcSxdMRi29VwjVExZMPQfp4HwRbfsqjYXY=";
const IV_SIZE = 12;
const TAG_SIZE = 16;

export default function App() {
  // Key Management State
  const [aesKey, setAesKey] = useState(() => {
    return localStorage.getItem('aes_key') || DEFAULT_AES_KEY;
  });

  // Encryption State
  const [encryptInput, setEncryptInput] = useState('');
  const [encryptOutput, setEncryptOutput] = useState('');
  const [encryptError, setEncryptError] = useState('');
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [encryptCopied, setEncryptCopied] = useState(false);

  // Decryption State
  const [decryptInput, setDecryptInput] = useState('');
  const [decryptOutput, setDecryptOutput] = useState('');
  const [decryptError, setDecryptError] = useState('');
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decryptCopied, setDecryptCopied] = useState(false);

  // Sync key to localStorage
  React.useEffect(() => {
    localStorage.setItem('aes_key', aesKey);
  }, [aesKey]);

  const toArrayBuffer = (u8: Uint8Array): ArrayBuffer => {
    return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
  };

  const base64ToBytes = (b64: string): Uint8Array => {
    const sanitized = b64.replace(/\s/g, '');
    const bin = atob(sanitized);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  };

  const bytesToBase64 = (bytes: Uint8Array): string => {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  };

  const getAesKey = async (usage: "encrypt" | "decrypt") => {
    const rawKeyU8 = base64ToBytes(aesKey);
    return await window.crypto.subtle.importKey(
      "raw",
      toArrayBuffer(rawKeyU8),
      { name: "AES-GCM" },
      false,
      [usage]
    );
  };

  const handleEncrypt = async () => {
    if (!encryptInput.trim()) {
      setEncryptError('Please enter text to encrypt.');
      return;
    }

    setIsEncrypting(true);
    setEncryptError('');
    setEncryptOutput('');

    try {
      const key = await getAesKey("encrypt");
      const ivU8 = window.crypto.getRandomValues(new Uint8Array(IV_SIZE));
      const ptU8 = new TextEncoder().encode(encryptInput);

      // WebCrypto returns ciphertext||tag (tag appended at end)
      const ctWithTagBuf = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: ivU8, tagLength: TAG_SIZE * 8 },
        key,
        toArrayBuffer(ptU8)
      );

      const ctWithTag = new Uint8Array(ctWithTagBuf);
      const ciphertext = ctWithTag.slice(0, ctWithTag.length - TAG_SIZE);
      const tag = ctWithTag.slice(ctWithTag.length - TAG_SIZE);

      // .NET layout: iv + tag + ciphertext
      const out = new Uint8Array(IV_SIZE + TAG_SIZE + ciphertext.length);
      out.set(ivU8, 0);
      out.set(tag, IV_SIZE);
      out.set(ciphertext, IV_SIZE + TAG_SIZE);

      setEncryptOutput(bytesToBase64(out));
    } catch (err) {
      console.error(err);
      setEncryptError('Encryption failed.');
    } finally {
      setIsEncrypting(false);
    }
  };

  const handleDecrypt = async () => {
    if (!decryptInput.trim()) {
      setDecryptError('Please enter encrypted data.');
      return;
    }

    setIsDecrypting(true);
    setDecryptError('');
    setDecryptOutput('');

    try {
      const key = await getAesKey("decrypt");
      const full = base64ToBytes(decryptInput.trim());
      
      if (full.length < IV_SIZE + TAG_SIZE + 1) {
        throw new Error("Payload too short.");
      }

      const iv = full.slice(0, IV_SIZE);
      const tag = full.slice(IV_SIZE, IV_SIZE + TAG_SIZE);
      const ciphertext = full.slice(IV_SIZE + TAG_SIZE);

      // WebCrypto expects: ciphertext + tag
      const ctWithTag = new Uint8Array(ciphertext.length + TAG_SIZE);
      ctWithTag.set(ciphertext, 0);
      ctWithTag.set(tag, ciphertext.length);

      const plainBuf = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv, tagLength: TAG_SIZE * 8 },
        key,
        toArrayBuffer(ctWithTag) 
      );

      const decodedText = new TextDecoder().decode(new Uint8Array(plainBuf));
      
      try {
        const json = JSON.parse(decodedText);
        setDecryptOutput(JSON.stringify(json, null, 2));
      } catch (e) {
        setDecryptOutput(decodedText);
      }
    } catch (err) {
      console.error(err);
      setDecryptError('Decryption failed. Check layout or key.');
    } finally {
      setIsDecrypting(false);
    }
  };

  const copyToClipboard = (text: string, setCopied: (v: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[#f8f9fa] flex items-center justify-center p-6 font-sans">
      <div className="w-full max-w-6xl space-y-6">
        {/* Global Header */}
        <div className="flex flex-col items-center text-center space-y-2 mb-4">
          <div className="p-3 bg-black rounded-2xl shadow-lg">
            <ShieldCheck className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-gray-900">AES-GCM Tool</h1>
          <p className="text-gray-500 max-w-md">
            Secure client-side encryption and decryption.
          </p>
        </div>

        {/* Key Configuration Section */}
        <div className="bg-white rounded-3xl shadow-sm border border-black/5 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-gray-400" />
              <h2 className="text-sm font-bold uppercase tracking-widest text-gray-500">Master AES Key (Base64)</h2>
            </div>
            <button 
              onClick={() => setAesKey(DEFAULT_AES_KEY)}
              className="text-[10px] font-bold uppercase tracking-widest text-indigo-600 hover:text-indigo-800 transition-colors"
            >
              Reset to Default
            </button>
          </div>
          <div className="relative group">
            <input
              type="text"
              value={aesKey}
              onChange={(e) => setAesKey(e.target.value)}
              className="w-full p-4 bg-gray-50 border border-gray-200 rounded-2xl font-mono text-xs focus:ring-2 focus:ring-indigo-500/10 focus:border-indigo-500 outline-none transition-all pr-12"
              placeholder="Enter your 256-bit AES key in Base64..."
            />
            <div className="absolute right-4 top-1/2 -translate-y-1/2">
              <div className={`w-2 h-2 rounded-full ${aesKey.length === 44 ? 'bg-emerald-500' : 'bg-amber-500'} animate-pulse`} title={aesKey.length === 44 ? 'Valid Key Length' : 'Check Key Length'} />
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* ENCRYPT SECTION (LEFT) */}
          <div className="bg-white rounded-3xl shadow-sm border border-black/5 overflow-hidden flex flex-col h-full">
            <div className="p-6 border-b border-black/5 bg-gray-50/50">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-indigo-600 rounded-lg">
                  <Lock className="w-5 h-5 text-white" />
                </div>
                <h2 className="text-xl font-semibold text-gray-900">Encrypt</h2>
              </div>
            </div>
            
            <div className="p-6 space-y-6 flex-grow">
              <div className="space-y-2">
                <label className="text-xs font-bold uppercase tracking-widest text-gray-400">Plain Text / JSON</label>
                <textarea
                  className="w-full h-40 p-4 bg-gray-50 border border-gray-200 rounded-2xl focus:ring-2 focus:ring-indigo-500/10 focus:border-indigo-500 outline-none transition-all resize-none font-mono text-sm"
                  placeholder="Enter text to encrypt..."
                  value={encryptInput}
                  onChange={(e) => setEncryptInput(e.target.value)}
                />
              </div>

              <button
                onClick={handleEncrypt}
                disabled={isEncrypting}
                className="w-full py-4 bg-indigo-600 text-white rounded-2xl font-semibold hover:bg-indigo-700 active:scale-[0.98] transition-all disabled:bg-gray-100 disabled:text-gray-400 flex items-center justify-center gap-2"
              >
                {isEncrypting ? <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <><Lock className="w-5 h-5" /> Encrypt Now</>}
              </button>

              {encryptError && <div className="p-4 bg-red-50 text-red-600 rounded-2xl text-sm border border-red-100 flex items-center gap-2"><AlertCircle className="w-4 h-4" /> {encryptError}</div>}

              {encryptOutput && (
                <div className="space-y-2 animate-in fade-in slide-in-from-bottom-2">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-bold uppercase tracking-widest text-gray-400">Encrypted Payload (Base64)</label>
                    <button onClick={() => copyToClipboard(encryptOutput, setEncryptCopied)} className="text-xs font-medium text-indigo-600 hover:text-indigo-800 flex items-center gap-1">
                      {encryptCopied ? <><Check className="w-3 h-3" /> Copied</> : <><Copy className="w-3 h-3" /> Copy</>}
                    </button>
                  </div>
                  <div className="w-full p-4 bg-indigo-50/30 border border-indigo-100 rounded-2xl font-mono text-xs text-indigo-900 break-all max-h-40 overflow-y-auto">
                    {encryptOutput}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* DECRYPT SECTION (RIGHT) */}
          <div className="bg-white rounded-3xl shadow-sm border border-black/5 overflow-hidden flex flex-col h-full">
            <div className="p-6 border-b border-black/5 bg-gray-50/50">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-emerald-600 rounded-lg">
                  <Unlock className="w-5 h-5 text-white" />
                </div>
                <h2 className="text-xl font-semibold text-gray-900">Decrypt</h2>
              </div>
            </div>

            <div className="p-6 space-y-6 flex-grow">
              <div className="space-y-2">
                <label className="text-xs font-bold uppercase tracking-widest text-gray-400">Encrypted Payload (Base64)</label>
                <textarea
                  className="w-full h-40 p-4 bg-gray-50 border border-gray-200 rounded-2xl focus:ring-2 focus:ring-emerald-500/10 focus:border-emerald-500 outline-none transition-all resize-none font-mono text-sm"
                  placeholder="Paste base64 encrypted string..."
                  value={decryptInput}
                  onChange={(e) => setDecryptInput(e.target.value)}
                />
              </div>

              <button
                onClick={handleDecrypt}
                disabled={isDecrypting}
                className="w-full py-4 bg-emerald-600 text-white rounded-2xl font-semibold hover:bg-emerald-700 active:scale-[0.98] transition-all disabled:bg-gray-100 disabled:text-gray-400 flex items-center justify-center gap-2"
              >
                {isDecrypting ? <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <><Unlock className="w-5 h-5" /> Decrypt Now</>}
              </button>

              {decryptError && <div className="p-4 bg-red-50 text-red-600 rounded-2xl text-sm border border-red-100 flex items-center gap-2"><AlertCircle className="w-4 h-4" /> {decryptError}</div>}

              {decryptOutput && (
                <div className="space-y-2 animate-in fade-in slide-in-from-bottom-2">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-bold uppercase tracking-widest text-gray-400">Decrypted Result</label>
                    <button onClick={() => copyToClipboard(decryptOutput, setDecryptCopied)} className="text-xs font-medium text-emerald-600 hover:text-emerald-800 flex items-center gap-1">
                      {decryptCopied ? <><Check className="w-3 h-3" /> Copied</> : <><Copy className="w-3 h-3" /> Copy</>}
                    </button>
                  </div>
                  <div className="w-full p-4 bg-emerald-50/30 border border-emerald-100 rounded-2xl font-mono text-xs text-emerald-900 whitespace-pre-wrap break-all max-h-40 overflow-y-auto">
                    {decryptOutput}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Global Footer */}
        <div className="flex justify-center">
          <div className="bg-white/50 backdrop-blur-sm border border-black/5 rounded-2xl px-6 py-3 flex gap-8 text-[10px] font-bold uppercase tracking-widest text-gray-400">
            <div className="flex flex-col"><span className="text-gray-300">Algorithm</span><span className="text-gray-600">AES-GCM</span></div>
            <div className="flex flex-col"><span className="text-gray-300">Layout</span><span className="text-gray-600">IV(12)+Tag(16)+CT</span></div>
            <div className="flex flex-col"><span className="text-gray-300">Key Size</span><span className="text-gray-600">256-bit</span></div>
          </div>
        </div>
      </div>
    </div>
  );
}
