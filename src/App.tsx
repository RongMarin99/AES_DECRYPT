import React, { useState } from 'react';
import { Lock, Unlock, Copy, Check, AlertCircle } from 'lucide-react';

const AES_KEY_B64 = "1uNgm/8Z8BcSxdMRi29VwjVExZMPQfp4HwRbfsqjYXY=";
const IV_SIZE = 12;
const TAG_SIZE = 16;

export default function App() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [copied, setCopied] = useState(false);

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

  const decryptData = async () => {
    if (!input.trim()) {
      setError('Please enter encrypted data.');
      return;
    }

    setIsDecrypting(true);
    setError('');
    setOutput('');

    try {
      // 1. Prepare Key
      const rawKeyU8 = base64ToBytes(AES_KEY_B64);
      const key = await window.crypto.subtle.importKey(
        "raw",
        toArrayBuffer(rawKeyU8),
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      // 2. Prepare Data (Matching .NET layout: IV + Tag + Ciphertext)
      const full = base64ToBytes(input.trim());
      
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

      // 3. Decrypt
      const plainBuf = await window.crypto.subtle.decrypt(
        { 
          name: "AES-GCM", 
          iv: iv, 
          tagLength: TAG_SIZE * 8 
        },
        key,
        toArrayBuffer(ctWithTag) 
      );

      const decodedText = new TextDecoder().decode(new Uint8Array(plainBuf));
      
      // Attempt to format as JSON
      try {
        const json = JSON.parse(decodedText);
        setOutput(JSON.stringify(json, null, 2));
      } catch (e) {
        // Not JSON, use raw text
        setOutput(decodedText);
      }
    } catch (err) {
      console.error(err);
      setError('Decryption failed. Ensure the input follows the .NET layout (IV + Tag + Ciphertext) and uses the correct key.');
    } finally {
      setIsDecrypting(false);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(output);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[#f5f5f5] flex items-center justify-center p-4 font-sans">
      <div className="w-full max-w-2xl bg-white rounded-3xl shadow-sm border border-black/5 overflow-hidden">
        {/* Header */}
        <div className="p-8 border-bottom border-black/5">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-black rounded-lg">
              <Lock className="w-5 h-5 text-white" />
            </div>
            <h1 className="text-2xl font-semibold tracking-tight text-gray-900">AES Decryptor</h1>
          </div>
          <p className="text-sm text-gray-500">
            Optimized for .NET layout: <code className="bg-gray-100 px-1 rounded text-xs font-mono">IV(12) + Tag(16) + Ciphertext</code>
          </p>
        </div>

        {/* Content */}
        <div className="p-8 space-y-6">
          {/* Input Area */}
          <div className="space-y-2">
            <label className="text-xs font-medium uppercase tracking-wider text-gray-400">
              Encrypted Data (Base64)
            </label>
            <textarea
              id="encrypted-input"
              className="w-full h-32 p-4 bg-gray-50 border border-gray-200 rounded-2xl focus:ring-2 focus:ring-black/5 focus:border-black outline-none transition-all resize-none font-mono text-sm"
              placeholder="Paste your base64 encrypted string here..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
            />
          </div>

          {/* Action Button */}
          <button
            id="decrypt-button"
            onClick={decryptData}
            disabled={isDecrypting}
            className={`w-full py-4 rounded-2xl font-medium flex items-center justify-center gap-2 transition-all ${
              isDecrypting 
                ? 'bg-gray-100 text-gray-400 cursor-not-allowed' 
                : 'bg-black text-white hover:bg-gray-800 active:scale-[0.98]'
            }`}
          >
            {isDecrypting ? (
              <div className="w-5 h-5 border-2 border-gray-400 border-t-transparent rounded-full animate-spin" />
            ) : (
              <>
                <Unlock className="w-5 h-5" />
                Decrypt Data
              </>
            )}
          </button>

          {/* Error Message */}
          {error && (
            <div className="flex items-center gap-2 p-4 bg-red-50 text-red-600 rounded-2xl text-sm border border-red-100 animate-in fade-in slide-in-from-top-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}

          {/* Output Area */}
          {output && (
            <div className="space-y-2 animate-in fade-in slide-in-from-bottom-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium uppercase tracking-wider text-gray-400">
                  Decrypted Result
                </label>
                <button
                  onClick={copyToClipboard}
                  className="flex items-center gap-1.5 text-xs font-medium text-gray-500 hover:text-black transition-colors"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-500" />
                      Copied!
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      Copy Result
                    </>
                  )}
                </button>
              </div>
              <div className="w-full p-4 bg-emerald-50/50 border border-emerald-100 rounded-2xl font-mono text-sm text-gray-800 whitespace-pre-wrap break-all max-h-[400px] overflow-y-auto">
                {output}
              </div>
            </div>
          )}
        </div>

        {/* Footer Info */}
        <div className="p-6 bg-gray-50 border-t border-gray-100 flex justify-between items-center">
          <div className="flex gap-4">
            <div className="flex flex-col">
              <span className="text-[10px] uppercase tracking-widest text-gray-400 font-bold">Algorithm</span>
              <span className="text-xs font-medium text-gray-600">AES-GCM</span>
            </div>
            <div className="flex flex-col">
              <span className="text-[10px] uppercase tracking-widest text-gray-400 font-bold">IV Size</span>
              <span className="text-xs font-medium text-gray-600">12 Bytes</span>
            </div>
            <div className="flex flex-col">
              <span className="text-[10px] uppercase tracking-widest text-gray-400 font-bold">Tag Size</span>
              <span className="text-xs font-medium text-gray-600">16 Bytes</span>
            </div>
          </div>
          <div className="text-[10px] text-gray-400 italic">
            Client-side decryption only
          </div>
        </div>
      </div>
    </div>
  );
}
