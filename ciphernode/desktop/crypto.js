// AES-256-GCM with per-file IVs ensures confidentiality and integrity.
const AES_ALGORITHM = 'AES-GCM';
const IV_LENGTH = 12;

// Normalizes Blob/ArrayBuffer inputs for decryption.
const toArrayBuffer = async (blob) => {
  if (blob instanceof ArrayBuffer) {
    return blob;
  }
  return blob.arrayBuffer();
};

// Re-encodes images to PNG to remove EXIF/GPS metadata.
const stripImageMetadata = async (file) => {
  const bitmap = await createImageBitmap(file);
  const canvas = typeof OffscreenCanvas !== 'undefined'
    ? new OffscreenCanvas(bitmap.width, bitmap.height)
    : Object.assign(document.createElement('canvas'), {
        width: bitmap.width,
        height: bitmap.height,
      });
  const ctx = canvas.getContext('2d', { alpha: true });
  ctx.drawImage(bitmap, 0, 0);
  const blob = await canvas.convertToBlob
    ? canvas.convertToBlob({ type: 'image/png' })
    : new Promise((resolve) => canvas.toBlob(resolve, 'image/png'));
  return blob.arrayBuffer();
};

// Only allow document types with explicit metadata stripping.
const stripMetadata = async (file) => {
  if (file.type.startsWith('image/')) {
    return stripImageMetadata(file);
  }
  if (file.type === 'text/plain' || file.type === 'application/json') {
    return file.arrayBuffer();
  }
  throw new Error('Unsupported document type. Add a sanitizer before encryption.');
};

// Encrypts sanitized bytes locally before upload; key must be shared via E2EE.
export const encryptFileForUpload = async (file) => {
  const sanitized = await stripMetadata(file);
  const key = await crypto.subtle.generateKey({ name: AES_ALGORITHM, length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertext = await crypto.subtle.encrypt({ name: AES_ALGORITHM, iv }, key, sanitized);
  const rawKey = await crypto.subtle.exportKey('raw', key);

  return {
    encryptedBlob: new Blob([ciphertext]),
    keyBytes: new Uint8Array(rawKey),
    iv,
  };
};

// Decrypts in memory without writing to disk or public storage.
export const decryptFileInMemory = async ({ encryptedBlob, keyBytes, iv }) => {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: AES_ALGORITHM }, false, [
    'decrypt',
  ]);
  const ciphertext = await toArrayBuffer(encryptedBlob);
  const plaintext = await crypto.subtle.decrypt({ name: AES_ALGORITHM, iv }, key, ciphertext);
  return new Uint8Array(plaintext);
};
