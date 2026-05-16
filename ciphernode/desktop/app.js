import { CipherNodeDatabasePool } from './db.js';
import { encryptFileForUpload } from './crypto.js';
import { startExpiryWorker } from './expiry-worker.js';

// WebSocket retry policy for resilient connectivity.
const WS_RETRY_BASE_MS = 1000;
const WS_RETRY_MAX_MS = 15000;
const UID_STORAGE_KEY = 'ciphernode_uid';

// UI element references for fast, safe DOM updates.
const elements = {
  status: document.querySelector('[data-status]'),
  conversationList: document.querySelector('[data-conversation-list]'),
  messageList: document.querySelector('[data-message-list]'),
  messageForm: document.querySelector('[data-message-form]'),
  messageInput: document.querySelector('[data-message-input]'),
  fileInput: document.querySelector('[data-file-input]'),
  ephemeralToggle: document.querySelector('[data-ephemeral-toggle]'),
  ttlSelect: document.querySelector('[data-ttl-select]'),
};

// Generates a random numeric UID instead of email/phone identifiers.
const generateUid = () => {
  const digits = crypto.getRandomValues(new Uint8Array(12)).map((value) => value % 10);
  return `${digits.slice(0, 4).join('')}-${digits.slice(4, 8).join('')}-${digits
    .slice(8, 12)
    .join('')}`;
};

// Stores the UID locally so pairing never uses passwords or emails.
const getLocalUid = () => {
  const existing = localStorage.getItem(UID_STORAGE_KEY);
  if (existing) {
    return existing;
  }
  const uid = generateUid();
  localStorage.setItem(UID_STORAGE_KEY, uid);
  return uid;
};

// Node/Electron Buffer is used for base64 encoding before storage or transport.
const toBase64 = (bytes) => Buffer.from(bytes).toString('base64');

// Renders a message bubble with attachment and expiry states.
const renderMessage = ({ id, senderId, body, isOutgoing, fileName, expired }) => {
  const item = document.createElement('div');
  item.className = `message ${isOutgoing ? 'message--outgoing' : 'message--incoming'}${
    expired ? ' message--expired' : ''
  }`;
  item.dataset.messageId = id;
  const meta = document.createElement('div');
  meta.className = 'message__meta';
  const sender = document.createElement('span');
  sender.textContent = senderId;
  meta.appendChild(sender);
  if (fileName) {
    const attachment = document.createElement('span');
    attachment.className = 'message__attachment';
    attachment.textContent = `📎 ${fileName}`;
    meta.appendChild(attachment);
  }
  const messageBody = document.createElement('div');
  messageBody.className = 'message__body';
  messageBody.textContent = body;
  item.appendChild(meta);
  item.appendChild(messageBody);
  elements.messageList.appendChild(item);
  elements.messageList.scrollTop = elements.messageList.scrollHeight;
};

// Updates UI connection state for user awareness.
const updateStatus = (text, state = 'offline') => {
  elements.status.textContent = text;
  elements.status.dataset.state = state;
};

// Creates a reconnecting WebSocket with defensive parsing.
const createWebSocketManager = ({ uid, onMessage }) => {
  let socket;
  let retryDelay = WS_RETRY_BASE_MS;

  const connect = () => {
    socket = new WebSocket('wss://ciphernode.local/ws');

    socket.onopen = () => {
      retryDelay = WS_RETRY_BASE_MS;
      updateStatus('Connected', 'online');
      socket.send(JSON.stringify({ type: 'handshake', uid }));
    };

    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        onMessage(payload);
      } catch (error) {
        console.error('Invalid message payload', error);
      }
    };

    socket.onclose = () => {
      updateStatus('Disconnected. Reconnecting...', 'offline');
      const nextDelay = Math.min(retryDelay, WS_RETRY_MAX_MS);
      retryDelay *= 2;
      setTimeout(connect, nextDelay);
    };

    socket.onerror = () => {
      socket.close();
    };
  };

  connect();

  return {
    send: (payload) => {
      if (socket?.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify(payload));
      }
    },
  };
};

// Bootstraps database, WebSocket, and expiry worker.
const initialize = async () => {
  const uid = getLocalUid();
  updateStatus('Connecting...', 'offline');

  // Session key should be derived from a paired E2EE handshake.
  const sessionKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const dbPool = await new CipherNodeDatabasePool({ filename: 'ciphernode.db', poolSize: 4 }).initialize();

  startExpiryWorker({
    dbPool,
    onExpired: (ids) => {
      ids.forEach((id) => {
        const element = elements.messageList.querySelector(`[data-message-id="${id}"]`);
        if (element) {
          element.classList.add('message--expired');
          setTimeout(() => element.remove(), 600);
        }
      });
    },
  });

  const ws = createWebSocketManager({
    uid,
    onMessage: async (payload) => {
      if (payload.type === 'message') {
        renderMessage({
          id: payload.id,
          senderId: payload.senderId,
          body: payload.body ?? '[Encrypted] ',
          isOutgoing: payload.senderId === uid,
          fileName: payload.fileName,
        });
        const encryptedBytes = payload.payloadEncrypted
          ? Buffer.from(payload.payloadEncrypted, 'base64')
          : Buffer.from('');
        await dbPool.withConnection((conn) =>
          conn.run(
            'INSERT INTO messages (id, conversation_id, sender_id, payload_encrypted, file_blob_pointer, timestamp, read_status, expiry_timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [
              payload.id,
              payload.conversationId,
              payload.senderId,
              encryptedBytes,
              payload.filePointer ?? null,
              payload.timestamp,
              1,
              payload.expiryTimestamp ?? null,
            ],
          ),
        );
      }
    },
  });

  elements.messageForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const text = elements.messageInput.value.trim();
    const file = elements.fileInput.files[0];
    if (!text && !file) {
      return;
    }

    let filePointer;
    let fileKey;
    if (file) {
      const { encryptedBlob, keyBytes, iv } = await encryptFileForUpload(file);
      filePointer = await uploadEncryptedFile(encryptedBlob);
      fileKey = { keyBytes: Array.from(keyBytes), iv: Array.from(iv) };
    }

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedPayload = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      sessionKey,
      new TextEncoder().encode(text || ''),
    );
    const encryptedBytes = new Uint8Array(encryptedPayload);
    const combined = new Uint8Array(iv.length + encryptedBytes.length);
    combined.set(iv, 0);
    combined.set(encryptedBytes, iv.length);

    const ttl = Number(elements.ttlSelect.value || 0);
    const expiryTimestamp = elements.ephemeralToggle.checked && ttl > 0 ? Date.now() + ttl : null;

    const payload = {
      type: 'message',
      body: text,
      payloadEncrypted: toBase64(combined),
      fileName: file?.name ?? null,
      filePointer,
      fileKey,
      ephemeral: elements.ephemeralToggle.checked,
      ttl,
      expiryTimestamp,
      timestamp: Date.now(),
    };

    ws.send(payload);
    renderMessage({
      id: crypto.randomUUID(),
      senderId: uid,
      body: text || '[Encrypted attachment]',
      isOutgoing: true,
      fileName: file?.name,
    });

    elements.messageInput.value = '';
    elements.fileInput.value = '';
  });
};

// Uploads encrypted binary; plaintext never leaves the device.
const uploadEncryptedFile = async (encryptedBlob) => {
  const response = await fetch('/upload', {
    method: 'POST',
    body: encryptedBlob,
  });
  if (!response.ok) {
    throw new Error('Encrypted upload failed');
  }
  const { pointer } = await response.json();
  return pointer;
};

initialize().catch((error) => {
  console.error('CipherNode failed to initialize', error);
  updateStatus('Offline', 'offline');
});
