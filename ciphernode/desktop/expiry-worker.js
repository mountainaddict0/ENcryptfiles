// Periodically purges expired, read messages and updates the UI via callback.
export const startExpiryWorker = ({ dbPool, onExpired, intervalMs = 1000 }) => {
  const tick = async () => {
    const now = Date.now();
    const expiredIds = await dbPool.withConnection(async (conn) => {
      const rows = await conn.all(
        'SELECT id FROM messages WHERE read_status = 1 AND expiry_timestamp IS NOT NULL AND expiry_timestamp <= ?',
        [now],
      );
      if (!rows.length) {
        return [];
      }
      const ids = rows.map((row) => row.id);
      // Placeholder list is derived from ids length; values remain parameterized.
      const placeholders = ids.map(() => '?').join(',');
      await conn.run(`DELETE FROM messages WHERE id IN (${placeholders})`, ids);
      return ids;
    });

    if (expiredIds.length && typeof onExpired === 'function') {
      onExpired(expiredIds);
    }
  };

  const timer = setInterval(() => {
    tick().catch((error) => {
      console.error('Expiry worker failed', error);
    });
  }, intervalMs);

  return () => clearInterval(timer);
};
