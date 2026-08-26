-- Telegram-only accounts are temporary until a verified-email provider is linked.
DROP TRIGGER user_status_insert_guard;
DROP TRIGGER user_status_update_guard;

CREATE TRIGGER user_status_insert_guard
BEFORE INSERT ON user
WHEN NEW.status IS NOT NULL
 AND NEW.status NOT IN ('active', 'suspended', 'pending_telegram')
BEGIN
  SELECT RAISE(ABORT, 'invalid user status');
END;

CREATE TRIGGER user_status_update_guard
BEFORE UPDATE OF status ON user
WHEN NEW.status IS NOT NULL
 AND NEW.status NOT IN ('active', 'suspended', 'pending_telegram')
BEGIN
  SELECT RAISE(ABORT, 'invalid user status');
END;

CREATE INDEX user_pending_telegram_idx
  ON user(status, createdAt);
