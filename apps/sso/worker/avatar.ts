/**
 * Avatar upload validation.
 *
 * Everything here is pure and side-effect free so it can be unit tested in the
 * workerd pool without a request. The content type is always derived from the
 * file's magic bytes, never from a client-supplied header or data-URL MIME, and
 * both byte size and (best-effort) pixel dimensions are bounded before the
 * image is stored. No image-processing library is used: the bytes are kept as
 * uploaded, so the guardrails are the size and dimension ceilings below.
 */

export const AVATAR_CONTENT_TYPES = [
  "image/png",
  "image/jpeg",
  "image/webp",
] as const;

export type AvatarContentType = (typeof AVATAR_CONTENT_TYPES)[number];

/** Decoded-byte ceiling. JSON data URLs inflate ~33%, still under the route body limit. */
export const MAX_AVATAR_BYTES = 256 * 1024;
/** Sanity ceiling on decoded dimensions to reject decompression-bomb shaped inputs. */
export const MAX_AVATAR_DIMENSION = 2048;

export interface AvatarDimensions {
  width: number;
  height: number;
}

/**
 * Identifies a supported image strictly from its signature bytes. Returns null
 * for anything that is not a PNG, JPEG, or WebP (RIFF/WEBP) container.
 */
export function detectImageType(bytes: Uint8Array): AvatarContentType | null {
  if (
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a
  ) {
    return "image/png";
  }
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return "image/jpeg";
  }
  if (
    bytes.length >= 12 &&
    bytes[0] === 0x52 && // R
    bytes[1] === 0x49 && // I
    bytes[2] === 0x46 && // F
    bytes[3] === 0x46 && // F
    bytes[8] === 0x57 && // W
    bytes[9] === 0x45 && // E
    bytes[10] === 0x42 && // B
    bytes[11] === 0x50 // P
  ) {
    return "image/webp";
  }
  return null;
}

function readPngDimensions(bytes: Uint8Array): AvatarDimensions | null {
  // IHDR is the first chunk: width at byte 16, height at byte 20 (big-endian).
  if (bytes.length < 24) return null;
  const width =
    ((bytes[16]! << 24) | (bytes[17]! << 16) | (bytes[18]! << 8) | bytes[19]!) >>> 0;
  const height =
    ((bytes[20]! << 24) | (bytes[21]! << 16) | (bytes[22]! << 8) | bytes[23]!) >>> 0;
  return { width, height };
}

function readJpegDimensions(bytes: Uint8Array): AvatarDimensions | null {
  let offset = 2;
  while (offset + 9 <= bytes.length) {
    if (bytes[offset] !== 0xff) {
      offset += 1;
      continue;
    }
    const marker = bytes[offset + 1]!;
    // Start-of-frame markers (SOF0..SOF15) carry the dimensions; DHT (0xc4),
    // JPG (0xc8), and DAC (0xcc) share the range but are not frame headers.
    if (
      marker >= 0xc0 &&
      marker <= 0xcf &&
      marker !== 0xc4 &&
      marker !== 0xc8 &&
      marker !== 0xcc
    ) {
      const height = (bytes[offset + 5]! << 8) | bytes[offset + 6]!;
      const width = (bytes[offset + 7]! << 8) | bytes[offset + 8]!;
      return { width, height };
    }
    const segmentLength = (bytes[offset + 2]! << 8) | bytes[offset + 3]!;
    if (segmentLength < 2) return null;
    offset += 2 + segmentLength;
  }
  return null;
}

function readWebpDimensions(bytes: Uint8Array): AvatarDimensions | null {
  const format = String.fromCharCode(
    bytes[12] ?? 0,
    bytes[13] ?? 0,
    bytes[14] ?? 0,
    bytes[15] ?? 0,
  );
  if (format === "VP8 ") {
    // Lossy: the key frame's 14-bit width/height start at byte 26.
    if (bytes.length < 30) return null;
    const width = ((bytes[26]! | (bytes[27]! << 8)) & 0x3fff);
    const height = ((bytes[28]! | (bytes[29]! << 8)) & 0x3fff);
    return { width, height };
  }
  if (format === "VP8L") {
    // Lossless: 14-bit width/height packed after the 0x2f signature at byte 20.
    if (bytes.length < 25) return null;
    const b0 = bytes[21]!;
    const b1 = bytes[22]!;
    const b2 = bytes[23]!;
    const b3 = bytes[24]!;
    const width = 1 + (((b1 & 0x3f) << 8) | b0);
    const height = 1 + (((b3 & 0x0f) << 10) | (b2 << 2) | ((b1 & 0xc0) >> 6));
    return { width, height };
  }
  if (format === "VP8X") {
    // Extended: 24-bit canvas width/height (minus one) at byte 24.
    if (bytes.length < 30) return null;
    const width = 1 + (bytes[24]! | (bytes[25]! << 8) | (bytes[26]! << 16));
    const height = 1 + (bytes[27]! | (bytes[28]! << 8) | (bytes[29]! << 16));
    return { width, height };
  }
  return null;
}

/**
 * Best-effort pixel dimensions from the container header. Returns null when the
 * header cannot be parsed; callers treat null as "unknown", not "invalid".
 */
export function readImageDimensions(
  contentType: AvatarContentType,
  bytes: Uint8Array,
): AvatarDimensions | null {
  switch (contentType) {
    case "image/png":
      return readPngDimensions(bytes);
    case "image/jpeg":
      return readJpegDimensions(bytes);
    case "image/webp":
      return readWebpDimensions(bytes);
  }
}

export type AvatarValidation =
  | {
      ok: true;
      contentType: AvatarContentType;
      width: number | null;
      height: number | null;
    }
  | { ok: false; error: string };

/**
 * Validates decoded image bytes: non-empty, within the size ceiling, a
 * recognised PNG/JPEG/WebP signature, and — when the dimensions can be read —
 * within the pixel ceiling. Unparseable dimensions do not fail validation; the
 * byte-size ceiling still bounds the payload.
 */
export function validateAvatarBytes(bytes: Uint8Array): AvatarValidation {
  if (bytes.length === 0) {
    return { ok: false, error: "empty_avatar" };
  }
  if (bytes.length > MAX_AVATAR_BYTES) {
    return { ok: false, error: "avatar_too_large" };
  }
  const contentType = detectImageType(bytes);
  if (!contentType) {
    return { ok: false, error: "unsupported_avatar_type" };
  }
  const dimensions = readImageDimensions(contentType, bytes);
  if (
    dimensions &&
    (dimensions.width < 1 ||
      dimensions.height < 1 ||
      dimensions.width > MAX_AVATAR_DIMENSION ||
      dimensions.height > MAX_AVATAR_DIMENSION)
  ) {
    return { ok: false, error: "avatar_dimensions_too_large" };
  }
  return {
    ok: true,
    contentType,
    width: dimensions?.width ?? null,
    height: dimensions?.height ?? null,
  };
}

/**
 * Decodes a `data:<mime>;base64,<data>` URL into raw bytes. The MIME is
 * returned only for completeness; the caller re-derives the content type from
 * the decoded signature bytes and never trusts this value.
 */
export function decodeDataUrl(
  dataUrl: unknown,
): { mime: string; bytes: Uint8Array } | null {
  if (typeof dataUrl !== "string" || dataUrl.length > 2 * 1024 * 1024) {
    return null;
  }
  const match = /^data:([\w.+-]+\/[\w.+-]+);base64,([A-Za-z0-9+/]+={0,2})$/.exec(
    dataUrl,
  );
  if (!match) return null;
  try {
    const binary = atob(match[2]!);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return { mime: match[1]!, bytes };
  } catch {
    return null;
  }
}

/** Encodes raw bytes to a base64 string for TEXT storage. */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Decodes a stored base64 avatar back to raw bytes for serving. */
export function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
