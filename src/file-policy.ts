import { constants } from "node:fs";
import { type FileHandle, mkdir, open, realpath, stat } from "node:fs/promises";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";
import { isSafeAbsolutePath } from "./tools/shared.js";

const MIB = 1048576;
/** Telegram's own limit for one file; downloads stream to disk, so nothing smaller is needed. */
export const TELEGRAM_FILE_LIMIT_BYTES = 2000 * MIB;

/** MCP_TELEGRAM_MAX_DOWNLOAD_BYTES, or Telegram's own 2000 MiB. Set 20971520 for the old 20 MiB cap. */
export function maxDownloadBytes(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.MCP_TELEGRAM_MAX_DOWNLOAD_BYTES;
  const value = raw ? Number(raw) : TELEGRAM_FILE_LIMIT_BYTES;
  if (!Number.isSafeInteger(value) || value < 1 || value > TELEGRAM_FILE_LIMIT_BYTES * 2)
    throw new Error("Invalid MCP_TELEGRAM_MAX_DOWNLOAD_BYTES");
  return value;
}

/** Name of the worker tool that fetches a message's file to disk. */
export const DOWNLOAD_MEDIA_TOOL = "telegram-download-media";

/**
 * How long one media download may run (MCP_TELEGRAM_DOWNLOAD_TIMEOUT_MS, default 15 min,
 * 30 s – 2 h). Only the download tool gets this; every other tool keeps its short deadline.
 */
export function downloadTimeoutMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.MCP_TELEGRAM_DOWNLOAD_TIMEOUT_MS;
  const value = raw ? Number(raw) : 15 * 60000;
  if (!Number.isSafeInteger(value) || value < 30000 || value > 2 * 3600000)
    throw new Error("Invalid MCP_TELEGRAM_DOWNLOAD_TIMEOUT_MS");
  return value;
}

export class FilePolicy {
  private readonly root?: string;
  private readonly maxBytes: number;
  private readonly maxDownloadBytes: number;
  constructor(options: { root?: string; maxBytes?: number; maxDownloadBytes?: number } = {}) {
    this.root = options.root ? resolve(options.root) : undefined;
    this.maxBytes = options.maxBytes ?? 20 * MIB;
    this.maxDownloadBytes = options.maxDownloadBytes ?? TELEGRAM_FILE_LIMIT_BYTES;
    if (!Number.isSafeInteger(this.maxBytes) || this.maxBytes < 1) throw new Error("Invalid media size limit");
    if (!Number.isSafeInteger(this.maxDownloadBytes) || this.maxDownloadBytes < 1)
      throw new Error("Invalid media download limit");
  }
  private async confined(path: string, output = false): Promise<string> {
    if (!isSafeAbsolutePath(path)) throw new Error("Unsafe media path: use an absolute local path without traversal");
    if (!this.root) return path;
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const root = await realpath(this.root);
    const target = output ? resolve(await realpath(dirname(path)), basename(path)) : await realpath(path);
    const rel = relative(root, target);
    if (!rel || rel.startsWith("..") || isAbsolute(rel))
      throw new Error("Media path must stay inside the configured file root");
    return target;
  }
  async upload(path: string): Promise<string> {
    const target = await this.confined(path);
    if (this.root) {
      const info = await stat(target);
      if (!info.isFile()) throw new Error("Media upload must be a regular file");
      this.checkSize(info.size);
    }
    return target;
  }
  checkSize(bytes: number): void {
    if (this.root && bytes > this.maxBytes) throw new Error("Media size exceeds configured limit");
  }
  /** Downloads from Telegram have their own (larger) limit: they stream to disk, never into memory. */
  checkDownloadSize(bytes: number): void {
    if (this.root && bytes > this.maxDownloadBytes) throw new Error("Media size exceeds configured download limit");
  }
  /** Create a new confined output file (never an existing one, never through a symlink). */
  async openOutput(path: string): Promise<{ handle: FileHandle; path: string }> {
    const target = await this.confined(path, true);
    const handle = await open(
      target,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    return { handle, path: target };
  }
  async save(path: string, data: Buffer): Promise<void> {
    this.checkSize(data.length);
    const { handle } = await this.openOutput(path);
    try {
      await handle.writeFile(data);
    } finally {
      await handle.close();
    }
  }
}

export function mediaPolicy(): FilePolicy {
  return new FilePolicy({
    root: process.env.MCP_TELEGRAM_FILE_ROOT,
    maxBytes: process.env.MCP_TELEGRAM_MAX_MEDIA_BYTES ? Number(process.env.MCP_TELEGRAM_MAX_MEDIA_BYTES) : undefined,
    maxDownloadBytes: maxDownloadBytes(),
  });
}
