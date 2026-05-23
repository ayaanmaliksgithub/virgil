/**
 * Resolve a runnable `virgil` binary for the current OS/arch.
 *
 * Three sources, in order:
 *   1. The `virgil.cliPath` setting — full path to a binary the user
 *      built themselves. Honored verbatim; useful while developing the
 *      CLI alongside the extension (`apps/cli/dist/virgil`).
 *   2. A previously-downloaded binary cached under the extension's
 *      `globalStorageUri/bin/` directory, keyed by version.
 *   3. A fresh download from the matching GitHub Release. Files are
 *      attached by `.github/workflows/cli-binaries.yml`; the asset
 *      naming convention is shared between the two.
 *
 * The extension never assumes Python or pipx is present — the bundled
 * binary is fully self-contained (built with PyInstaller).
 */
import * as fs from "node:fs/promises";
import * as fsSync from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";

/**
 * Pinned CLI version the extension expects. Bump this in lockstep with the
 * release tag that publishes binaries — the extension's download URL is
 * `…/releases/download/v${CLI_VERSION}/virgil-<os>-<arch>`.
 */
export const CLI_VERSION = "0.3.1";

const RELEASE_BASE =
  "https://github.com/ayaanmaliksgithub/virgil/releases/download";

export type BinaryErrorKind = "missing" | "download" | "unsupported";

export class BinaryError extends Error {
  constructor(public kind: BinaryErrorKind, message: string) {
    super(message);
    this.name = "BinaryError";
  }
}

interface PlatformAsset {
  name: string;
  isWindows: boolean;
}

function platformAsset(): PlatformAsset | null {
  const p = process.platform;
  const a = process.arch;
  if (p === "darwin" && a === "arm64") return { name: "virgil-macos-arm64", isWindows: false };
  if (p === "darwin" && a === "x64") return { name: "virgil-macos-x86_64", isWindows: false };
  if (p === "linux" && a === "x64") return { name: "virgil-linux-x86_64", isWindows: false };
  if (p === "win32" && a === "x64") return { name: "virgil-windows-x86_64.exe", isWindows: true };
  return null;
}

export async function resolveBinary(
  context: vscode.ExtensionContext,
): Promise<string> {
  const override = vscode.workspace
    .getConfiguration("virgil")
    .get<string>("cliPath", "")
    .trim();
  if (override) {
    try {
      await fs.access(override, fsSync.constants.X_OK);
      return override;
    } catch {
      throw new BinaryError(
        "missing",
        `virgil.cliPath is set to "${override}" but the file isn't executable (or doesn't exist)`,
      );
    }
  }

  const asset = platformAsset();
  if (!asset) {
    throw new BinaryError(
      "unsupported",
      `Virgil doesn't ship a CLI binary for ${process.platform}/${process.arch} yet. ` +
        `Set "virgil.cliPath" to a locally-built binary, or install via \`pipx install virgilhq\`.`,
    );
  }

  const cacheDir = vscode.Uri.joinPath(context.globalStorageUri, "bin").fsPath;
  await fs.mkdir(cacheDir, { recursive: true });
  const cached = path.join(
    cacheDir,
    `virgil-${CLI_VERSION}${asset.isWindows ? ".exe" : ""}`,
  );
  try {
    await fs.access(cached);
    return cached;
  } catch {
    // fall through to download
  }

  const url = `${RELEASE_BASE}/v${CLI_VERSION}/${asset.name}`;
  await downloadWithProgress(url, cached);
  if (!asset.isWindows) {
    await fs.chmod(cached, 0o755);
  }
  return cached;
}

async function downloadWithProgress(url: string, dest: string): Promise<void> {
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Virgil: downloading CLI ${CLI_VERSION}`,
      cancellable: false,
    },
    async (progress) => {
      const res = await fetch(url);
      if (!res.ok || !res.body) {
        throw new BinaryError(
          "download",
          `failed to download ${url} (HTTP ${res.status} ${res.statusText})`,
        );
      }
      const total = Number(res.headers.get("content-length") ?? 0);
      let received = 0;

      // Write to a `.part` file and rename on completion so a partial
      // download never gets mistaken for a finished cache entry.
      const tmp = dest + ".part";
      const out = fsSync.createWriteStream(tmp);
      const reader = res.body.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          out.write(Buffer.from(value));
          received += value.length;
          if (total) {
            progress.report({
              message: `${Math.round((received / total) * 100)}%`,
              increment: (value.length / total) * 100,
            });
          }
        }
      } catch (e) {
        out.destroy();
        await fs.unlink(tmp).catch(() => undefined);
        throw new BinaryError("download", `stream interrupted: ${(e as Error).message}`);
      }
      await new Promise<void>((resolve, reject) =>
        out.end((err: NodeJS.ErrnoException | null | undefined) =>
          err ? reject(err) : resolve(),
        ),
      );
      await fs.rename(tmp, dest);
    },
  );
}
